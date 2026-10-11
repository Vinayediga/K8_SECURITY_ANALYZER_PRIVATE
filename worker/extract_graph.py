#!/usr/bin/env python3
"""
Kubernetes Attack Path Extractor
---------------------------------
Connects to a live cluster (via your current kubeconfig context) and builds
an attack-path graph: nodes = K8s entities, edges = capabilities/relationships
that an attacker could exploit (RBAC permissions, pod security misconfigs).

Output schema matches what graph_engine.py / main.py / report.py expect:
  - nodes carry: id, type, namespace, risk_score, is_source, is_sink, cves
  - edges carry: source, target, relationship, weight, risk, cve, cvss

Usage:
    pip install kubernetes
    python extract_graph.py [--out cluster-graph.json] [--context CONTEXT_NAME]

Requires: `kubectl` already configured to point at your target cluster
(kind/minikube/real cluster) — this script just uses the same kubeconfig.
"""

import json
import argparse
from pathlib import Path
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# Dangerous verb/resource combinations from Chapter 7.2 of the study guide
DANGEROUS_RULES = {
    "pods": {
        "create": "CAN_CREATE_POD",
    },
    "secrets": {
        "get": "CAN_READ_SECRET",
        "list": "CAN_READ_SECRET",
    },
    "rolebindings": {
        "create": "CAN_ESCALATE_VIA_BINDING",
        "patch": "CAN_ESCALATE_VIA_BINDING",
    },
    "clusterrolebindings": {
        "create": "CAN_ESCALATE_VIA_CLUSTERBINDING",
        "patch": "CAN_ESCALATE_VIA_CLUSTERBINDING",
    },
    "pods/exec": {
        "create": "CAN_EXEC_INTO_POD",
        "get": "CAN_EXEC_INTO_POD",
    },
    "serviceaccounts": {
        "create": "CAN_CREATE_SERVICEACCOUNT",
        "impersonate": "CAN_IMPERSONATE",
    },
}
ESCALATION_VERBS = {"bind", "escalate", "impersonate", "*"}

# risk severity -> (weight for Dijkstra, numeric risk_score for the node/edge)
# Lower weight = easier/cheaper hop for an attacker, so Dijkstra's "shortest
# path" surfaces the lowest-effort route to a target, not just any route.
RISK_WEIGHT = {"critical": 1.0, "high": 3.0, "medium": 5.0, "info": 9.0}
RISK_SCORE = {"critical": 9.0, "high": 7.0, "medium": 4.0, "info": 1.0}

VULNERABILITY_SEVERITY = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
}

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "data" / "cluster-graph.json")


def add_finding(node, finding_id, title, severity, description, recommendation):
    """Attach a structured security finding to a graph node."""
    if "findings" not in node:
        node["findings"] = []

    node["findings"].append({
        "id": finding_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    })

    # Keep the node risk at least as high as its most severe finding.
    node["risk_score"] = max(
        node.get("risk_score", 1.0),
        VULNERABILITY_SEVERITY.get(severity, 1.0)
    )


class GraphBuilder:
    def __init__(self):
        self.nodes = {}   # id -> node dict (dedup)
        self.edges = []   # list of edge dicts

    def add_node(self, node_id, ntype, label, risk="info", is_source=False, is_sink=False, **extra):
        if node_id not in self.nodes:
            node = {
                "id": node_id, "type": ntype, "label": label,
                "risk_score": RISK_SCORE.get(risk, 1.0),
                "is_source": is_source, "is_sink": is_sink,
                "cves": [],
            }
            node.update(extra)
            self.nodes[node_id] = node
        else:
            # a node can be touched more than once (e.g. flagged high-risk later);
            # only ever raise is_source/is_sink/risk, never silently downgrade them
            existing = self.nodes[node_id]
            existing["is_source"] = existing["is_source"] or is_source
            existing["is_sink"] = existing["is_sink"] or is_sink
            existing["risk_score"] = max(existing["risk_score"], RISK_SCORE.get(risk, 1.0))
        return node_id

    def add_edge(self, source, target, relation, risk="info"):
        # avoid duplicate edges
        key = (source, target, relation)
        if not any((e["source"], e["target"], e["relationship"]) == key for e in self.edges):
            self.edges.append({
                "source": source, "target": target,
                "relation": relation,        # kept for the visualizer (visualize.html)
                "relationship": relation,     # kept for graph_engine.py
                "weight": RISK_WEIGHT.get(risk, 9.0),
                "risk": risk,
            })

    def to_json(self):
        return {"nodes": list(self.nodes.values()), "edges": self.edges}


def sa_id(namespace, name):
    return f"sa:{namespace}:{name}"


def pod_id(namespace, name):
    return f"pod:{namespace}:{name}"


def node_id_(name):
    return f"node:{name}"


def secret_id(namespace, name):
    return f"secret:{namespace}:{name}"


def ns_id(namespace):
    return f"ns:{namespace}"


def role_id(namespace, name):
    return f"role:{namespace or 'cluster'}:{name}"


def build_graph(v1, rbac,networking):
    g = GraphBuilder()

    # ---- Nodes (physical/VM machines) ----
    for n in v1.list_node().items:
        labels = n.metadata.labels or {}
        is_control_plane = "node-role.kubernetes.io/control-plane" in labels
        g.add_node(node_id_(n.metadata.name), "Node", n.metadata.name,
                   control_plane=is_control_plane,
                   is_sink=is_control_plane,  # compromising the control-plane node is a top-tier target
                   risk="critical" if is_control_plane else "info")
    # Synthetic placeholder for pods that exist but haven't been scheduled yet
    g.add_node(node_id_("unscheduled"), "Node", "unscheduled (synthetic)")

    # ---- Namespaces ----
    for ns in v1.list_namespace().items:
        g.add_node(ns_id(ns.metadata.name), "Namespace", ns.metadata.name)
    # Synthetic namespace used for ClusterRole-derived edges that aren't scoped
    # to one real namespace (cluster-wide permissions)
    g.add_node(ns_id("cluster-wide"), "Namespace", "cluster-wide (synthetic)")

        # ---- NetworkPolicy analysis ----
    #
    # Kubernetes namespaces without any NetworkPolicy are treated as
    # having unrestricted pod-to-pod ingress/egress by default.
    network_policies = (
        networking.list_network_policy_for_all_namespaces().items
    )

    policies_by_namespace = {}

    for policy in network_policies:
        namespace = policy.metadata.namespace
        policies_by_namespace.setdefault(namespace, []).append(policy)

    for namespace in v1.list_namespace().items:
        ns_name = namespace.metadata.name
        ns_node = ns_id(ns_name)

        policy_count = len(policies_by_namespace.get(ns_name, []))

        if ns_name in {"kube-system", "kube-public", "kube-node-lease"}:
            # Avoid automatically flagging Kubernetes system namespaces.
            continue

        if policy_count == 0:
            ns_node_data = g.nodes.get(ns_node)

            if ns_node_data is not None:
                add_finding(
                    ns_node_data,
                    "K8S-NO-NETWORK-POLICY",
                    "No NetworkPolicy Defined",
                    "medium",
                    "No NetworkPolicy is defined for this namespace. "
                    "Kubernetes therefore permits unrestricted pod "
                    "network communication by default.",
                    "Define appropriate ingress and egress NetworkPolicies "
                    "using least-privilege network access."
                )

                ns_node_data["network_policy_count"] = 0

    # ---- ServiceAccounts ----
    for sa in v1.list_service_account_for_all_namespaces().items:
        g.add_node(sa_id(sa.metadata.namespace, sa.metadata.name),
                   "ServiceAccount", sa.metadata.name, namespace=sa.metadata.namespace)

    # ---- Secrets ----
    for secret in v1.list_secret_for_all_namespaces().items:
        g.add_node(secret_id(secret.metadata.namespace, secret.metadata.name),
                   "Secret", secret.metadata.name, namespace=secret.metadata.namespace,
                   is_sink=True, risk="high")  # any Secret is a high-value target

    # ---- Pods (+ security posture) ----
    for pod in v1.list_pod_for_all_namespaces().items:
        spec = pod.spec
        pid = f"pod:{pod.metadata.namespace}:{pod.metadata.name}"
        host_pid = bool(spec.host_pid)
        host_network = bool(spec.host_network)

        privileged = any(
            bool(c.security_context and c.security_context.privileged)
            for c in (spec.containers or [])
        )

        allow_privilege_escalation = any(
            bool(
                c.security_context
                and c.security_context.allow_privilege_escalation
            )
            for c in (spec.containers or [])
        )

        run_as_non_root = all(
            bool(
                c.security_context
                and c.security_context.run_as_non_root
            )
            for c in (spec.containers or [])
        )

        read_only_root_filesystem = all(
            bool(
                c.security_context
                and c.security_context.read_only_root_filesystem
            )
            for c in (spec.containers or [])
        )

        token_automount = spec.automount_service_account_token

        findings = []

        if privileged:
            findings.append({
                "id": "K8S-PRIVILEGED-CONTAINER",
                "title": "Privileged Container",
                "severity": "critical",
                "description":
                    "Container runs with privileged mode enabled, "
                    "which can significantly increase access to the host.",
                "recommendation":
                    "Disable privileged mode unless explicitly required."
            })

        if host_pid:
            findings.append({
                "id": "K8S-HOSTPID",
                "title": "Host PID Namespace",
                "severity": "high",
                "description":
                    "Pod shares the host PID namespace and may observe "
                    "processes running on the Kubernetes node.",
                "recommendation":
                    "Disable hostPID unless there is a documented requirement."
            })

        if host_network:
            findings.append({
                "id": "K8S-HOSTNETWORK",
                "title": "Host Network Enabled",
                "severity": "high",
                "description":
                    "Pod uses the host network namespace, increasing "
                    "its access to node-level networking.",
                "recommendation":
                    "Disable hostNetwork unless it is explicitly required."
            })

        if allow_privilege_escalation:
            findings.append({
                "id": "K8S-PRIVILEGE-ESCALATION",
                "title": "Privilege Escalation Allowed",
                "severity": "high",
                "description":
                    "One or more containers allow privilege escalation.",
                "recommendation":
                    "Set allowPrivilegeEscalation to false."
            })

        if not run_as_non_root:
            findings.append({
                "id": "K8S-RUN-AS-ROOT",
                "title": "Container May Run as Root",
                "severity": "medium",
                "description":
                    "The container security context does not require "
                    "execution as a non-root user.",
                "recommendation":
                    "Configure runAsNonRoot=true and use a non-root user."
            })

        if not read_only_root_filesystem:
            findings.append({
                "id": "K8S-WRITABLE-ROOTFS",
                "title": "Writable Root Filesystem",
                "severity": "medium",
                "description":
                    "The container root filesystem is not configured as read-only.",
                "recommendation":
                    "Set readOnlyRootFilesystem=true where application compatibility allows."
            })

        if token_automount is not False:
            findings.append({
                "id": "K8S-AUTOMOUNT-SA-TOKEN",
                "title": "Service Account Token Automatically Mounted",
                "severity": "medium",
                "description":
                    "The pod automatically receives a service account token.",
                "recommendation":
                    "Set automountServiceAccountToken=false unless "
                    "the workload explicitly requires Kubernetes API access."
            })

        highest_risk = "info"

        severity_order = {
            "info": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        for finding in findings:
            if severity_order[finding["severity"]] > severity_order[highest_risk]:
                highest_risk = finding["severity"]

        g.add_node(
            pid,
            "Pod",
            pod.metadata.name,
            namespace=pod.metadata.namespace,
            hostPID=host_pid,
            hostNetwork=host_network,
            privileged=privileged,
            allowPrivilegeEscalation=allow_privilege_escalation,
            runAsNonRoot=run_as_non_root,
            readOnlyRootFilesystem=read_only_root_filesystem,
            tokenAutomount=token_automount,
            findings=findings,
            risk=highest_risk,
            is_source=True
        )

        sa_name = spec.service_account_name or "default"
        said = sa_id(pod.metadata.namespace, sa_name)
        g.add_edge(pid, said, "RUNS_AS")

        if token_automount is not False:  # None or True -> token IS mounted (default)
            g.add_edge(pid, said, "TOKEN_MOUNTED", risk="medium")

        if pod.spec.node_name:
            g.add_edge(pid, node_id_(pod.spec.node_name), "SCHEDULED_ON")

        if privileged or host_pid:
            g.add_edge(pid, node_id_(pod.spec.node_name or "unscheduled"),
                       "CAN_ESCAPE_TO_NODE", risk="critical")

    # ---- Roles + ClusterRoles -> resolve rules ----
    def process_rules(rules, subject_id, source_namespace):
        for rule in rules:
            resources = rule.resources or []
            verbs = rule.verbs or []
            ns_label = source_namespace or "cluster-wide"
            for res in resources:
                for verb in verbs:
                    relation = DANGEROUS_RULES.get(res, {}).get(verb)
                    if relation:
                        target = ns_id(ns_label)
                        g.add_node(target, "Namespace", ns_label, is_sink=True)
                        g.add_edge(subject_id, target, relation, risk="high")
                    if verb in ESCALATION_VERBS:
                        target = ns_id(ns_label)
                        g.add_node(target, "Namespace", ns_label, is_sink=True)
                        g.add_edge(subject_id, target, "CAN_ESCALATE_PRIVILEGE", risk="critical")

    # RoleBindings (namespaced)
    for binding in rbac.list_role_binding_for_all_namespaces().items:
        try:
            if binding.role_ref.kind == "Role":
                role = rbac.read_namespaced_role(binding.role_ref.name, binding.metadata.namespace)
            else:
                role = rbac.read_cluster_role(binding.role_ref.name)
        except ApiException:
            continue
        for subject in (binding.subjects or []):
            if subject.kind == "ServiceAccount":
                subj_id = sa_id(subject.namespace or binding.metadata.namespace, subject.name)
                process_rules(role.rules or [], subj_id, binding.metadata.namespace)

    # ClusterRoleBindings (cluster-wide)
    for binding in rbac.list_cluster_role_binding().items:
        try:
            role = rbac.read_cluster_role(binding.role_ref.name)
        except ApiException:
            continue
        for subject in (binding.subjects or []):
            if subject.kind == "ServiceAccount":
                subj_id = sa_id(subject.namespace or "default", subject.name)
                process_rules(role.rules or [], subj_id, None)

    return g


def extract_graph(context=None):
    """Extract the selected Kubernetes context and return graph data as a dict.

    This function can be called by the CLI or by the backend without writing
    an intermediate JSON file.
    """
    config.load_kube_config(context=context)
    v1 = client.CoreV1Api()
    rbac = client.RbacAuthorizationV1Api()
    networking = client.NetworkingV1Api()

    graph = build_graph(v1, rbac, networking)
    return graph.to_json()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=DEFAULT_OUTPUT)
    parser.add_argument("--context", default=None)
    args = parser.parse_args()

    data = extract_graph(context=args.context)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"Wrote {len(data['nodes'])} nodes and {len(data['edges'])} edges to {args.out}")


if __name__ == "__main__":
    main()
