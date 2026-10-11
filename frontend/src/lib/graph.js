import { RISK_COLORS, SYSTEM_NAMESPACES } from "./constants.js";

export function severityColor(severity) {
  return RISK_COLORS[severity] || RISK_COLORS.info;
}

/** Map a CVSS-like numeric score to a severity label. */
export function scoreToSeverity(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return "info";
  if (n >= 9) return "critical";
  if (n >= 7) return "high";
  if (n >= 4) return "medium";
  return "info";
}

/** Map an edge weight (lower = easier for an attacker) to a severity label. */
function weightToSeverity(weight) {
  const n = Number(weight);
  if (!Number.isFinite(n)) return "info";
  if (n <= 1) return "critical";
  if (n <= 3) return "high";
  if (n <= 6) return "medium";
  return "info";
}

const SEVERITY_ALIASES = {
  critical: "critical", severe: "critical",
  high: "high", important: "high",
  medium: "medium", moderate: "medium", med: "medium",
  low: "info", info: "info", informational: "info", none: "info",
};
const SEVERITY_SCORE = { critical: 9, high: 7, medium: 4, info: 1 };
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, info: 1 };

/** Accepts "High", "moderate", "LOW"… and returns critical|high|medium|info, or null. */
export function severityFromLabel(value) {
  if (typeof value !== "string") return null;
  return SEVERITY_ALIASES[value.trim().toLowerCase()] ?? null;
}

const firstFinite = (...values) => {
  for (const v of values) {
    if (v === null || v === undefined || v === "" || typeof v === "boolean") continue;
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
};

function normalizeFinding(f, i, fallbackSeverity) {
  if (typeof f === "string") {
    return { id: f, title: f, severity: fallbackSeverity, description: "", recommendation: "" };
  }
  const severity =
    severityFromLabel(f.severity) ?? severityFromLabel(f.risk) ?? scoreToSeverity(firstFinite(f.cvss, f.score) ?? NaN);
  return {
    ...f,
    id: String(f.id ?? f.cve ?? f.title ?? `finding-${i}`),
    title: String(f.title ?? f.name ?? f.id ?? f.cve ?? "Security finding"),
    severity: Number.isFinite(firstFinite(f.cvss, f.score)) || severityFromLabel(f.severity) || severityFromLabel(f.risk) ? severity : fallbackSeverity,
    description: f.description ?? f.details ?? "",
    recommendation: f.recommendation ?? f.remediation ?? f.fix ?? "",
  };
}


const cap = (t) => t.charAt(0).toUpperCase() + t.slice(1);

/**
 * Some graph files only carry a risk rating per node and no findings list.
 * Only in that case (no node in the whole file has findings) we build findings
 * from the rating and from well-known flags, so Findings / Risk / Mitigation
 * are not empty. Derived findings are labelled as such. Graphs from the
 * extractor already contain findings and are never touched.
 */
function deriveFindings(n) {
  const out = [];
  const add = (id, title, severity, description, recommendation) =>
    out.push({ id, title, severity, description, recommendation, derived: true });

  if (n.privileged === true)
    add("K8S-PRIVILEGED-CONTAINER", "Privileged Container", "critical",
      "Container runs with privileged mode enabled, which can significantly increase access to the host.",
      "Disable privileged mode unless explicitly required.");
  if (n.hostPID === true)
    add("K8S-HOSTPID", "Host PID Namespace", "high",
      "Pod shares the host PID namespace and may observe processes running on the Kubernetes node.",
      "Disable hostPID unless there is a documented requirement.");
  if (n.hostNetwork === true)
    add("K8S-HOSTNETWORK", "Host Network Enabled", "high",
      "Pod uses the host network namespace, increasing its access to node-level networking.",
      "Disable hostNetwork unless it is explicitly required.");
  if (n.allowPrivilegeEscalation === true)
    add("K8S-PRIVILEGE-ESCALATION", "Privilege Escalation Allowed", "high",
      "One or more containers allow privilege escalation.",
      "Set allowPrivilegeEscalation to false.");
  if (n.vulnerable === true)
    add("K8S-VULNERABLE", "Resource Flagged as Vulnerable",
      SEVERITY_RANK[n.risk] >= 2 ? n.risk : "high",
      `${n.label} is flagged as vulnerable in the graph data.`,
      "Review the resource's exposure, permissions and known vulnerabilities, and apply the relevant patches or configuration fixes.");

  if (!out.length && n.hasRiskInfo && SEVERITY_RANK[n.risk] >= 2) {
    const score = Number.isFinite(n.risk_score) ? ` (score ${n.risk_score.toFixed(1)})` : "";
    add(`RISK-${n.risk.toUpperCase()}`, `${cap(n.risk)}-risk ${n.type}`, n.risk,
      `${n.label} is rated ${n.risk} risk${score}. The loaded graph has no detailed findings list, so this finding was derived from the risk rating.`,
      "Review this resource's permissions, exposure and configuration. Add a findings list to the graph JSON to get specific remediation steps.");
  }
  return out;
}

function normalizeNode(node, index) {
  const id = String(node.id ?? `node-${index}`);

  // Risk may arrive as a number (risk_score / score / cvss / numeric risk) or a
  // label (risk / severity: "high"). Accept either and derive the other.
  const labelRisk = severityFromLabel(node.severity) ?? severityFromLabel(node.risk) ?? severityFromLabel(node.risk_level);
  let score = firstFinite(node.risk_score, node.riskScore, node.score, node.cvss, node.cvss_score, node.risk);
  const hasRiskInfo = score !== null || labelRisk !== null;
  if (score === null && labelRisk) score = SEVERITY_SCORE[labelRisk];

  const cves = [node.cves, node.CVEs, node.cve].find(Array.isArray) ?? [];
  const baseSeverity = labelRisk ?? scoreToSeverity(score);

  const rawFindings = [node.findings, node.vulnerabilities, node.issues].find(Array.isArray);
  const findings = rawFindings
    ? rawFindings.map((f, i) => normalizeFinding(f, i, baseSeverity))
    : cves.map((cve) => ({
        id: String(cve),
        title: String(cve),
        severity: baseSeverity,
        description: `${cve} is associated with ${node.name ?? node.label ?? id}.`,
        recommendation:
          "Review the affected workload and apply the vendor/Kubernetes security remediation for this vulnerability.",
      }));

  // A node is at least as risky as its worst finding.
  let risk = baseSeverity;
  findings.forEach((f) => {
    if ((SEVERITY_RANK[f.severity] || 0) > (SEVERITY_RANK[risk] || 0)) risk = f.severity;
  });

  return {
    ...node,
    id,
    label: String(node.label ?? node.name ?? id),
    name: String(node.name ?? node.label ?? id),
    type: String(node.type ?? node.kind ?? "Unknown"),
    namespace: node.namespace ?? null,
    risk_score: score,
    risk,
    hasRiskInfo,
    cves,
    findings,
    isSource: Boolean(node.is_source ?? node.isSource ?? false),
    isSink: Boolean(node.is_sink ?? node.isSink ?? false),
  };
}

function normalizeEdge(edge, index) {
  const source = String(edge.source ?? edge.from ?? "");
  const target = String(edge.target ?? edge.to ?? "");
  const relation = String(edge.relationship ?? edge.relation ?? edge.label ?? edge.type ?? "UNKNOWN");
  const weight = firstFinite(edge.weight, edge.cost);
  const cvss = firstFinite(edge.cvss);

  // Prefer an explicit severity from the extractor, then CVSS, then weight.
  const explicit = severityFromLabel(edge.risk) ?? severityFromLabel(edge.severity);
  const risk = explicit ?? (cvss !== null ? scoreToSeverity(cvss) : weightToSeverity(weight ?? 1));

  return {
    ...edge,
    id: String(edge.id ?? `e${index}`),
    source,
    target,
    relation,
    weight: weight !== null && weight >= 0 ? weight : 1,
    hasWeight: weight !== null,
    cvss,
    risk,
  };
}

export function normalizeGraph(input) {
  if (!input || !Array.isArray(input.nodes) || !Array.isArray(input.edges)) {
    throw new Error("Graph JSON must contain nodes and edges arrays.");
  }
  const nodes = input.nodes.map(normalizeNode);

  let derivedFindings = 0;
  if (nodes.every((n) => n.findings.length === 0)) {
    nodes.forEach((n) => {
      n.findings = deriveFindings(n);
      derivedFindings += n.findings.length;
      n.findings.forEach((f) => {
        if ((SEVERITY_RANK[f.severity] || 0) > (SEVERITY_RANK[n.risk] || 0)) n.risk = f.severity;
      });
    });
  }
  const ids = new Set(nodes.map((n) => n.id));
  const allEdges = input.edges.map(normalizeEdge);
  const edges = allEdges.filter((e) => ids.has(e.source) && ids.has(e.target));

  // Surface format problems instead of failing silently.
  const diagnostics = {
    droppedEdges: allEdges
      .filter((e) => !(ids.has(e.source) && ids.has(e.target)))
      .map((e) => `${e.source || "?"} → ${e.target || "?"} (${e.relation})`),
    nodesWithoutRisk: nodes.filter((n) => !n.hasRiskInfo && n.findings.length === 0).length,
    nodesWithFindings: nodes.filter((n) => n.findings.length > 0).length,
    derivedFindings,
    edgesWithoutWeight: edges.filter((e) => !e.hasWeight).length,
    sources: nodes.filter((n) => n.isSource).length,
    sinks: nodes.filter((n) => n.isSink).length,
  };

  return { ...input, metadata: input.metadata || {}, nodes, edges, diagnostics };
}

export function isSystemNode(node) {
  return SYSTEM_NAMESPACES.has(node.namespace) || node.id === "ns:kube-system";
}

/* ---------- Findings ---------- */

export function collectFindings(graph) {
  if (!graph) return [];
  const out = [];
  graph.nodes.forEach((node) => {
    (node.findings || []).forEach((f, i) => {
      out.push({
        key: `${node.id}::${f.id || f.title || i}`,
        nodeId: node.id,
        resource: node.label,
        type: node.type,
        namespace: node.namespace || "—",
        id: f.id || "—",
        title: f.title || f.id || "Security Finding",
        severity: String(f.severity || "info").toLowerCase(),
        description: f.description || "No description provided.",
        recommendation: f.recommendation || "No recommendation provided.",
        derived: Boolean(f.derived),
      });
    });
  });
  return out;
}

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, info: 0 };
  findings.forEach((f) => {
    if (f.severity in counts) counts[f.severity] += 1;
  });
  return counts;
}

/* ---------- Mitigation mapping ---------- */

export function mitigationControlFor(finding) {
  const id = String(finding.id || "").toUpperCase();
  const title = String(finding.title || "").toLowerCase();

  if (id.includes("NETWORK-POLICY") || title.includes("networkpolicy"))
    return { name: "NetworkPolicy / Network Segmentation", explanation: "Restrict ingress and egress traffic using least-privilege Kubernetes NetworkPolicies." };
  if (id.includes("HOSTNETWORK") || id.includes("HOSTPID") || title.includes("host pid") || title.includes("host network"))
    return { name: "Pod Isolation", explanation: "Avoid host namespaces unless explicitly required; enforce workload isolation through Pod Security controls." };
  if (id.includes("PRIVILEGED") || title.includes("privileged container"))
    return { name: "Pod Security Controls", explanation: "Disallow privileged containers and enforce an appropriate Pod Security Standard for workloads." };
  if (id.includes("TOKEN") || title.includes("service account"))
    return { name: "Service Account Hardening", explanation: "Disable automatic service-account token mounting unless Kubernetes API access is explicitly required." };
  if (id.includes("RBAC") || title.includes("role") || title.includes("permission") || title.includes("privilege escalation"))
    return { name: "Least-Privilege RBAC", explanation: "Reduce Kubernetes permissions to only the verbs and resources required by the workload." };
  if (id.includes("ROOT") || title.includes("root filesystem") || title.includes("as root"))
    return { name: "Container Hardening", explanation: "Run containers as non-root users and use a read-only root filesystem where application compatibility permits." };

  return { name: "Kubernetes Workload Hardening", explanation: "Apply least-privilege configuration and remove unnecessary Kubernetes capabilities from the affected resource." };
}

export function collectMitigations(graph) {
  return collectFindings(graph).map((f) => ({ ...f, control: mitigationControlFor(f) }));
}
