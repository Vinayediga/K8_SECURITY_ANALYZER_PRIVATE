#!/usr/bin/env python3
"""
convert_graph.py - turn a non-standard graph JSON into the standard format used
by extract_graph.py / graph_engine.py / the backend / the frontend.

Handles: from/to or source/target; relation/relationship/label/type on edges;
risk as a number (risk_score, score, cvss) or a word ("high", "Critical",
"moderate"); findings/vulnerabilities/issues lists (strings allowed); missing
weights; edges that point at nodes that do not exist (dropped and reported).
If NO node in the file has findings, findings are derived from risk ratings and
well-known flags (privileged, hostPID, hostNetwork, vulnerable ...).

Usage:
    python convert_graph.py input.json [-o output.json]
"""
import argparse
import json
import sys
from pathlib import Path

ALIASES = {"critical": "critical", "severe": "critical", "high": "high", "important": "high",
           "medium": "medium", "moderate": "medium", "med": "medium",
           "low": "info", "info": "info", "informational": "info", "none": "info"}
SCORE = {"critical": 9.0, "high": 7.0, "medium": 4.0, "info": 1.0}
RANK = {"critical": 4, "high": 3, "medium": 2, "info": 1}
WEIGHT = {"critical": 1.0, "high": 3.0, "medium": 5.0, "info": 9.0}


def label_to_sev(v):
    return ALIASES.get(v.strip().lower()) if isinstance(v, str) else None


def num(*values):
    for v in values:
        if v is None or isinstance(v, bool) or v == "":
            continue
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    return None


def score_to_sev(s):
    if s is None:
        return "info"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "info"


def weight_to_sev(w):
    return "critical" if w <= 1 else "high" if w <= 3 else "medium" if w <= 6 else "info"


def norm_finding(f, i, fallback):
    if isinstance(f, str):
        return {"id": f, "title": f, "severity": fallback, "description": "", "recommendation": ""}
    sev = label_to_sev(f.get("severity")) or label_to_sev(f.get("risk"))
    cvss = num(f.get("cvss"), f.get("score"))
    sev = sev or (score_to_sev(cvss) if cvss is not None else fallback)
    out = dict(f)
    out.update(id=str(f.get("id") or f.get("cve") or f.get("title") or f"finding-{i}"),
               title=str(f.get("title") or f.get("name") or f.get("id") or f.get("cve") or "Security finding"),
               severity=sev, description=f.get("description") or f.get("details") or "",
               recommendation=f.get("recommendation") or f.get("remediation") or f.get("fix") or "")
    return out


def derive(n):
    out = []

    def add(i, t, s, d, r):
        out.append({"id": i, "title": t, "severity": s, "description": d, "recommendation": r})

    if n.get("privileged") is True:
        add("K8S-PRIVILEGED-CONTAINER", "Privileged Container", "critical",
            "Container runs with privileged mode enabled, which can significantly increase access to the host.",
            "Disable privileged mode unless explicitly required.")
    if n.get("hostPID") is True:
        add("K8S-HOSTPID", "Host PID Namespace", "high",
            "Pod shares the host PID namespace and may observe processes running on the Kubernetes node.",
            "Disable hostPID unless there is a documented requirement.")
    if n.get("hostNetwork") is True:
        add("K8S-HOSTNETWORK", "Host Network Enabled", "high",
            "Pod uses the host network namespace, increasing its access to node-level networking.",
            "Disable hostNetwork unless it is explicitly required.")
    if n.get("allowPrivilegeEscalation") is True:
        add("K8S-PRIVILEGE-ESCALATION", "Privilege Escalation Allowed", "high",
            "One or more containers allow privilege escalation.", "Set allowPrivilegeEscalation to false.")
    if n.get("vulnerable") is True:
        sev = n["_sev"] if RANK[n["_sev"]] >= 2 else "high"
        add("K8S-VULNERABLE", "Resource Flagged as Vulnerable", sev,
            f"{n['label']} is flagged as vulnerable in the graph data.",
            "Review the resource's exposure, permissions and known vulnerabilities, and apply fixes.")
    if not out and n["_has_risk"] and RANK[n["_sev"]] >= 2:
        add(f"RISK-{n['_sev'].upper()}", f"{n['_sev'].capitalize()}-risk {n['type']}", n["_sev"],
            f"{n['label']} is rated {n['_sev']} risk (score {n['risk_score']:.1f}). The input had no findings "
            "list, so this finding was derived from the risk rating.",
            "Review this resource's permissions, exposure and configuration.")
    return out


def convert(data):
    raw_nodes = data.get("nodes")
    raw_edges = data.get("edges", data.get("links"))
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise SystemExit("Input must be an object with 'nodes' and 'edges' arrays.")

    nodes, seen = [], set()
    for i, n in enumerate(raw_nodes):
        nid = str(n.get("id", f"node-{i}"))
        if nid in seen:
            print(f"  ! duplicate node id skipped: {nid}", file=sys.stderr)
            continue
        seen.add(nid)
        word = label_to_sev(n.get("severity")) or label_to_sev(n.get("risk")) or label_to_sev(n.get("risk_level"))
        score = num(n.get("risk_score"), n.get("riskScore"), n.get("score"), n.get("cvss"), n.get("risk"))
        has_risk = score is not None or word is not None
        if score is None:
            score = SCORE[word] if word else 1.0
        sev = word or score_to_sev(score)
        cves = next((n[k] for k in ("cves", "CVEs", "cve") if isinstance(n.get(k), list)), [])
        raw_f = next((n[k] for k in ("findings", "vulnerabilities", "issues") if isinstance(n.get(k), list)), None)
        findings = [norm_finding(f, j, sev) for j, f in enumerate(raw_f)] if raw_f else []
        out = {k: v for k, v in n.items() if k not in ("vulnerabilities", "issues", "CVEs", "cve", "severity", "risk", "risk_level", "riskScore", "score", "isSource", "isSink")}
        out.update(id=nid, label=str(n.get("label") or n.get("name") or nid), type=str(n.get("type") or n.get("kind") or "Unknown"),
                   risk_score=score, is_source=bool(n.get("is_source", n.get("isSource", False))),
                   is_sink=bool(n.get("is_sink", n.get("isSink", False))), cves=cves,
                   _sev=sev, _has_risk=has_risk)
        if findings:
            out["findings"] = findings
        nodes.append(out)

    derived = 0
    if not any(n.get("findings") for n in nodes):
        for n in nodes:
            f = derive(n)
            if f:
                n["findings"] = f
                derived += len(f)

    for n in nodes:  # a node is at least as risky as its worst finding
        for f in n.get("findings", []):
            n["risk_score"] = max(n["risk_score"], SCORE[f["severity"]])
        del n["_sev"], n["_has_risk"]

    ids, edges, dropped = {n["id"] for n in nodes}, [], []
    for e in raw_edges:
        s, t = str(e.get("source", e.get("from", ""))), str(e.get("target", e.get("to", "")))
        rel = str(e.get("relationship") or e.get("relation") or e.get("label") or e.get("type") or "UNKNOWN")
        if s not in ids or t not in ids:
            dropped.append(f"{s} -> {t} ({rel})")
            continue
        w, cvss = num(e.get("weight"), e.get("cost")), num(e.get("cvss"))
        risk = label_to_sev(e.get("risk")) or label_to_sev(e.get("severity")) or \
            (score_to_sev(cvss) if cvss is not None else weight_to_sev(w if w is not None else 1.0))
        if w is None or w < 0:
            w = WEIGHT[risk]
        out = {k: v for k, v in e.items() if k not in ("from", "to", "label", "type", "severity")}
        out.update(source=s, target=t, relation=rel, relationship=rel, weight=w, risk=risk)
        edges.append(out)

    print(f"nodes: {len(nodes)}  edges: {len(edges)}  dropped edges: {len(dropped)}  derived findings: {derived}")
    for d in dropped:
        print(f"  ! dropped (unknown endpoint): {d}", file=sys.stderr)
    if not any(n["is_source"] for n in nodes) or not any(n["is_sink"] for n in nodes):
        print("  ! no is_source / is_sink flags: critical-node analysis will not run", file=sys.stderr)
    return {"nodes": nodes, "edges": edges}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    args = ap.parse_args()
    out_path = Path(args.output) if args.output else Path(args.input).with_suffix(".standard.json")
    result = convert(json.loads(Path(args.input).read_text(encoding="utf-8")))
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
