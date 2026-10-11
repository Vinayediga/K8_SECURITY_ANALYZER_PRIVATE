import { useMemo, useState } from "react";
import { useGraph } from "../context/GraphContext.jsx";
import { collectFindings, countBySeverity, severityColor } from "../lib/graph.js";

const STATS = [["all", "All Findings"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["info", "Info"]];

function Badge({ severity }) {
  const c = severityColor(severity);
  return <span className="severity-badge" style={{ color: c, background: `${c}12` }}>{severity}</span>;
}

export default function FindingsPane() {
  const { graph, setSelectedNodeId } = useGraph();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selectedKey, setSelectedKey] = useState(null);

  const findings = useMemo(() => collectFindings(graph), [graph]);
  const counts = useMemo(() => countBySeverity(findings), [findings]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (severity !== "all" && f.severity !== severity) return false;
      if (!q) return true;
      return [f.resource, f.type, f.namespace, f.id, f.title, f.description, f.recommendation].join(" ").toLowerCase().includes(q);
    });
  }, [findings, search, severity]);

  const selected = findings.find((f) => f.key === selectedKey);
  const countFor = (key) => (key === "all" ? findings.length : counts[key]);

  return (
    <section className="app-pane">
      <div className="pane-header">
        <div>
          <div className="pane-title">Security Findings</div>
          <div className="pane-subtitle">Review detected Kubernetes security weaknesses by severity, affected resource, and recommended action.</div>
        </div>
      </div>

      <div className="finding-stat-grid">
        {STATS.map(([key, label]) => (
          <div key={key} className={`finding-stat ${severity === key ? "active" : ""}`} onClick={() => setSeverity(key)}>
            <div className="finding-stat-label">{label}</div>
            <div className="finding-stat-value">{countFor(key)}</div>
          </div>
        ))}
      </div>

      <div className="findings-toolbar">
        <input className="finding-search" type="search" placeholder="Search resource, namespace, finding, or ID..."
          autoComplete="off" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select className="finding-filter" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="info">Info</option>
        </select>
      </div>

      <div className="findings-layout">
        <div className="finding-table-wrap">
          <table className="finding-table">
            <thead><tr><th>Severity</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
            <tbody>
              {!filtered.length ? (
                <tr><td colSpan={4}><div className="findings-empty"><div>
                  <strong style={{ display: "block", color: "var(--text)", fontSize: 14, marginBottom: 6 }}>No matching findings</strong>
                  <span>{graph ? "Try another severity or search term." : "Load a graph to see findings."}</span>
                </div></div></td></tr>
              ) : filtered.map((f) => (
                <tr key={f.key} className={f.key === selectedKey ? "selected" : ""}
                  onClick={() => { setSelectedKey(f.key); setSelectedNodeId(f.nodeId); }}>
                  <td><Badge severity={f.severity} /></td>
                  <td><div className="finding-resource">{f.resource}</div><div className="finding-namespace">{f.namespace}</div></td>
                  <td><div className="finding-title">{f.title}</div><div className="finding-id">{f.id}</div></td>
                  <td><span style={{ color: "var(--text-dim)", lineHeight: 1.45 }}>{f.recommendation}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="finding-detail">
          <h2 style={{ fontSize: 13, marginBottom: 10 }}>🔍 Finding Details</h2>
          {!selected ? (
            <div className="findings-empty"><div>
              <strong style={{ display: "block", color: "var(--text)", fontSize: 14, marginBottom: 6 }}>Select a security finding</strong>
              <span>Choose a finding from the table to view its description and recommended action.</span>
            </div></div>
          ) : (
            <div className="finding-detail-card">
              <div className="finding-detail-title">{selected.title}</div>
              <div className="finding-detail-meta">
                <Badge severity={selected.severity} />
                <span className="finding-meta-chip">Resource: {selected.resource}</span>
                <span className="finding-meta-chip">Type: {selected.type}</span>
                <span className="finding-meta-chip">Namespace: {selected.namespace}</span>
              </div>
              <div className="finding-detail-section"><h3>Description</h3><p>{selected.description}</p></div>
              <div className="finding-detail-section"><h3>Recommended Action</h3><div className="recommendation-box">{selected.recommendation}</div></div>
              <div className="finding-detail-section"><h3>Finding ID</h3><p>{selected.id}{selected.derived ? " · derived from risk rating (no findings list in the graph file)" : ""}</p></div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
