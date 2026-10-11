import { useMemo, useState } from "react";
import { useGraph } from "../context/GraphContext.jsx";
import { collectMitigations, severityColor } from "../lib/graph.js";

const FILTERS = ["all", "critical", "high", "medium", "info"];

function Badge({ severity }) {
  const c = severityColor(severity);
  return <span className="severity-badge" style={{ color: c, background: `${c}12` }}>{severity}</span>;
}

export default function MitigationPane() {
  const { graph } = useGraph();
  const [filter, setFilter] = useState("all");
  const [selectedKey, setSelectedKey] = useState(null);

  const items = useMemo(() => collectMitigations(graph), [graph]);
  const filtered = items.filter((i) => filter === "all" || i.severity === filter);
  const selected = items.find((i) => i.key === selectedKey);
  const count = (s) => items.filter((i) => i.severity === s).length;

  return (
    <section className="app-pane">
      <div className="pane-header">
        <div>
          <div className="pane-title">Mitigation & Recommendations</div>
          <div className="pane-subtitle">Map each detected security weakness to a practical Kubernetes security control and remediation action.</div>
        </div>
      </div>

      <div className="mitigation-summary">
        <div className="mitigation-card"><div className="mitigation-card-label">Total Recommendations</div><div className="mitigation-card-value">{items.length}</div></div>
        <div className="mitigation-card"><div className="mitigation-card-label">Critical</div><div className="mitigation-card-value">{count("critical")}</div></div>
        <div className="mitigation-card"><div className="mitigation-card-label">High Priority</div><div className="mitigation-card-value">{count("high")}</div></div>
        <div className="mitigation-card"><div className="mitigation-card-label">Controls Covered</div><div className="mitigation-card-value">{new Set(items.map((i) => i.control.name)).size}</div></div>
      </div>

      <div className="mitigation-layout">
        <div className="mitigation-panel">
          <h2>Recommended Actions</h2>
          <div className="mitigation-subtitle">Select a finding to view the associated security control and remediation guidance.</div>
          <div className="mitigation-filters">
            {FILTERS.map((f) => (
              <button key={f} className={`mitigation-filter ${filter === f ? "active" : ""}`} onClick={() => setFilter(f)}>
                {f[0].toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
          <div className="mitigation-list">
            {!filtered.length ? (
              <div className="mitigation-detail-empty"><div>
                <strong style={{ display: "block", color: "var(--text)", fontSize: 13, marginBottom: 5 }}>No recommendations</strong>
                <span>No findings match the selected severity.</span>
              </div></div>
            ) : filtered.map((i) => (
              <div key={i.key} className={`mitigation-item ${i.key === selectedKey ? "selected" : ""}`} onClick={() => setSelectedKey(i.key)}>
                <div className="mitigation-item-head">
                  <div>
                    <div className="mitigation-item-title">{i.title}</div>
                    <div className="mitigation-item-resource">{i.resource} · {i.namespace}</div>
                  </div>
                  <Badge severity={i.severity} />
                </div>
                <div className="mitigation-control">{i.control.name}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="mitigation-panel">
          <h2>Security Control</h2>
          {!selected ? (
            <div className="mitigation-detail-empty"><div>
              <strong style={{ display: "block", color: "var(--text)", fontSize: 14, marginBottom: 6 }}>Select a recommendation</strong>
              <span>The selected finding's remediation and mapped Kubernetes security control will appear here.</span>
            </div></div>
          ) : (
            <>
              <div className="mitigation-detail-title">{selected.title}</div>
              <div className="finding-detail-meta">
                <Badge severity={selected.severity} />
                <span className="finding-meta-chip">{selected.resource}</span>
                <span className="finding-meta-chip">{selected.namespace}</span>
              </div>
              <div className="mitigation-detail-section"><h3>Security Control</h3>
                <div className="control-box"><strong>{selected.control.name}</strong><span>{selected.control.explanation}</span></div>
              </div>
              <div className="mitigation-detail-section"><h3>Recommended Remediation</h3><p>{selected.recommendation}</p></div>
              <div className="mitigation-detail-section"><h3>Why This Matters</h3><p>{selected.description}</p></div>
              <div className="mitigation-detail-section"><h3>Affected Resource</h3><p>{selected.resource} · {selected.type} · {selected.namespace}</p></div>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
