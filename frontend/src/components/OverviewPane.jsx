import { useGraph } from "../context/GraphContext.jsx";
import { collectFindings, countBySeverity } from "../lib/graph.js";

export default function OverviewPane() {
  const { graph, meta, error } = useGraph();
  const findings = collectFindings(graph);
  const counts = countBySeverity(findings);
  const dash = (v) => (graph ? v : "—");

  return (
    <section className="app-pane">
      <div className="pane-header">
        <div>
          <div className="pane-title">Security Overview</div>
          <div className="pane-subtitle">
            A high-level view of the Kubernetes attack surface and graph analysis.
            {meta.label && <> Source: <b>{meta.label}</b>{meta.source === "api" ? " (from backend)" : ""}.</>}
          </div>
        </div>
      </div>

      {error && <div className="attack-analysis-result" style={{ borderColor: "var(--risk-critical)" }}><div className="attack-result-text">{error}</div></div>}
      {!graph && !error && (
        <div className="placeholder-panel"><div><strong>No graph loaded</strong><span>Open “Clusters & Scans” to load a snapshot, or upload a graph JSON from the top bar.</span></div></div>
      )}

      {graph?.diagnostics && <DataCheck d={graph.diagnostics} />}

      <div className="pane-grid">
        <div className="metric-card"><div className="metric-label">Graph Nodes</div><div className="metric-value">{dash(graph?.nodes.length)}</div><div className="metric-note">Kubernetes resources modeled</div></div>
        <div className="metric-card"><div className="metric-label">Graph Edges</div><div className="metric-value">{dash(graph?.edges.length)}</div><div className="metric-note">Relationships / attack transitions</div></div>
        <div className="metric-card"><div className="metric-label">Security Findings</div><div className="metric-value">{dash(findings.length)}</div><div className="metric-note">Structured findings detected</div></div>
        <div className="metric-card"><div className="metric-label">Critical Findings</div><div className="metric-value">{dash(counts.critical)}</div><div className="metric-note">Highest-severity findings</div></div>
      </div>

      <div className="feature-grid">
        <div className="feature-card"><h3>🕸️ Attack Graph</h3><p>Explore Kubernetes resources and the relationships that form potential attack transitions.</p></div>
        <div className="feature-card"><h3>🛡️ Security Findings</h3><p>Review security weaknesses with severity, description, and recommended action.</p></div>
        <div className="feature-card"><h3>🛣️ Attack Path Analysis</h3><p>Use BFS, Dijkstra, DFS, and critical-node analysis to study attack propagation and path impact.</p></div>
      </div>
    </section>
  );
}

function DataCheck({ d }) {
  const issues = [];
  if (d.droppedEdges.length)
    issues.push(`${d.droppedEdges.length} edge(s) were skipped because their source or target is not in the node list, e.g. ${d.droppedEdges.slice(0, 3).join("; ")}.`);
  if (d.nodesWithoutRisk)
    issues.push(`${d.nodesWithoutRisk} node(s) have no risk data (expected risk_score, or risk/severity such as "high") and are shown as info.`);
  if (d.derivedFindings)
    issues.push(`The file has no findings list, so ${d.derivedFindings} finding(s) were derived from node risk ratings and flags (privileged, hostNetwork, vulnerable…). For specific descriptions and fixes, include findings: [{id, title, severity, description, recommendation}] on each node.`);
  else if (!d.nodesWithFindings)
    issues.push("No node has a findings list or any risk of medium or above, so Findings, Risk and Mitigation will be empty.");
  if (!d.sources || !d.sinks)
    issues.push(`Critical-node analysis needs is_source and is_sink flags (found ${d.sources} source, ${d.sinks} sink nodes).`);
  if (d.edgesWithoutWeight)
    issues.push(`${d.edgesWithoutWeight} edge(s) have no weight; shortest-path treats them as cost 1.`);
  if (!issues.length) return null;
  return (
    <div className="attack-analysis-result" style={{ borderColor: "var(--risk-medium)" }}>
      <div className="attack-result-title">⚠ Data check — the loaded graph differs from the expected format</div>
      <ul className="attack-result-text" style={{ listStyle: "disc", paddingLeft: 18 }}>
        {issues.map((t) => <li key={t}>{t}</li>)}
      </ul>
    </div>
  );
}
