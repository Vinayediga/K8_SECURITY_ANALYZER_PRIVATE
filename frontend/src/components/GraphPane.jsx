import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { useGraph } from "../context/GraphContext.jsx";
import { NODE_COLORS, RISK_COLORS, TOPOLOGY_EDGES } from "../lib/constants.js";
import { isSystemNode, severityColor } from "../lib/graph.js";

cytoscape.use(dagre);

const LAYOUTS = {
  dagre: { name: "dagre", rankDir: "LR", nodeSep: 35, rankSep: 110, edgeSep: 15, animate: false, fit: false, padding: 40, nodeDimensionsIncludeLabels: true },
  cose: { name: "cose", animate: false, padding: 40, nodeRepulsion: 9000, idealEdgeLength: 90 },
};

const LEGEND = [
  ["Pod", "Pod"], ["ServiceAccount", "ServiceAccount"], ["Namespace", "Namespace"], ["Secret", "Secret"],
  ["Node", "Node"], ["User", "User"], ["Role", "Role"], ["Service", "Service"],
  ["ConfigMap", "ConfigMap"], ["Database", "Database"], ["PersistentVolume", "PersistentVol"],
];

function buildElements(graph) {
  return [
    ...graph.nodes.map((n) => ({
      data: {
        id: n.id, label: n.label, type: n.type, namespace: n.namespace,
        risk: n.risk,
        has_findings: n.findings.length > 0 ? "true" : "false",
        privileged: n.privileged ? "true" : "false",
      },
    })),
    ...graph.edges.map((e) => ({
      data: { id: e.id, source: e.source, target: e.target, label: e.relation, relation: e.relation, risk: e.risk },
    })),
  ];
}

const STYLE = [
  { selector: "node", style: {
      "background-color": (n) => NODE_COLORS[n.data("type")] || "#888",
      label: "data(label)", color: "#d7dde3", "font-size": 12, "font-family": "Inter, sans-serif",
      "text-valign": "bottom", "text-margin-y": 6, width: 26, height: 26, "border-width": 2, "border-color": "#0b0e11" } },
  { selector: "node[has_findings = 'true']", style: { "border-color": RISK_COLORS.medium, "border-width": 3 } },
  { selector: "node[risk = 'medium']", style: { "border-color": RISK_COLORS.medium, "border-width": 3 } },
  { selector: "node[risk = 'high']", style: { "border-color": RISK_COLORS.high, "border-width": 4 } },
  { selector: "node[risk = 'critical']", style: { "border-color": RISK_COLORS.critical, "border-width": 5 } },
  { selector: "node[privileged = 'true']", style: { "border-color": RISK_COLORS.critical, "border-width": 3 } },
  { selector: "edge", style: {
      width: (e) => (e.data("risk") === "critical" ? 2.6 : e.data("risk") === "high" ? 2.2 : 1.6),
      "line-color": (e) => RISK_COLORS[e.data("risk")] || "#555",
      "target-arrow-color": (e) => RISK_COLORS[e.data("risk")] || "#555",
      "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", "font-size": 10,
      color: "#8a97a3", "text-background-color": "#0b0e11", "text-background-opacity": 0.8,
      "text-background-padding": 2, "arrow-scale": 0.8 } },
  { selector: 'edge[label = "SCHEDULED_ON"], edge[label = "hosts"]', style: {
      width: 0.6, "line-color": "#333c44", "target-arrow-color": "#333c44", "line-style": "dashed",
      opacity: 0.5, "font-size": 9, color: "#4a545c" } },
  { selector: ":selected", style: { "border-color": "#fff", "line-color": "#fff", "target-arrow-color": "#fff" } },
];

const GraphPane = forwardRef(function GraphPane({ view }, ref) {
  const { graph, selectedNodeId, setSelectedNodeId, highlight } = useGraph();
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState(null);
  const [zoomPercent, setZoomPercent] = useState(100);

  const nodeById = useMemo(() => new Map((graph?.nodes || []).map((n) => [n.id, n])), [graph]);
  const nameOf = (id) => nodeById.get(id)?.label || id;
  const syncZoomLabel = (cy) => setZoomPercent(Math.round(cy.zoom() * 100));
  const zoomBy = (factor) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({
      level: Math.max(cy.minZoom(), Math.min(cy.maxZoom(), cy.zoom() * factor)),
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
  };

  const runLayout = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.resize();
    const visible = cy.elements(":visible");
    const target = visible.length ? visible : cy.elements();
    try {
      target.layout({ ...(LAYOUTS[view.layout] || LAYOUTS.dagre), fit: false }).run();
    } catch (err) {
      console.warn("Primary layout failed, falling back to cose:", err);
      target.layout({ ...LAYOUTS.cose, fit: false }).run();
    }
    cy.fit(target, 50);
  };

  useImperativeHandle(ref, () => ({
    relayout: runLayout,
    fit: () => {
      const cy = cyRef.current;
      if (!cy) return;
      const visible = cy.elements(":visible");
      cy.fit(visible.length ? visible : cy.elements(), 50);
    },
    zoomIn: () => {
      const cy = cyRef.current;
      if (!cy) return;
      cy.zoom({
        level: Math.min(cy.maxZoom(), cy.zoom() * 1.2),
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      });
    },
    zoomOut: () => {
      const cy = cyRef.current;
      if (!cy) return;
      cy.zoom({
        level: Math.max(cy.minZoom(), cy.zoom() / 1.2),
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      });
    },
  }));

  // (Re)build the Cytoscape instance whenever the graph changes.
  useEffect(() => {
    if (!graph || !containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current, minZoom: 0.15, maxZoom: 4, wheelSensitivity: 0.18,
      elements: buildElements(graph), style: STYLE,
    });
    cyRef.current = cy;
    syncZoomLabel(cy);
    cy.on("zoom", () => syncZoomLabel(cy));

    cy.on("tap", "node", (ev) => {
      setSelectedEdgeId(null);
      setSelectedNodeId(ev.target.id());
    });
    cy.on("tap", "edge", (ev) => {
      setSelectedNodeId(null);
      setSelectedEdgeId(ev.target.id());
    });
    cy.on("tap", (ev) => {
      if (ev.target === cy) {
        setSelectedNodeId(null);
        setSelectedEdgeId(null);
      }
    });
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, setSelectedNodeId]);

  // Filters + layout.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;
    cy.nodes().forEach((n) => {
      const hidden = isSystemNode(nodeById.get(n.id()) || {}) && !view.showSystem;
      n.style("display", hidden ? "none" : "element");
    });
    cy.edges().forEach((e) => {
      const hidden =
        e.source().style("display") === "none" || e.target().style("display") === "none" ||
        (TOPOLOGY_EDGES.has(e.data("relation")) && !view.showTopology);
      e.style("display", hidden ? "none" : "element");
    });
    const id = requestAnimationFrame(runLayout);
    return () => cancelAnimationFrame(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, view.showSystem, view.showTopology, view.layout]);

  // Reflect analysis highlights from the Attack Paths pane.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !highlight.nodeIds.length) return;
    cy.elements().unselect();
    highlight.nodeIds.forEach((id) => cy.getElementById(id).select());
    highlight.edgeIds.forEach((id) => cy.getElementById(id).select());
    const sel = cy.elements(":selected");
    if (sel.length) cy.fit(sel, 100);
  }, [highlight, graph]);

  // Reflect single-node selection (from this pane, Findings or the micro view).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !selectedNodeId) return;
    cy.elements().unselect();
    const n = cy.getElementById(selectedNodeId);
    if (n.length) n.select();
  }, [selectedNodeId, graph]);

  if (!graph) {
    return <section className="app-pane"><div className="placeholder-panel"><div><strong>No graph loaded</strong><span>Load a scan snapshot from Clusters & Scans, or upload a JSON file.</span></div></div></section>;
  }

  const node = selectedNodeId ? nodeById.get(selectedNodeId) : null;
  const edge = selectedEdgeId ? graph.edges.find((e) => e.id === selectedEdgeId) : null;

  return (
    <section className="app-pane graph-pane">
      <div className="graph-toolbar">
        <span className="graph-toolbar-title">🕸️ Kubernetes Attack Graph</span>
        <span className="tag">Click a node to inspect security findings</span>
        <div className="graph-zoom-controls" aria-label="Graph zoom controls">
          <button type="button" onClick={() => zoomBy(1 / 1.2)} aria-label="Zoom out">−</button>
          <span aria-live="polite">{zoomPercent}%</span>
          <button type="button" onClick={() => zoomBy(1.2)} aria-label="Zoom in">+</button>
        </div>
      </div>
      <div className="graph-stage">
        <div id="cy" ref={containerRef} />

        <div className="graph-side-panel">
          <div className="inline-node-security">
            {node ? <NodeDetails node={node} graph={graph} nameOf={nameOf} /> : edge ? <EdgeDetails edge={edge} nameOf={nameOf} /> : (
              <div className="inline-node-empty"><strong>Node Security</strong><span>Click a node to inspect its security here.</span></div>
            )}
          </div>
        </div>

        <div className="graph-legend">
          <h2>Node types</h2>
          <div className="legend-grid">
            {LEGEND.map(([type, label]) => (
              <div className="legend-row" key={type}><span className="dot" style={{ background: NODE_COLORS[type] }} />{label}</div>
            ))}
          </div>
          <div style={{ marginTop: 10, display: "flex", gap: 12, flexWrap: "wrap" }}>
            {Object.entries(RISK_COLORS).map(([k, c]) => (
              <span className="legend-row" key={k}><span className="dot" style={{ background: c }} />{k}</span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
});

function NodeDetails({ node, graph, nameOf }) {
  const color = severityColor(node.risk);
  const relations = graph.edges.filter((e) => e.source === node.id || e.target === node.id);
  return (
    <>
      <div className="inline-node-head">
        <div>
          <div className="inline-node-type">{node.type}</div>
          <div className="inline-node-name">{node.label}</div>
          <div className="inline-node-ns">{node.namespace || "cluster-wide"}</div>
        </div>
        <span className="inline-node-risk" style={{ color, borderColor: color }}>{node.risk}</span>
      </div>
      <div className="inline-node-stats">
        <div><span>Risk</span><b>{Number.isFinite(node.risk_score) ? node.risk_score.toFixed(1) : "—"}</b></div>
        <div><span>CVEs</span><b>{node.cves.length}</b></div>
        <div><span>Links</span><b>{relations.length}</b></div>
      </div>
      <div className="inline-node-section">
        <div className="inline-node-section-title">Security findings</div>
        {node.findings.length ? node.findings.slice(0, 6).map((f, i) => {
          const sev = String(f.severity || node.risk).toLowerCase();
          const c = severityColor(sev);
          return (
            <div className="inline-node-finding" key={f.id || i} style={{ borderLeft: `3px solid ${c}` }}>
              <div className="inline-node-finding-title">{f.title || f.id}</div>
              <div className="inline-node-finding-meta" style={{ color: c }}>{sev.toUpperCase()}</div>
            </div>
          );
        }) : <div className="inline-node-relation">No security findings recorded.</div>}
        {node.findings.length > 6 && <div className="inline-node-relation">+{node.findings.length - 6} more in Findings</div>}
      </div>
      <div className="inline-node-section">
        <div className="inline-node-section-title">Attack relationships</div>
        {relations.length ? relations.slice(0, 8).map((e) => {
          const out = e.source === node.id;
          return (
            <div className="inline-node-relation" key={e.id}>
              <strong>{out ? "→" : "←"} {nameOf(out ? e.target : e.source)}</strong> · {e.relation} ·{" "}
              <span style={{ color: severityColor(e.risk) }}>{e.risk}</span>
            </div>
          );
        }) : <div className="inline-node-relation">No relationships recorded.</div>}
      </div>
    </>
  );
}

function EdgeDetails({ edge, nameOf }) {
  const color = severityColor(edge.risk);
  return (
    <>
      <div className="inline-node-type">Relationship</div>
      <div className="inline-node-name">{edge.relation}</div>
      <div className="inline-node-relation" style={{ marginTop: 8 }}>{nameOf(edge.source)} → {nameOf(edge.target)}</div>
      <div className="inline-node-relation">Severity: <span style={{ color }}>{edge.risk}</span> · attack cost {edge.weight}</div>
    </>
  );
}

export default GraphPane;
