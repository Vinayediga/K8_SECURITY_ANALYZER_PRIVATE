import { useEffect, useMemo, useRef, useState } from "react";
import { useGraph } from "../context/GraphContext.jsx";
import { api } from "../lib/api.js";
import * as local from "../lib/analysis.js";
import { severityColor } from "../lib/graph.js";

const TABS = [["blast", "💥 Blast Radius"], ["path", "🛣️ Shortest Path"], ["cycles", "🔄 Cycles"], ["critical", "🎯 Critical Node"]];
const RANK = { critical: 4, high: 3, medium: 2, info: 1 };

function MicroNode({ node, onOpen }) {
  if (!node) return null;
  const sev = node.findings.reduce((best, f) => {
    const v = String(f.severity || "info").toLowerCase();
    return (RANK[v] || 0) > (RANK[best] || 0) ? v : best;
  }, "info");
  const color = severityColor(sev);
  return (
    <div className="micro-node" onClick={() => onOpen(node.id)}>
      <div className="micro-node-risk" style={{ color, background: `${color}18` }}>{sev}</div>
      <div className="micro-node-type">{node.type}</div>
      <div className="micro-node-name">{node.label}</div>
      <div className="micro-node-ns">{node.namespace || "cluster-wide"}</div>
    </div>
  );
}

function MicroLink({ edge }) {
  if (!edge) return <div className="micro-link"><div className="micro-link-line" /></div>;
  const color = severityColor(edge.risk);
  return (
    <div className="micro-link">
      <div className="micro-link-line" style={{ background: color }} />
      <div className="micro-link-label">{edge.relation}</div>
      <div className="micro-link-risk" style={{ color }}>{edge.risk}</div>
    </div>
  );
}

function MicroView({ micro, graph, onOpen }) {
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  if (!micro) return <div className="micro-empty"><strong>Run an algorithm</strong><span>The relevant resources and relationships will appear here.</span></div>;
  if (!micro.nodeIds.length) return <div className="micro-empty"><strong>No result</strong><span>No resources were returned by this analysis.</span></div>;
  const N = (id) => <MicroNode key={id} node={byId.get(id)} onOpen={onOpen} />;

  if (micro.kind === "critical") {
    const id = micro.nodeIds[0];
    const edges = graph.edges.filter((e) => e.source === id || e.target === id).slice(0, 8);
    return (
      <div className="micro-critical">
        <div>{N(id)}</div>
        <div className="micro-critical-impact">
          <div className="micro-critical-impact-label">Direct attack relationships</div>
          <div className="micro-critical-impact-value">{edges.length}</div>
          <div className="micro-critical-impact-note">Immediate relationships around the highest-impact resource.</div>
        </div>
        <div className="micro-neighbors">
          {edges.map((e) => {
            const other = e.source === id ? e.target : e.source;
            return (
              <div className="micro-neighbor" key={e.id}>
                <span className="micro-neighbor-dot" style={{ background: severityColor(e.risk) }} />
                <span className="micro-neighbor-name">{byId.get(other)?.label || other}</span>
                <span className="micro-neighbor-relation">{e.relation} · {e.risk}</span>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  if (micro.kind === "blast") {
    const [source, ...rest] = micro.nodeIds;
    return (
      <div className="micro-exposure">
        <div className="micro-exposure-source">{N(source)}</div>
        <div className="micro-exposure-arrow">↓ reachable resources{rest.length > 12 ? ` (showing 12 of ${rest.length})` : ""}</div>
        <div className="micro-exposure-grid">{rest.slice(0, 12).map(N)}</div>
      </div>
    );
  }

  const closed = micro.kind === "cycle";
  const items = [];
  micro.nodeIds.forEach((id, i) => {
    items.push(N(id));
    const next = micro.nodeIds[i + 1] ?? (closed ? micro.nodeIds[0] : null);
    if (next) items.push(<MicroLink key={`l${i}`} edge={local.edgeBetween(graph, id, next)} />);
  });
  return closed ? (
    <div className="micro-cycle"><div className="micro-cycle-loop">{items}</div>
      <div className="micro-cycle-caption">↻ The relationship chain returns to its starting resource.</div></div>
  ) : <div className="micro-chain">{items}</div>;
}

export default function PathsPane({ goToGraph }) {
  const { graph, meta, setHighlight, clearHighlight, setSelectedNodeId } = useGraph();
  const [tab, setTab] = useState("blast");
  const [blastSource, setBlastSource] = useState("");
  const [hops, setHops] = useState(2);
  const [pathSource, setPathSource] = useState("");
  const [pathTarget, setPathTarget] = useState("");
  const [micro, setMicro] = useState(null);
  const [badge, setBadge] = useState("");
  const [result, setResult] = useState({ title: "Ready for analysis", text: "Select an algorithm above. The result will be shown at resource level.", path: "" });
  const [busy, setBusy] = useState(false);
  const analysisCache = useRef({ id: null, data: null });

  const nodes = useMemo(() => [...(graph?.nodes || [])].sort((a, b) => a.label.localeCompare(b.label)), [graph]);
  const label = (id) => graph?.nodes.find((n) => n.id === id)?.label || id;

  // Sensible defaults: sources start the attack, sinks are the targets.
  useEffect(() => {
    if (!graph) return;
    const firstSource = graph.nodes.find((n) => n.isSource)?.id ?? graph.nodes[0]?.id ?? "";
    const firstSink = graph.nodes.find((n) => n.isSink)?.id ?? graph.nodes[1]?.id ?? "";
    setBlastSource((v) => (graph.nodes.some((n) => n.id === v) ? v : firstSource));
    setPathSource((v) => (graph.nodes.some((n) => n.id === v) ? v : firstSource));
    setPathTarget((v) => (graph.nodes.some((n) => n.id === v) ? v : firstSink));
    analysisCache.current = { id: null, data: null };
  }, [graph]);

  const reset = () => {
    setMicro(null);
    setBadge("");
    clearHighlight();
    setResult({ title: "Ready for analysis", text: "Select an algorithm above. The result will be shown at resource level.", path: "" });
  };
  const switchTab = (t) => { setTab(t); reset(); };

  // Use the backend when a snapshot is loaded from it; fall back to the
  // in-browser implementation (same result shape) if the call fails.
  const compute = async (remote, localFn) => {
    if (meta.snapshotId) {
      try {
        return { data: await remote(meta.snapshotId), note: "" };
      } catch (err) {
        return { data: localFn(), note: ` (computed in browser — backend said: ${err.message})` };
      }
    }
    return { data: localFn(), note: "" };
  };
  const remoteAnalysis = async (id) => {
    if (analysisCache.current.id !== id) analysisCache.current = { id, data: await api.analysis(id) };
    return analysisCache.current.data;
  };

  const show = (kind, nodeIds, edgeIds, badgeText, title, text, path = "") => {
    setMicro({ kind, nodeIds });
    setBadge(badgeText);
    setHighlight({ nodeIds, edgeIds });
    setResult({ title, text, path });
  };

  const run = async (fn) => {
    if (!graph) return setResult({ title: "No graph loaded", text: "Load a graph first.", path: "" });
    setBusy(true);
    try {
      await fn();
    } catch (err) {
      setMicro(null);
      setBadge("");
      clearHighlight();
      setResult({ title: "Analysis failed", text: err.message, path: "" });
    } finally {
      setBusy(false);
    }
  };

  const runBlast = () => run(async () => {
    const { data: layers, note } = await compute(
      (id) => api.blastRadius(id, blastSource, hops),
      () => local.blastRadius(graph, blastSource, hops),
    );
    const reached = Object.values(layers).flat();
    const ids = [blastSource, ...reached];
    const perHop = Object.entries(layers).filter(([, v]) => v.length).map(([h, v]) => `Hop ${h}: ${v.map(label).join(", ")}`).join("  |  ");
    show("blast", ids, local.edgeIdsAmong(graph, ids), `Blast radius: ${reached.length} reachable`,
      "Blast Radius", `${reached.length} resource${reached.length === 1 ? "" : "s"} reachable within ${hops} hop${hops === 1 ? "" : "s"} of ${label(blastSource)}.${note}`, perHop);
    setResult((current) => ({ ...current, kind: "blast-radius", count: reached.length, hops, source: label(blastSource), detail: perHop }));
  });

  const runPath = () => run(async () => {
    if (pathSource === pathTarget) throw new Error("Select two different resources.");
    const { data, note } = await compute(
      (id) => api.shortestPath(id, pathSource, pathTarget),
      () => local.shortestPath(graph, pathSource, pathTarget),
    );
    if (!data.path.length) {
      setMicro({ kind: "path", nodeIds: [] });
      setBadge("No path found");
      clearHighlight();
        return setResult({ title: "Shortest Attack Path", text: `No directed path from ${label(pathSource)} to ${label(pathTarget)}.${note}`, path: "" });
    }
    show("path", data.path, local.chainEdgeIds(graph, data.path), `Shortest path: ${data.hops} hop${data.hops === 1 ? "" : "s"}`,
      "Shortest Attack Path", `Total attack cost ${Number(data.risk_score).toFixed(2)} over ${data.hops} hop${data.hops === 1 ? "" : "s"}. Lower cost = easier for an attacker.${note}`,
      data.path.map(label).join(" → "));
    setResult((current) => ({
      ...current,
      kind: "shortest-path",
      hops: data.hops,
      cost: Number(data.risk_score).toFixed(2),
      pathNodes: data.path.map(label),
    }));
  });

  const runCycles = () => run(async () => {
    const { data: cycles, note } = await compute(async (id) => (await remoteAnalysis(id)).cycles, () => local.findCycles(graph));
    if (!cycles.length) {
      setMicro({ kind: "cycle", nodeIds: [] });
      setBadge("No directed cycles");
      clearHighlight();
      return setResult({ title: "Privilege Cycles", text: `No directed cycles detected.${note}`, path: "" });
    }
    const first = cycles[0];
    show("cycle", first, local.chainEdgeIds(graph, first, true), `Privilege cycles: ${cycles.length} detected`,
      "Privilege Cycles", `${cycles.length} directed cycle${cycles.length === 1 ? "" : "s"} detected. Showing the first.${note}`,
      [...first, first[0]].map(label).join(" → "));
    setResult((current) => ({ ...current, kind: "privilege-cycles", count: cycles.length, pathNodes: [...first, first[0]].map(label) }));
  });

  const runCritical = () => run(async () => {
    const { data, note } = await compute(async (id) => (await remoteAnalysis(id)).critical_nodes, () => local.criticalNode(graph));
    if (!data.critical_node) throw new Error("No critical node could be determined.");
    const top = data.ranking.slice(0, 5).map((r) => `${label(r.node)} (${r.paths_removed})`).join(", ");
    show("critical", [data.critical_node], [], `Critical resource: ${label(data.critical_node)}`,
      "Critical Resource", `${label(data.critical_node)} removes ${data.paths_removed} of ${data.baseline_path_count} source→sink attack paths.${note}`,
      `Top candidates (paths removed): ${top}`);
    setResult((current) => ({
      ...current,
      kind: "critical-resource",
      resource: label(data.critical_node),
      pathsRemoved: data.paths_removed,
      baselinePaths: data.baseline_path_count,
      candidates: data.ranking.slice(0, 5).map((r) => `${label(r.node)} (${r.paths_removed})`),
    }));
  });

  const openNode = (id) => { setSelectedNodeId(id); goToGraph?.(); };
  const select = (value, setter, id) => (
    <select id={id} value={value} onChange={(e) => setter(e.target.value)}>
      {nodes.map((n) => <option key={n.id} value={n.id}>{n.label} · {n.id}</option>)}
    </select>
  );

  return (
    <section className="app-pane analysis-pane">
      <div className="pane-header">
        <div>
          <div className="pane-title">Attack Path Analysis</div>
          {graph && <div style={{ color: "var(--text-dim)", fontSize: 9, marginTop: 4 }}>
            {graph.nodes.length} nodes · {graph.edges.length} edges · {graph.nodes.filter((n) => n.isSource).length} sources · {graph.nodes.filter((n) => n.isSink).length} sinks
            {meta.snapshotId ? " · analysis runs on the backend" : " · analysis runs in the browser"}
          </div>}
          <div className="pane-subtitle">Analyze only the resources and relationships involved in the selected algorithm.</div>
        </div>
      </div>

      <div className="attack-analysis-tools">
        {TABS.map(([key, text]) => (
          <button key={key} className={`attack-analysis-tab ${tab === key ? "active" : ""}`} onClick={() => switchTab(key)}>{text}</button>
        ))}
        <button className="attack-analysis-reset" onClick={reset}>↺ Reset</button>
      </div>

      {tab === "blast" && (
        <div className="attack-analysis-inputs">
          <label>Source</label>{select(blastSource, setBlastSource)}
          <label>Hops</label>
          <input type="number" min={0} max={50} value={hops} onChange={(e) => setHops(Number(e.target.value))} />
          <button className="attack-analysis-run" disabled={busy} onClick={runBlast}>Run Blast Radius</button>
        </div>
      )}
      {tab === "path" && (
        <div className="attack-analysis-inputs">
          <label>From</label>{select(pathSource, setPathSource)}
          <label>To</label>{select(pathTarget, setPathTarget)}
          <button className="attack-analysis-run" disabled={busy} onClick={runPath}>Find Shortest Path</button>
        </div>
      )}
      {tab === "cycles" && (
        <div className="attack-analysis-inputs">
          <span className="attack-analysis-note">Detect directed privilege cycles in the current graph.</span>
          <button className="attack-analysis-run" disabled={busy} onClick={runCycles}>Find Cycles</button>
        </div>
      )}
      {tab === "critical" && (
        <div className="attack-analysis-inputs">
          <span className="attack-analysis-note">Identify the resource with the highest attack-path impact.</span>
          <button className="attack-analysis-run" disabled={busy} onClick={runCritical}>Find Critical Node</button>
        </div>
      )}

      <div className="micro-attack-card">
        <div className="micro-attack-header">
          <div>
            <div className="micro-attack-title">Micro Attack Path</div>
            <div className="micro-attack-subtitle">Only the resources involved in the analysis are shown. Click one to open it in the graph.</div>
          </div>
          {badge && <div className="micro-attack-badge">{badge}</div>}
        </div>
        <div className="micro-attack-view">
          {graph ? <MicroView micro={micro} graph={graph} onOpen={openNode} />
            : <div className="micro-empty"><strong>No graph loaded</strong><span>Load a graph first.</span></div>}
        </div>
      </div>

      <div className="attack-analysis-result">
        {result.kind === "shortest-path" ? (
          <div className="shortest-path-result">
            <div className="shortest-path-header">
              <div className="attack-result-title">{busy ? "Running…" : result.title}</div>
              <span className="shortest-path-hops">{result.hops} hop{result.hops === 1 ? "" : "s"}</span>
            </div>
            <div className="shortest-path-metrics">
              <div className="shortest-path-cost">
                <span>ATTACK COST</span>
                <strong>{result.cost}</strong>
              </div>
              <p>Lower cost means easier attacker movement.</p>
            </div>
            <div className="shortest-path-label">PATH</div>
            <div className="shortest-path-nodes">
              {result.pathNodes.map((node, index) => (
                <span className="shortest-path-node-group" key={`${node}-${index}`}>
                  {index > 0 && <span className="shortest-path-arrow" aria-hidden="true">→</span>}
                  <span className="shortest-path-node">{node}</span>
                </span>
              ))}
            </div>
          </div>
        ) : result.kind === "blast-radius" ? (
          <div className="analysis-summary-result">
            <div className="analysis-summary-header">
              <div className="attack-result-title">{busy ? "Running…" : "Blast Radius"}</div>
              <span className="analysis-summary-badge">{result.hops} hop{result.hops === 1 ? "" : "s"}</span>
            </div>
            <div className="analysis-summary-metrics">
              <div><span>REACHABLE RESOURCES</span><strong>{result.count}</strong></div>
              <p>Resources reachable from <b>{result.source}</b> within the selected hop limit.</p>
            </div>
            {result.detail && <><div className="analysis-summary-label">REACHABILITY BY HOP</div><div className="analysis-summary-detail">{result.detail}</div></>}
          </div>
        ) : result.kind === "privilege-cycles" ? (
          <div className="analysis-summary-result">
            <div className="analysis-summary-header">
              <div className="attack-result-title">{busy ? "Running…" : "Privilege Cycles"}</div>
              <span className="analysis-summary-badge">{result.count} detected</span>
            </div>
            <div className="analysis-summary-metrics">
              <div><span>DIRECTED CYCLES</span><strong>{result.count}</strong></div>
              <p>Showing the first detected privilege cycle in the visualization above.</p>
            </div>
            <div className="analysis-summary-label">CYCLE</div>
            <div className="shortest-path-nodes">{result.pathNodes.map((node, index) => <span className="shortest-path-node-group" key={`${node}-${index}`}>{index > 0 && <span className="shortest-path-arrow" aria-hidden="true">→</span>}<span className="shortest-path-node">{node}</span></span>)}</div>
          </div>
        ) : result.kind === "critical-resource" ? (
          <div className="analysis-summary-result">
            <div className="analysis-summary-header">
              <div className="attack-result-title">{busy ? "Running…" : "Critical Resource"}</div>
              <span className="analysis-summary-badge">highest impact</span>
            </div>
            <div className="analysis-summary-metrics">
              <div><span>ATTACK PATHS REMOVED</span><strong>{result.pathsRemoved}</strong></div>
              <p><b>{result.resource}</b> removes {result.pathsRemoved} of {result.baselinePaths} source-to-sink attack paths.</p>
            </div>
            <div className="analysis-summary-label">TOP CANDIDATES · PATHS REMOVED</div>
            <div className="analysis-summary-detail">{result.candidates.join(" · ")}</div>
          </div>
        ) : (
          <>
            <div className="attack-result-title">{busy ? "Running…" : result.title}</div>
            <div className="attack-result-text">{result.text}</div>
            {result.path && <div className="attack-result-path">{result.path}</div>}
          </>
        )}
      </div>
    </section>
  );
}
