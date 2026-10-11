import { useGraph } from "../context/GraphContext.jsx";

export default function TopBar({ user, offline, pane, view, setView, graphRef, onLogout }) {
  const { status, reload, loadFile } = useGraph();
  const set = (patch) => setView((v) => ({ ...v, ...patch }));
  const showGraphControls = pane === "graph";

  return (
    <div id="top">
      <h1>⚡ K8s Security Analyzer</h1>
      <span className="tag" id="stats">{status}</span>
      <div id="controls">
        {showGraphControls && (
          <>
            <label className="toggle">
              <input type="checkbox" checked={view.showSystem} onChange={(e) => set({ showSystem: e.target.checked })} /> system
            </label>
            <label className="toggle">
              <input type="checkbox" checked={view.showTopology} onChange={(e) => set({ showTopology: e.target.checked })} /> topology
            </label>
            <select value={view.layout} onChange={(e) => set({ layout: e.target.value })}>
              <option value="dagre">Path (dagre)</option>
              <option value="cose">Cluster (cose)</option>
            </select>
            <input
              type="file"
              accept=".json"
              style={{ maxWidth: 140 }}
              onChange={(e) => { loadFile(e.target.files?.[0]); e.target.value = ""; }}
            />
            <button onClick={reload}>↻ Reload</button>
            <button onClick={() => graphRef.current?.relayout()}>⊞ Layout</button>
            <button onClick={() => graphRef.current?.zoomOut()} aria-label="Zoom out">− Zoom out</button>
            <button onClick={() => graphRef.current?.zoomIn()} aria-label="Zoom in">＋ Zoom in</button>
            <button onClick={() => graphRef.current?.fit()}>⊡ Fit</button>
          </>
        )}
        {user ? (
          <button onClick={onLogout} title={user.email}>⎋ Sign out</button>
        ) : (
          offline && <button onClick={onLogout}>⎋ Exit demo</button>
        )}
      </div>
    </div>
  );
}
