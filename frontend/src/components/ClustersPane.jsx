import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api.js";
import { useGraph } from "../context/GraphContext.jsx";

const card = "rounded-xl border p-5";
const cardStyle = { background: "var(--surface)", borderColor: "var(--border)" };
const inputCls = "rounded-lg border px-3 py-2 text-sm outline-none";
const inputStyle = { background: "#0a0d11", borderColor: "var(--border)", color: "var(--text)" };
const btn = "cluster-btn rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors disabled:opacity-50";
const STATUS_COLOR = { queued: "#c9962c", running: "#5fa8e6", completed: "#7bd88f", failed: "#e8836b" };

export default function ClustersPane({ onLoaded }) {
  const { loadSnapshot, meta } = useGraph();
  const [clusters, setClusters] = useState([]);
  const [scans, setScans] = useState([]);
  const [snapshots, setSnapshots] = useState({});
  const [name, setName] = useState("");
  const [context, setContext] = useState("");
  const [editingCluster, setEditingCluster] = useState(null);
  const [agent, setAgent] = useState(null);
  const [msg, setMsg] = useState({ text: "", error: false });
  const [busy, setBusy] = useState("");
  const watching = useRef(new Map()); // scanId -> clusterId, loaded automatically on completion
  const toastTimer = useRef(null);

  const say = useCallback((text, error = false) => {
    setMsg({ text, error });
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setMsg({ text: "", error: false }), error ? 7000 : 4500);
  }, []);

  useEffect(() => () => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [c, s] = await Promise.all([api.listClusters(), api.listScans()]);
      setClusters(c);
      setScans(s);
      return s;
    } catch (e) {
      say(e.message, true);
      return [];
    }
  }, []);

  const loadSnapshots = useCallback(async (clusterId) => {
    try {
      const list = await api.listSnapshots(clusterId);
      setSnapshots((prev) => ({ ...prev, [clusterId]: list }));
      return list;
    } catch (e) {
      say(e.message, true);
      return [];
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Poll while any scan is still in flight.
  const active = scans.some((s) => s.status === "queued" || s.status === "running");
  useEffect(() => {
    if (!active) return undefined;
    const t = setInterval(async () => {
      const list = await refresh();
      for (const [scanId, clusterId] of [...watching.current]) {
        const scan = list.find((s) => s.id === scanId);
        if (scan?.status === "failed") {
          watching.current.delete(scanId);
          say(`Scan failed: ${scan.error || "unknown error"}`, true);
        } else if (scan?.status === "completed") {
          watching.current.delete(scanId);
          const snaps = await loadSnapshots(clusterId);
          const snap = snaps.find((x) => x.scan_id === scanId);
          if (snap && (await loadSnapshot(snap.id, "latest scan"))) onLoaded?.();
        }
      }
    }, 4000);
    return () => clearInterval(t);
  }, [active, refresh, loadSnapshots, loadSnapshot, onLoaded]);

  const addCluster = async (e) => {
    e.preventDefault();
    setBusy("cluster");
    try {
      await api.createCluster(name.trim(), context.trim());
      setName(""); setContext("");
      say("Cluster registered.");
      await refresh();
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const saveCluster = async (e) => {
    e.preventDefault();
    if (!editingCluster) return;
    setBusy(`edit-${editingCluster.id}`);
    try {
      const updated = await api.updateCluster(editingCluster.id, editingCluster.name.trim(), editingCluster.context_name.trim());
      setClusters((prev) => prev.map((cluster) => cluster.id === updated.id ? updated : cluster));
      setEditingCluster(null);
      say("Cluster updated.");
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const removeCluster = async (cluster) => {
    if (!window.confirm(`Delete "${cluster.name}" and all of its scans and snapshots?`)) return;
    setBusy(`delete-${cluster.id}`);
    try {
      await api.deleteCluster(cluster.id);
      setClusters((prev) => prev.filter((item) => item.id !== cluster.id));
      setScans((prev) => prev.filter((scan) => scan.cluster_id !== cluster.id));
      setSnapshots((prev) => { const next = { ...prev }; delete next[cluster.id]; return next; });
      say("Cluster and related scan data deleted.");
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const removeScan = async (scan) => {
    if (!window.confirm("Delete this scan and its snapshot?")) return;
    setBusy(`delete-scan-${scan.id}`);
    try {
      await api.deleteScan(scan.id);
      setScans((prev) => prev.filter((item) => item.id !== scan.id));
      setSnapshots((prev) => Object.fromEntries(Object.entries(prev).map(([id, list]) => [id, list.filter((snapshot) => snapshot.scan_id !== scan.id)])));
      say("Scan deleted.");
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const startScan = async (cluster) => {
    setBusy(`scan-${cluster.id}`);
    try {
      const scan = await api.createScan(cluster.id);
      watching.current.set(scan.id, cluster.id);
      say("Scan queued. The agent for this cluster will pick it up; the graph loads automatically when it finishes.");
      await refresh();
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const makeAgent = async (cluster) => {
    setBusy(`agent-${cluster.id}`);
    try {
      setAgent({ ...(await api.registerAgent(cluster.id)), clusterName: cluster.name });
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const rotateAgent = async () => {
    if (!agent || !window.confirm("Rotate this token? The current token will stop working immediately.")) return;
    setBusy(`rotate-agent-${agent.agent_id}`);
    try {
      setAgent({ ...await api.rotateAgentToken(agent.agent_id), clusterName: agent.clusterName });
    } catch (err) { say(err.message, true); } finally { setBusy(""); }
  };

  const open = async (snap) => {
    if (await loadSnapshot(snap.id, `snapshot ${new Date(snap.created_at).toLocaleString()}`)) onLoaded?.();
  };

  const clusterName = (id) => clusters.find((c) => c.id === id)?.name || id.slice(-6);

  return (
    <section className="app-pane">
      <div className="pane-header">
        <div>
          <div className="pane-title">Clusters & Scans</div>
          <div className="pane-subtitle">Register a cluster, run a scan through its local agent, then open the resulting graph snapshot.</div>
        </div>
      </div>

      {msg.text && (
        <div className={`cluster-toast${msg.error ? " cluster-toast-error" : ""}`} role={msg.error ? "alert" : "status"}>
          <span>{msg.text}</span>
          <button type="button" aria-label="Dismiss notification" onClick={() => setMsg({ text: "", error: false })}>×</button>
        </div>
      )}

      <div className="cluster-metrics">
        <div className="cluster-metric"><span>REGISTERED CLUSTERS</span><strong>{clusters.length}</strong><small>Connected contexts</small></div>
        <div className="cluster-metric"><span>TOTAL SCANS</span><strong>{scans.length}</strong><small>Scan jobs created</small></div>
        <div className="cluster-metric"><span>ACTIVE SCANS</span><strong>{scans.filter((s) => s.status === "queued" || s.status === "running").length}</strong><small>Currently processing</small></div>
        <div className="cluster-metric"><span>COMPLETED</span><strong>{scans.filter((s) => s.status === "completed").length}</strong><small>Available snapshots</small></div>
      </div>

      {agent && (
        <div className="agent-modal-backdrop" role="presentation">
          <div className="agent-modal" role="dialog" aria-modal="true" aria-labelledby="agent-token-title">
            <div className="agent-modal-icon">!</div>
            <div className="auth-form-kicker">AGENT CREDENTIALS</div>
            <h2 id="agent-token-title" className="mt-2 text-xl font-bold">Save these details now</h2>
            <p className="mt-2 text-sm leading-6" style={{ color: "var(--text-dim)" }}>
              This token is shown only once. You cannot access it again after closing this window. Store it securely on the machine that can reach the cluster.
            </p>
            <pre className="agent-config mt-5 overflow-x-auto rounded-lg p-4 text-xs" style={{ background: "#0a0d11" }}>{`API_URL=http://127.0.0.1:8000
AGENT_TOKEN=${agent.agent_token}
AGENT_CLUSTER_ID=${agent.cluster_id}
KUBE_CONTEXT=${agent.context_name}`}</pre>
            <div className="mt-7 flex flex-wrap justify-end gap-3">
              <button className={btn} style={{ background: "var(--surface2)", color: "var(--text)" }} onClick={() => setAgent(null)}>I've saved the details</button>
              <button className={btn} style={{ background: "var(--accent)", color: "#0a0d11" }} disabled={busy === `rotate-agent-${agent.agent_id}`} onClick={rotateAgent}>
                {busy === `rotate-agent-${agent.agent_id}` ? "Generating…" : "Generate new token"}
              </button>
            </div>
          </div>
        </div>
      )}

      {editingCluster && (
        <div className="agent-modal-backdrop" role="presentation">
          <form className="agent-modal cluster-edit-modal" role="dialog" aria-modal="true" aria-labelledby="edit-cluster-title" onSubmit={saveCluster}>
            <div className="auth-form-kicker">CLUSTER SETTINGS</div>
            <h2 id="edit-cluster-title" className="mt-2 text-xl font-bold">Edit cluster</h2>
            <div className="cluster-edit-fields">
              <label className="text-sm font-medium" style={{ color: "var(--text-dim)" }}>Cluster name
                <input className={inputCls} style={inputStyle} required maxLength={100} value={editingCluster.name} onChange={(e) => setEditingCluster({ ...editingCluster, name: e.target.value })} />
              </label>
              <label className="text-sm font-medium" style={{ color: "var(--text-dim)" }}>kubectl context
                <input className={inputCls} style={inputStyle} required maxLength={200} value={editingCluster.context_name} onChange={(e) => setEditingCluster({ ...editingCluster, context_name: e.target.value })} />
              </label>
            </div>
            <div className="mt-7 flex flex-wrap justify-end gap-3">
              <button type="button" className={btn} style={{ background: "var(--surface2)", color: "var(--text)" }} onClick={() => setEditingCluster(null)}>Cancel</button>
              <button type="submit" className={btn} style={{ background: "var(--accent)", color: "#0a0d11" }} disabled={busy === `edit-${editingCluster.id}`}>{busy === `edit-${editingCluster.id}` ? "Saving…" : "Save changes"}</button>
            </div>
          </form>
        </div>
      )}

      <form onSubmit={addCluster} className={`${card} cluster-create-card`} style={cardStyle}>
        <div>
          <div className="section-kicker">NEW CONNECTION</div>
          <h2 className="mt-1 text-lg font-bold">Register a cluster</h2>
          <p className="mt-1 text-sm" style={{ color: "var(--text-dim)" }}>Connect a local Kubernetes context to begin scanning.</p>
        </div>
        <div className="cluster-form-fields">
          <label className="text-sm font-medium" style={{ color: "var(--text-dim)" }}>Cluster name
            <input className={inputCls} style={inputStyle} required maxLength={100} placeholder="Production lab" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="text-sm font-medium" style={{ color: "var(--text-dim)" }}>kubectl context
            <input className={inputCls} style={inputStyle} required maxLength={200} placeholder="kind-k8s-security-lab" value={context} onChange={(e) => setContext(e.target.value)} />
          </label>
          <button className={btn} style={{ background: "var(--accent)", color: "#0a0d11" }} disabled={busy === "cluster"}>{busy === "cluster" ? "Registering…" : "Register cluster"}</button>
        </div>
      </form>

      <div className="cluster-list grid gap-5">
        {!clusters.length && <div className="placeholder-panel"><div><strong>No clusters yet</strong><span>Register one above to start scanning.</span></div></div>}
        {clusters.map((c) => (
          <div key={c.id} className={`${card} cluster-card`} style={cardStyle}>
            <div className="flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="section-kicker">CONNECTED CLUSTER</div>
                <div className="mt-1 text-lg font-bold">{c.name}</div>
                <div className="mt-1 text-sm" style={{ color: "var(--text-dim)" }}>context <code>{c.context_name}</code></div>
              </div>
              <div className="cluster-actions">
                <button className={`${btn} cluster-btn-primary`} disabled={busy === `scan-${c.id}`} onClick={() => startScan(c)}><span className="cluster-btn-icon" aria-hidden="true">▶</span><span>{busy === `scan-${c.id}` ? "Starting…" : "Run scan"}</span></button>
                <button className={`${btn} cluster-btn-secondary`} disabled={busy === `agent-${c.id}`} onClick={() => makeAgent(c)}>{busy === `agent-${c.id}` ? "Registering…" : "Register agent"}</button>
                <button className={`${btn} cluster-btn-secondary`} onClick={() => loadSnapshots(c.id)}>View snapshots</button>
                <button className={`${btn} cluster-btn-secondary`} onClick={() => setEditingCluster({ id: c.id, name: c.name, context_name: c.context_name })}>Edit cluster</button>
                <button className={`${btn} cluster-btn-danger`} disabled={busy === `delete-${c.id}`} onClick={() => removeCluster(c)}>Delete cluster</button>
              </div>
            </div>
            {snapshots[c.id] && (
              <div className="snapshot-list mt-3 grid gap-2">
                {!snapshots[c.id].length && <div className="text-xs" style={{ color: "var(--text-dim)" }}>No snapshots yet — run a scan.</div>}
                {snapshots[c.id].map((s) => (
                  <div key={s.id} className="snapshot-row flex items-center gap-3 rounded-lg p-3 text-sm" style={{ background: "#0d1218", border: "1px solid var(--border)" }}>
                    <span className="snapshot-meta flex-1">{new Date(s.created_at).toLocaleString()} · {s.node_count} nodes · {s.edge_count} edges</span>
                    <span className="snapshot-loaded" style={{ color: "#7bd88f", visibility: meta.snapshotId === s.id ? "visible" : "hidden" }} aria-hidden={meta.snapshotId !== s.id}>loaded</span>
                    <button className="snapshot-open-btn" onClick={() => open(s)}>Open</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className={`${card} recent-scans-card`} style={cardStyle}>
        <div className="recent-scans-header">
          <div>
            <div className="section-kicker">ACTIVITY</div>
            <div className="mt-1 text-lg font-bold">Recent scans</div>
          </div>
          {active && <span className="scan-live">● Updating</span>}
        </div>
        {!scans.length ? <div className="text-xs" style={{ color: "var(--text-dim)" }}>No scans yet.</div> : (
          <div className="recent-scan-list">
            {scans.slice(0, 8).map((s) => (
              <div key={s.id} className="recent-scan-row">
                <div className="scan-time">{new Date(s.created_at).toLocaleString()}</div>
                <div className="scan-cluster">{clusterName(s.cluster_id)}</div>
                <span className={`scan-status scan-status-${s.status}`} style={{ color: STATUS_COLOR[s.status] }}>{s.status}</span>
                <button className="scan-delete-btn" disabled={busy === `delete-scan-${s.id}`} onClick={() => removeScan(s)}>Delete</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
