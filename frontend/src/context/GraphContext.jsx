import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { normalizeGraph } from "../lib/graph.js";
import { api } from "../lib/api.js";

const GraphContext = createContext(null);
export const useGraph = () => useContext(GraphContext);

const EMPTY_HIGHLIGHT = { nodeIds: [], edgeIds: [] };

export function GraphProvider({ children }) {
  const [graph, setGraph] = useState(null);
  // meta.source: "sample" | "file" | "api"; snapshotId is set only for "api"
  const [meta, setMeta] = useState({ source: null, snapshotId: null, label: "" });
  const [status, setStatus] = useState("no graph");
  const [error, setError] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [highlight, setHighlight] = useState(EMPTY_HIGHLIGHT);

  const loadGraph = useCallback((raw, nextMeta) => {
    const normalized = normalizeGraph(raw);
    setGraph(normalized);
    setMeta(nextMeta);
    setSelectedNodeId(null);
    setHighlight(EMPTY_HIGHLIGHT);
    setError("");
    setStatus(`${normalized.nodes.length} nodes · ${normalized.edges.length} edges · ${nextMeta.label}`);
    return normalized;
  }, []);

  const fail = useCallback((message) => {
    setError(message);
    setStatus(`Failed — ${message}`);
  }, []);

  const loadSample = useCallback(async () => {
    try {
      setStatus("Loading sample graph…");
      const res = await fetch("/sample-graph.json", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      loadGraph(await res.json(), { source: "sample", snapshotId: null, label: "sample graph" });
    } catch (e) {
      fail(e.message);
    }
  }, [loadGraph, fail]);

  const loadFile = useCallback(
    (file) => {
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        try {
          loadGraph(JSON.parse(ev.target.result), { source: "file", snapshotId: null, label: file.name });
        } catch (e) {
          fail(`Invalid graph JSON — ${e.message}`);
        }
      };
      reader.onerror = () => fail("Failed to read selected file.");
      reader.readAsText(file);
    },
    [loadGraph, fail],
  );

  const loadSnapshot = useCallback(
    async (snapshotId, label) => {
      try {
        setStatus("Loading snapshot…");
        const snap = await api.getSnapshot(snapshotId);
        loadGraph(snap.graph, { source: "api", snapshotId, label: label || `snapshot ${snapshotId.slice(-6)}` });
        return true;
      } catch (e) {
        fail(e.message);
        return false;
      }
    },
    [loadGraph, fail],
  );

  const reload = useCallback(() => {
    if (meta.source === "api" && meta.snapshotId) return loadSnapshot(meta.snapshotId, meta.label);
    return loadSample();
  }, [meta, loadSnapshot, loadSample]);

  const clearGraph = useCallback(() => {
    setGraph(null);
    setMeta({ source: null, snapshotId: null, label: "" });
    setStatus("no graph");
    setSelectedNodeId(null);
    setHighlight(EMPTY_HIGHLIGHT);
  }, []);

  const value = useMemo(
    () => ({
      graph, meta, status, error,
      selectedNodeId, setSelectedNodeId,
      highlight, setHighlight, clearHighlight: () => setHighlight(EMPTY_HIGHLIGHT),
      loadSample, loadFile, loadSnapshot, reload, clearGraph,
    }),
    [graph, meta, status, error, selectedNodeId, highlight, loadSample, loadFile, loadSnapshot, reload, clearGraph],
  );

  return <GraphContext.Provider value={value}>{children}</GraphContext.Provider>;
}
