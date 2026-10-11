/**
 * Local (in-browser) versions of the four analyses. They return exactly the
 * same shapes as the backend GraphEngine / API endpoints so the UI can use
 * either one interchangeably:
 *
 *   blastRadius   -> { "1": [ids], "2": [ids], ... }
 *   shortestPath  -> { path: [ids], hops, risk_score, message? }
 *   findCycles    -> [[ids], ...]
 *   criticalNode  -> { critical_node, paths_removed, baseline_path_count, ranking }
 */

function buildAdjacency(graph) {
  const adj = new Map(graph.nodes.map((n) => [n.id, []]));
  graph.edges.forEach((e) => adj.get(e.source)?.push({ to: e.target, edge: e }));
  return adj;
}

export function blastRadius(graph, source, hops) {
  const adj = buildAdjacency(graph);
  if (!adj.has(source)) throw new Error(`Unknown source node: ${source}`);
  if (!Number.isInteger(hops) || hops < 0) throw new Error("hops must be an integer >= 0");

  const layers = {};
  for (let h = 1; h <= hops; h++) layers[String(h)] = [];
  const visited = new Set([source]);
  let frontier = [source];

  for (let depth = 1; depth <= hops && frontier.length; depth++) {
    const next = [];
    for (const id of frontier) {
      for (const { to } of adj.get(id) || []) {
        if (visited.has(to)) continue;
        visited.add(to);
        layers[String(depth)].push(to);
        next.push(to);
      }
    }
    frontier = next;
  }
  return layers;
}

export function shortestPath(graph, source, target) {
  const adj = buildAdjacency(graph);
  if (!adj.has(source)) throw new Error(`Unknown source node: ${source}`);
  if (!adj.has(target)) throw new Error(`Unknown target node: ${target}`);

  const dist = new Map([[source, 0]]);
  const prev = new Map();
  const done = new Set();

  for (;;) {
    let current = null;
    let best = Infinity;
    for (const [id, d] of dist) {
      if (!done.has(id) && d < best) {
        best = d;
        current = id;
      }
    }
    if (current === null) break;
    done.add(current);
    if (current === target) break;

    for (const { to, edge } of adj.get(current) || []) {
      const alt = best + edge.weight;
      if (alt < (dist.get(to) ?? Infinity)) {
        dist.set(to, alt);
        prev.set(to, current);
      }
    }
  }

  if (!dist.has(target)) return { path: [], hops: 0, risk_score: null, message: "No path found" };

  const path = [target];
  while (path[path.length - 1] !== source) path.push(prev.get(path[path.length - 1]));
  path.reverse();
  return { path, hops: path.length - 1, risk_score: dist.get(target) };
}

export function findCycles(graph) {
  const adj = buildAdjacency(graph);
  const visited = new Set();
  const inStack = new Set();
  const stack = [];
  const cycles = [];
  const seen = new Set();

  const canonical = (cycle) => {
    let min = 0;
    for (let i = 1; i < cycle.length; i++) if (cycle[i] < cycle[min]) min = i;
    return [...cycle.slice(min), ...cycle.slice(0, min)];
  };

  const dfs = (node) => {
    visited.add(node);
    inStack.add(node);
    stack.push(node);
    for (const { to } of adj.get(node) || []) {
      if (inStack.has(to)) {
        const cycle = canonical(stack.slice(stack.indexOf(to)));
        const key = cycle.join("\0");
        if (!seen.has(key)) {
          seen.add(key);
          cycles.push(cycle);
        }
      } else if (!visited.has(to)) {
        dfs(to);
      }
    }
    stack.pop();
    inStack.delete(node);
  };

  graph.nodes.forEach((n) => {
    if (!visited.has(n.id)) dfs(n.id);
  });
  return cycles;
}

export function criticalNode(graph) {
  const sources = graph.nodes.filter((n) => n.isSource).map((n) => n.id);
  const sinks = new Set(graph.nodes.filter((n) => n.isSink).map((n) => n.id));
  if (!sources.length || !sinks.size) {
    throw new Error("Critical-node analysis needs at least one is_source and one is_sink node.");
  }

  const base = new Map();
  buildAdjacency(graph).forEach((list, id) => base.set(id, list.map((x) => x.to)));

  const countPaths = (blocked) => {
    let total = 0;
    const walk = (node, visited) => {
      if (sinks.has(node) && visited.size > 1) {
        total++;
        return;
      }
      for (const next of base.get(node) || []) {
        if (visited.has(next) || blocked === next) continue;
        visited.add(next);
        walk(next, visited);
        visited.delete(next);
      }
    };
    sources.forEach((s) => {
      if (s !== blocked) walk(s, new Set([s]));
    });
    return total;
  };

  const baseline = countPaths(null);
  const ranking = graph.nodes
    .map((n) => ({ node: n.id, paths_removed: baseline - countPaths(n.id) }))
    .sort((a, b) => b.paths_removed - a.paths_removed || a.node.localeCompare(b.node));

  return {
    critical_node: ranking[0]?.node ?? null,
    paths_removed: ranking[0]?.paths_removed ?? 0,
    baseline_path_count: baseline,
    ranking,
  };
}

/* ---------- helpers for turning results into highlighted elements ---------- */

export function edgeBetween(graph, from, to) {
  return graph.edges.find((e) => e.source === from && e.target === to) || null;
}

export function edgeIdsAmong(graph, nodeIds) {
  const set = new Set(nodeIds);
  return graph.edges.filter((e) => set.has(e.source) && set.has(e.target)).map((e) => e.id);
}

export function chainEdgeIds(graph, ids, closed = false) {
  const out = [];
  const n = closed ? ids.length : ids.length - 1;
  for (let i = 0; i < n; i++) {
    const e = edgeBetween(graph, ids[i], ids[(i + 1) % ids.length]);
    if (e) out.push(e.id);
  }
  return out;
}
