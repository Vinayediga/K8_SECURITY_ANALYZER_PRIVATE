"""
graph_engine.py
----------------
Core graph engine for the Kubernetes Attack Path Visualizer.

Loads a directed attack graph (nodes + edges) from JSON, preserving every
original field on both nodes and edges, and exposes four analyses:

  1. blast_radius(source, hops)      -> BFS reachability, layered by hop count
  2. shortest_path(source, target)   -> Dijkstra, minimum sum of edge weights
  3. find_cycles()                   -> DFS back-edge detection, deduplicated
  4. critical_node_analysis()        -> node whose removal kills the most
                                         source -> sink simple paths
"""

import json
import heapq
from collections import deque, defaultdict


class GraphError(Exception):
    """Raised for malformed graph data or invalid queries."""
    pass


class GraphEngine:
    def __init__(self):
        self.nodes = {}               # id (str) -> full node dict (all original fields kept)
        self.adj = defaultdict(list)  # id -> list of (neighbor_id, edge dict)
        self._raw_edges = []

       # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    def load(self, path):
        """Load graph data from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            raise GraphError(f"Graph file not found: {path}")
        except json.JSONDecodeError as e:
            raise GraphError(f"Invalid JSON in {path}: {e}")

        return self.load_data(data)

    def load_data(self, data):
        """Load graph data directly from a Python dictionary."""
        if not isinstance(data, dict):
            raise GraphError(
                "Graph data must be an object with 'nodes' and 'edges' arrays"
            )

        if (
            not isinstance(data.get("nodes"), list)
            or not isinstance(data.get("edges"), list)
        ):
            raise GraphError(
                "Graph data must be an object with 'nodes' and 'edges' arrays"
            )

        # Reset state so loading another graph doesn't mix old data.
        self.nodes = {}
        self.adj = defaultdict(list)
        self._raw_edges = []

        for node in data["nodes"]:
            if not isinstance(node, dict) or "id" not in node:
                raise GraphError(
                    f"Node missing required 'id' field: {node}"
                )

            node_id = str(node["id"])

            if node_id in self.nodes:
                raise GraphError(f"Duplicate node id: {node_id}")

            self.nodes[node_id] = dict(node)
            self.nodes[node_id]["id"] = node_id

        for edge_data in data["edges"]:
            if (
                not isinstance(edge_data, dict)
                or "source" not in edge_data
                or "target" not in edge_data
            ):
                raise GraphError(
                    f"Edge missing required 'source'/'target': {edge_data}"
                )

            source = str(edge_data["source"])
            target = str(edge_data["target"])

            if source not in self.nodes:
                raise GraphError(
                    f"Edge references unknown source node: {source}"
                )

            if target not in self.nodes:
                raise GraphError(
                    f"Edge references unknown target node: {target}"
                )

            edge = dict(edge_data)
            edge["source"] = source
            edge["target"] = target
            edge.setdefault("weight", 1.0)

            self._raw_edges.append(edge)
            self.adj[source].append((target, edge))

        return self

    # ------------------------------------------------------------------ #
    # 1. Blast radius — BFS, layered by minimum hop distance
    # ------------------------------------------------------------------ #
    def blast_radius(self, source, hops):
        source = str(source)
        if source not in self.nodes:
            raise GraphError(f"Unknown source node: {source}")
        if hops < 0:
            raise GraphError("hops must be >= 0")

        layers = {str(h): [] for h in range(1, hops + 1)}
        visited = {source}
        queue = deque([(source, 0)])

        while queue:
            node, depth = queue.popleft()
            if depth == hops:
                continue
            for neighbor, _edge in self.adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_depth = depth + 1
                    layers[str(new_depth)].append(neighbor)
                    queue.append((neighbor, new_depth))

        return layers

    # ------------------------------------------------------------------ #
    # 2. Weighted shortest path — Dijkstra 
    # ------------------------------------------------------------------ #
    def shortest_path(self, source, target):
        source, target = str(source), str(target)
        if source not in self.nodes:
            raise GraphError(f"Unknown source node: {source}")
        if target not in self.nodes:
            raise GraphError(f"Unknown target node: {target}")

        dist = {source: 0.0}
        prev = {}
        visited = set()
        heap = [(0.0, source)]

        while heap:
            d, node = heapq.heappop(heap)
            if node in visited:
                continue  # stale heap entry, skip
            visited.add(node)
            if node == target:
                break
            for neighbor, edge in self.adj.get(node, []):
                weight = edge.get("weight", 1.0)
                if weight < 0:
                    raise GraphError(f"Negative edge weight not supported: {edge}")
                alt = d + weight
                if alt < dist.get(neighbor, float("inf")):
                    dist[neighbor] = alt
                    prev[neighbor] = node
                    heapq.heappush(heap, (alt, neighbor))

        if target not in dist:
            return {"path": [], "hops": 0, "risk_score": None, "message": "No path found"}

        path = [target]
        while path[-1] != source:
            path.append(prev[path[-1]])
        path.reverse()

        return {"path": path, "hops": len(path) - 1, "risk_score": dist[target]}

    # ------------------------------------------------------------------ #
    # 3. Cycle detection — DFS,
    # ------------------------------------------------------------------ #
    def find_cycles(self):
        visited = set()
        in_stack = set()
        stack = []
        cycles_found = []
        seen_canonical = set()

        def canonical(cycle):
            # rotate so the lexicographically-smallest id starts the cycle,
            # giving the same cycle a single stable representation
            min_idx = min(range(len(cycle)), key=lambda i: cycle[i])
            rotated = cycle[min_idx:] + cycle[:min_idx]
            return tuple(rotated)

        def dfs(node):
            visited.add(node)
            in_stack.add(node)
            stack.append(node)

            for neighbor, _edge in self.adj.get(node, []):
                if neighbor in in_stack:
                    idx = stack.index(neighbor)
                    cycle = stack[idx:]
                    key = canonical(cycle)
                    if key not in seen_canonical:
                        seen_canonical.add(key)
                        cycles_found.append(list(key))
                elif neighbor not in visited:
                    dfs(neighbor)

            stack.pop()
            in_stack.discard(node)

        for node_id in self.nodes:
            if node_id not in visited:
                dfs(node_id)

        return cycles_found

    # ------------------------------------------------------------------ #
    # 4. Critical node analysis
    # ------------------------------------------------------------------ #
    def _count_simple_paths(self, adjacency, sources, sinks):
        """Count all simple directed paths from any source to any sink."""
        total = 0
        sink_set = set(sinks)

        def dfs(node, visited):
            nonlocal total
            if node in sink_set and len(visited) > 1:
                total += 1
                return
            for neighbor in adjacency.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    dfs(neighbor, visited)
                    visited.remove(neighbor)

        for s in sources:
            dfs(s, {s})

        return total

    def critical_node_analysis(self):
        sources = [nid for nid, n in self.nodes.items() if n.get("is_source")]
        sinks = [nid for nid, n in self.nodes.items() if n.get("is_sink")]

        if not sources or not sinks:
            raise GraphError(
                "critical-node analysis requires at least one node with "
                "'is_source': true and one with 'is_sink': true"
            )

        base_adj = {nid: [t for t, _e in edges] for nid, edges in self.adj.items()}
        baseline = self._count_simple_paths(base_adj, sources, sinks)

        ranking = []
        for candidate in self.nodes:
            pruned_adj = {
                nid: [t for t in targets if t != candidate]
                for nid, targets in base_adj.items()
                if nid != candidate
            }
            pruned_sources = [s for s in sources if s != candidate]
            pruned_sinks = [t for t in sinks if t != candidate]
            new_count = self._count_simple_paths(pruned_adj, pruned_sources, pruned_sinks)
            ranking.append({"node": candidate, "paths_removed": baseline - new_count})

        ranking.sort(key=lambda r: (-r["paths_removed"], r["node"]))
        critical = ranking[0] if ranking else None

        return {
            "critical_node": critical["node"] if critical else None,
            "paths_removed": critical["paths_removed"] if critical else 0,
            "baseline_path_count": baseline,
            "ranking": ranking,
        }

    # ------------------------------------------------------------------ #
    def stats(self):
        return {"node_count": len(self.nodes), "edge_count": len(self._raw_edges)}
