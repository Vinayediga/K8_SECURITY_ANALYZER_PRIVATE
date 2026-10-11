#!/usr/bin/env python3
"""
report.py — narrative "kill chain" text report over the attack graph.
Combines entry points, blast radius, weighted attack paths, cycles, and
critical-node analysis into one human-readable document.
"""

import argparse
import sys
from pathlib import Path

from .graph_engine import GraphEngine, GraphError

DEFAULT_GRAPH = str(Path(__file__).resolve().parents[1] / "data" / "cluster-graph.json")


def describe_node(engine, node_id):
    n = engine.nodes.get(node_id, {})
    ntype = n.get("type", "?")
    ns = n.get("namespace")
    label = f"{ntype}:{node_id}"
    if ns:
        label += f" (ns={ns})"
    return label


def render_report(engine, blast_hops):
    lines = []
    stats = engine.stats()
    lines.append("=" * 60)
    lines.append("KUBERNETES ATTACK PATH — KILL CHAIN REPORT")
    lines.append("=" * 60)
    lines.append(f"Nodes: {stats['node_count']}   Edges: {stats['edge_count']}")
    lines.append("")

    sources = [nid for nid, n in engine.nodes.items() if n.get("is_source")]
    sinks = [nid for nid, n in engine.nodes.items() if n.get("is_sink")]

    lines.append(f"Entry points (is_source): {len(sources)}")
    for s in sources:
        lines.append(f"  - {describe_node(engine, s)}")
    lines.append(f"High-value targets (is_sink): {len(sinks)}")
    for s in sinks:
        lines.append(f"  - {describe_node(engine, s)}")
    lines.append("")

    lines.append(f"--- Blast radius (up to {blast_hops} hops from each entry point) ---")
    for s in sources:
        lines.append(f"\nFrom {describe_node(engine, s)}:")
        layers = engine.blast_radius(s, blast_hops)
        for hop, ids in layers.items():
            if ids:
                lines.append(f"  hop {hop}: " + ", ".join(describe_node(engine, i) for i in ids))

    lines.append("")
    lines.append("--- Weighted attack paths (entry -> target, lowest exploit cost) ---")
    for s in sources:
        for t in sinks:
            result = engine.shortest_path(s, t)
            if result.get("path"):
                path_str = " -> ".join(describe_node(engine, p) for p in result["path"])
                lines.append(f"  [{s} -> {t}] risk_score={result['risk_score']:.2f}  hops={result['hops']}")
                lines.append(f"    {path_str}")
            else:
                lines.append(f"  [{s} -> {t}] no path found")

    lines.append("")
    lines.append("--- Cycles (potential persistence / re-entry loops) ---")
    cycles = engine.find_cycles()
    if not cycles:
        lines.append("  none detected")
    else:
        for c in cycles:
            chain = " -> ".join(describe_node(engine, n) for n in c)
            lines.append(f"  {chain} -> {describe_node(engine, c[0])}")

    lines.append("")
    lines.append("--- Critical node (highest-value control point) ---")
    try:
        crit = engine.critical_node_analysis()
        lines.append(
            f"  {describe_node(engine, crit['critical_node'])}  "
            f"removes {crit['paths_removed']} of {crit['baseline_path_count']} attack paths"
        )
        lines.append("  Top 5 ranking:")
        for r in crit["ranking"][:5]:
            lines.append(f"    {describe_node(engine, r['node'])}: {r['paths_removed']} paths removed")
    except GraphError as e:
        lines.append(f"  (skipped: {e})")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Narrative kill-chain report over the attack graph")
    parser.add_argument("-g", "--graph", default=DEFAULT_GRAPH)
    parser.add_argument("--blast-hops", type=int, default=3)
    args = parser.parse_args(argv)

    try:
        engine = GraphEngine().load(args.graph)
    except GraphError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(render_report(engine, args.blast_hops))
    return 0


if __name__ == "__main__":
    sys.exit(main())
