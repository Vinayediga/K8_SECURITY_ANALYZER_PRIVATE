#!/usr/bin/env python3
"""
main.py — CLI for the Kubernetes Attack Path Visualizer graph engine.
Run `python main.py --help` for all options.
"""

import argparse
import json
import sys
from pathlib import Path

from .graph_engine import GraphEngine, GraphError

DEFAULT_GRAPH = str(Path(__file__).resolve().parents[1] / "data" / "cluster-graph.json")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Kubernetes Attack Path Visualizer — graph analysis CLI",
    )
    parser.add_argument("-g", "--graph", default=DEFAULT_GRAPH,
                         help="Path to the attack graph JSON (default: data/cluster-graph.json)")

    parser.add_argument("--blast-radius", action="store_true",
                         help="BFS blast-radius from --source, up to --hops")
    parser.add_argument("--source", help="Source node id (blast-radius / shortest-path)")
    parser.add_argument("--target", help="Target node id (shortest-path)")
    parser.add_argument("--hops", type=int, default=3,
                         help="Max hop depth for --blast-radius (default: 3)")

    parser.add_argument("--cycles", action="store_true", help="Detect directed cycles")
    parser.add_argument("--critical-node", action="store_true",
                         help="Rank nodes by how many attack paths break if removed")
    parser.add_argument("--full-report", action="store_true",
                         help="Aggregate stats + cycles + critical-node analysis as one JSON document")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        engine = GraphEngine().load(args.graph)
    except GraphError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1

    try:
        if args.blast_radius:
            if not args.source:
                parser.error("--blast-radius requires --source")
            result = engine.blast_radius(args.source, args.hops)

        elif args.cycles:
            result = engine.find_cycles()

        elif args.critical_node:
            result = engine.critical_node_analysis()

        elif args.full_report:
            result = {
                "graph_file": args.graph,
                **engine.stats(),
                "cycles": engine.find_cycles(),
                "critical_node_analysis": engine.critical_node_analysis(),
            }

        elif args.source and args.target:
            result = engine.shortest_path(args.source, args.target)

        else:
            parser.error(
                "No action specified. Use --blast-radius, --cycles, --critical-node, "
                "--full-report, or --source/--target together for shortest path."
            )
            return 2

    except GraphError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
