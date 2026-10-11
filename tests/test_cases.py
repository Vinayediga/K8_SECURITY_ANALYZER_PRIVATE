#!/usr/bin/env python3
"""
test_cases.py — fixture-based validation harness for graph_engine.py.
Run: python test_cases.py
"""

import sys
import os
import json
import tempfile

from analysis.graph_engine import GraphEngine, GraphError

# Fixture is built so its BFS / Dijkstra / cycle results match the
# worked examples in the project README exactly, for easy cross-checking.
FIXTURE = {
    "nodes": [
        {"id": "pod-webfront", "type": "Pod", "is_source": True},
        {"id": "svc-api-gateway", "type": "Service"},
        {"id": "deploy-auth-svc", "type": "Deployment"},
        {"id": "pod-worker-1", "type": "Pod", "is_sink": True},
        {"id": "pod-worker-2", "type": "Pod", "is_sink": True},
        {"id": "user-dev1", "type": "User", "is_source": True},
        {"id": "web-frontend", "type": "Pod"},
        {"id": "api-internal", "type": "Service"},
        {"id": "db-production", "type": "Database", "is_sink": True},
        {"id": "svc-service-a", "type": "Service"},
        {"id": "svc-service-b", "type": "Service"},
    ],
    "edges": [
        {"source": "pod-webfront", "target": "svc-api-gateway", "weight": 1},
        {"source": "svc-api-gateway", "target": "deploy-auth-svc", "weight": 1},
        {"source": "deploy-auth-svc", "target": "pod-worker-1", "weight": 1},
        {"source": "deploy-auth-svc", "target": "pod-worker-2", "weight": 1},
        {"source": "user-dev1", "target": "web-frontend", "weight": 4.5},
        {"source": "web-frontend", "target": "api-internal", "weight": 4.0},
        {"source": "api-internal", "target": "db-production", "weight": 4.0},
        {"source": "svc-service-a", "target": "svc-service-b", "weight": 1},
        {"source": "svc-service-b", "target": "svc-service-a", "weight": 1},
    ],
}


def load_fixture():
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(FIXTURE, f)
    engine = GraphEngine().load(path)
    os.remove(path)
    return engine


def check(label, condition, results):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    results.append(condition)


def main():
    results = []
    engine = load_fixture()

    # 1. BFS blast radius — matches README's worked example exactly
    layers = engine.blast_radius("pod-webfront", 3)
    ok = (
        layers.get("1") == ["svc-api-gateway"]
        and layers.get("2") == ["deploy-auth-svc"]
        and sorted(layers.get("3", [])) == ["pod-worker-1", "pod-worker-2"]
    )
    check("1. BFS (pod-webfront, hops=3)", ok, results)

    # 2. Dijkstra shortest path — matches README's worked example exactly
    sp = engine.shortest_path("user-dev1", "db-production")
    ok = (
        sp["path"] == ["user-dev1", "web-frontend", "api-internal", "db-production"]
        and sp["hops"] == 3
        and abs(sp["risk_score"] - 12.5) < 1e-9
    )
    check("2. Dijkstra (user-dev1 -> db-production)", ok, results)

    # 2b. Unreachable target
    sp2 = engine.shortest_path("svc-service-a", "db-production")
    ok = sp2.get("message") == "No path found" and sp2["path"] == []
    check("2b. Dijkstra unreachable target returns 'No path found'", ok, results)

    # 3. Cycle detection — matches README's worked example exactly
    cycles = engine.find_cycles()
    ok = cycles == [["svc-service-a", "svc-service-b"]]
    check("3. DFS cycle detection (svc-service-a <-> svc-service-b)", ok, results)

    # 4. Critical node analysis — deploy-auth-svc and svc-api-gateway are both
    #    single points of failure for the two worker paths (2 of 3 total paths)
    crit = engine.critical_node_analysis()
    ok = (
        crit["baseline_path_count"] == 3
        and crit["critical_node"] in ("deploy-auth-svc", "svc-api-gateway")
        and crit["paths_removed"] == 2
    )
    check("4. Critical node analysis (bottleneck removes 2 of 3 paths)", ok, results)

    # 5. Error handling for missing file
    try:
        GraphEngine().load("this-file-does-not-exist.json")
        ok = False
    except GraphError:
        ok = True
    check("5. GraphError raised for missing file", ok, results)

    passed = sum(results)
    total = len(results)
    print(f"\nSummary: {passed}/{total} checks passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
