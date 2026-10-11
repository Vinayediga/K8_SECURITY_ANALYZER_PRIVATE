# Kubernetes Attack Path Visualizer

End-to-end pipeline: **live cluster → JSON attack graph → algorithmic analysis → visualized in browser.**

```
extract_graph.py  →  cluster-graph.json  →  main.py / report.py  →  visualize.html
   (from kubectl)      (single shared file)     (BFS/Dijkstra/DFS)      (Cytoscape.js)
```

## Files

| File | Role |
|------|------|
| `extract_graph.py` | Connects to your live/kind cluster, builds the attack graph |
| `graph_engine.py` | Core engine: BFS blast-radius, Dijkstra shortest path, DFS cycles, critical-node analysis |
| `main.py` | CLI for running the four analyses, JSON output |
| `report.py` | Human-readable narrative "kill chain" report |
| `test_cases.py` | Fixture validation harness (`PASS`/`FAIL`) |
| `visualize.html` | Browser-based graph visualizer (Cytoscape.js, dagre layout) |
| `cluster-graph.json` | The shared data file all four tools read/write |

## 1. Install

```bash
pip install -r requirements.txt
```

## 2. Extract the graph from your cluster

```bash
python extract_graph.py --context kind-k8s-security-lab --out cluster-graph.json
```

This pulls Pods, ServiceAccounts, Secrets, Nodes, Namespaces, and resolves
RoleBindings/ClusterRoleBindings into attack edges. Every node/edge is tagged
with the fields the analysis engine needs:

- **Nodes**: `risk_score`, `is_source` (potential entry point — every Pod),
  `is_sink` (high-value target — Secrets, the control-plane Node, and any
  namespace reachable via a dangerous permission), `cves`
- **Edges**: `relationship`, `weight` (lower = easier/cheaper for an
  attacker — derived from severity: critical=1, high=3, medium=5, info=9)

## 3. Run the analysis (this is the actual "attack path" step)

```bash
# Verify the engine itself is correct first
python test_cases.py

# How far can an attacker reach from a compromised pod, in N hops?
python main.py --blast-radius --source "pod:default:vuln-pod" --hops 3

# What's the cheapest/easiest route from an entry point to a target?
python main.py --source "pod:default:vuln-pod" --target "secret:default:db-creds"

# Are there any privilege loops (re-entry / persistence opportunities)?
python main.py --cycles

# Which single node, if fixed/removed, breaks the most attack paths?
python main.py --critical-node

# Everything at once, one JSON document
python main.py --full-report

# Same thing, but as a readable narrative instead of raw JSON
python report.py --blast-hops 3
```

All commands default to reading `cluster-graph.json` from the current
directory; override with `-g/--graph path/to/file.json`.

## 4. Visualize it

```bash
python -m http.server 8000
```

Open `http://localhost:8000/visualize.html` — it auto-loads
`cluster-graph.json`. kube-system noise is hidden by default, `SCHEDULED_ON`
edges are dimmed (they're topology, not an attack step), and the layout is
a directed (dagre) path view rooted at your entry points. Click any
node/edge to inspect its full raw data, including `risk_score`/`weight`.

## Build your one-vulnerability test case

Minimal setup to produce a real `CAN_CREATE_POD` / `CAN_READ_SECRET` edge:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vuln-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-creator
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vuln-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: vuln-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-creator
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: vuln-pod
  namespace: default
spec:
  serviceAccountName: vuln-sa
  containers:
  - name: app
    image: nginx
```

Apply it, re-run `extract_graph.py`, then re-run `main.py --critical-node` —
you'll see `vuln-pod` come back as the critical node, since it's the sole
entry point feeding every downstream attack path.

## Algorithm notes

- **Blast radius (BFS)**: minimum-hop layering, no revisits, layers 1..N.
- **Shortest path (Dijkstra)**: binary heap, lazy stale-entry deletion,
  strict-improvement relaxation for deterministic ties. Returns
  `"No path found"` for unreachable targets.
- **Cycles (DFS)**: back-edge detection via a recursion stack; cycles are
  deduplicated by rotating to a canonical (lexicographically-smallest-first)
  form.
- **Critical node**: counts all simple `is_source → is_sink` paths as a
  baseline, then re-counts on a pruned copy with each candidate node removed.
  `paths_removed = baseline − pruned_count`; ties broken by ascending node id.
