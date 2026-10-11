# Kubernetes Attack Path Visualizer

A small Python toolkit for turning Kubernetes cluster metadata and RBAC relationships into a directed attack graph. The graph can be queried from the command line, rendered as a readable kill-chain report, or explored in a browser.

```text
Kubernetes cluster
        |
        v
worker/extract_graph.py  --->  data/cluster-graph.json  --->  analysis/main.py / analysis/report.py
                     |
                     v
                  frontend/visualize.html
```

## What it does

The project models Kubernetes resources and security relationships as nodes and directed edges. It then provides four analyses:

- **Blast radius:** breadth-first traversal showing what can be reached within a maximum number of hops.
- **Shortest attack path:** Dijkstra's algorithm using the sum of edge weights as the attack cost.
- **Cycle detection:** depth-first search for directed cycles that may indicate re-entry or persistence paths.
- **Critical-node analysis:** identifies the node whose removal breaks the largest number of source-to-sink paths.

The extractor also attaches structured security findings to graph nodes, including missing NetworkPolicies and risky RBAC relationships.

## Requirements

- Python 3.9 or newer is recommended.
- The analysis CLI and report generator use only the Python standard library.
- The cluster extractor requires the Kubernetes Python client.
- A Kubernetes context with permission to read the resources inspected by `extract_graph.py` is required for live extraction.
- A modern browser is required for `visualize.html`.

## Installation

Create and activate a virtual environment if you do not already have one:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

Install the extractor dependency:

```bash
python -m pip install -r requirements.txt
```

The core files (`graph_engine.py`, `main.py`, `report.py`, and `test_cases.py`) do not require third-party packages.

## Project layout

| File | Purpose |
| --- | --- |
| `backend/` | FastAPI application, authentication, database, models, and repositories. |
| `worker/` | Background scan agent and live Kubernetes graph extraction. |
| `analysis/` | Graph engine, JSON CLI, and human-readable report generator. |
| `tests/` | Standard-library fixture checks for the graph engine. |
| `frontend/` | React application and standalone graph visualizer. |
| `data/` | Default and sample attack graph JSON files. |
| `config/` | Local credential files; ignored by Git. |
| `api.py`, `agent.py`, `extract_graph.py`, `main.py`, `report.py`, `test_cases.py` | Compatibility launchers for the organized packages. |
| `requirements.txt` | Python dependency list for extraction and optional development tools. |

## Quick start with the included graph

Run the fixture checks first:

```bash
python test_cases.py
```

Run a complete JSON report:

```bash
python main.py --full-report
```

Generate the readable report:

```bash
python report.py --blast-hops 3
```

Commands use `data/cluster-graph.json` by default. Use `-g` or `--graph` to select another graph file:

```bash
python main.py --graph data/graph.json --cycles
python report.py --graph data/graph.json --blast-hops 5
```

## Command-line analyses

### Blast radius

Show nodes reachable from a source within a maximum hop count:

```bash
python main.py --blast-radius \
  --source "pod:default:vuln-pod" \
  --hops 3
```

The result is a JSON object whose keys are hop numbers. The source node is not included in its own layer.

### Weighted shortest path

Find the lowest-cost directed path between two nodes:

```bash
python main.py \
  --source "pod:default:vuln-pod" \
  --target "secret:default:db-creds"
```

The result contains `path`, `hops`, and `risk_score`. If the target is unreachable, the result contains an empty path and a `No path found` message.

### Cycle detection

Find directed cycles in the graph:

```bash
python main.py --cycles
```

Cycles are deduplicated and returned in a deterministic canonical form.

### Critical-node analysis

Rank nodes by the number of simple source-to-sink attack paths that disappear when each node is removed:

```bash
python main.py --critical-node
```

The result includes the baseline path count, the selected critical node, the number of paths removed, and a complete ranking. This analysis counts simple paths and can become expensive on graphs with many interconnected paths.

### Full report

Combine graph statistics, cycles, and critical-node analysis into one JSON document:

```bash
python main.py --full-report
```

The full report does not include the readable path-by-path narrative produced by `report.py`.

## Extract a graph from Kubernetes

The extractor uses the Kubernetes client configuration and reads the selected context. To see the available Kubernetes contexts:

```bash
kubectl config get-contexts
```

Extract the graph from a named context:

```bash
python extract_graph.py \
  --context kind-k8s-security-lab \
  --out data/cluster-graph.json
```

The options are:

| Option | Default | Description |
| --- | --- | --- |
| `--context` | Current Kubernetes context | Context to use when loading cluster configuration. |
| `--out` | `data/cluster-graph.json` | Destination JSON file. |

The extractor gathers Kubernetes objects such as Pods, Services, ServiceAccounts, Secrets, Nodes, Namespaces, Roles, ClusterRoles, RoleBindings, ClusterRoleBindings, and NetworkPolicies. The exact set depends on the resources available and readable in the cluster.

After extraction, inspect the result with:

```bash
python main.py --graph cluster-graph.json --full-report
```

## Graph file format

The graph must be a JSON object with `nodes` and `edges` arrays:

```json
{
  "nodes": [
    {
      "id": "pod:default:web",
      "type": "Pod",
      "label": "web",
      "risk_score": 4.0,
      "is_source": true,
      "is_sink": false
    }
  ],
  "edges": [
    {
      "source": "pod:default:web",
      "target": "secret:default:db-creds",
      "relationship": "CAN_READ_SECRET",
      "weight": 1.0
    }
  ]
}
```

### Required fields

- Every node requires a unique `id`.
- Every edge requires `source` and `target` values that refer to existing node IDs.
- Edge `weight` defaults to `1.0` when omitted.
- Edge weights must not be negative because shortest-path analysis uses Dijkstra's algorithm.

Additional node and edge fields are preserved by `GraphEngine`, so the visualizer and reports can use extractor-specific metadata.

### Common node fields

- `id`: Stable identifier used by commands and edges.
- `type`: Kubernetes or conceptual resource type.
- `label`: Display label.
- `namespace`: Kubernetes namespace when applicable.
- `risk_score`: Numeric risk estimate from the extractor.
- `is_source`: Marks a potential entry point.
- `is_sink`: Marks a high-value target.
- `findings`: Structured security findings, when present.
- `cves`: Associated vulnerability identifiers, when present.

### Common edge fields

- `source`: Origin node ID.
- `target`: Destination node ID.
- `relationship`: Description of the relationship or permission.
- `weight`: Relative attack cost; lower values are preferred by shortest-path analysis.

## Visualize the graph

Because browsers commonly block local `fetch()` requests from `file://` pages, serve the project directory over a local HTTP server:

```bash
python -m http.server 8000
```

Open [http://localhost:8000/frontend/visualize.html](http://localhost:8000/frontend/visualize.html) in a browser. The page loads `data/cluster-graph.json` automatically.

The visualizer provides a directed graph view with node and edge inspection. It hides Kubernetes system noise by default and visually de-emphasizes topology-only scheduling relationships. Use the raw JSON view or browser developer tools when you need to inspect fields that are not displayed in the graph panel.

## Test and validation

The repository includes a dependency-free fixture harness:

```bash
python test_cases.py
```

It checks:

1. BFS blast-radius layering.
2. Dijkstra shortest-path cost and hop count.
3. Unreachable-target handling.
4. DFS cycle detection and deduplication.
5. Critical-node path-removal ranking.
6. Missing-file error handling.

An optional `pytest` dependency is listed as a development tool, but the current test harness is run directly with Python.

## Example lab resource

To create a small RBAC fixture for experimentation, apply a ServiceAccount, a Role that can create Pods, a RoleBinding, and a Pod using that ServiceAccount. For example:

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

Apply it, extract the graph again, and rerun the analyses:

```bash
kubectl apply -f lab-fixture.yaml
python extract_graph.py --out data/cluster-graph.json
python main.py --critical-node
```

Only use this fixture in a disposable lab cluster. Review the permissions and delete the resources when finished:

```bash
kubectl delete -f lab-fixture.yaml
```

## Security and sensitive files

This tool reads cluster metadata and may identify secrets or privileged relationships. It does not need secret values to perform graph analysis.

Do not commit kubeconfig files, cloud credentials, tokens, private keys, or secret values. The current repository contains a tracked `credentials.json`; inspect it before sharing the repository publicly. If it contains a real credential, revoke or rotate that credential immediately, remove the file from version control, and add it to `.gitignore` before future commits.

Suggested local ignore entries:

```gitignore
credentials.json
.env
.venv/
__pycache__/
```

Removing a file from the latest commit does not remove it from older Git history. Credentials that were committed should be rotated and, when necessary, removed from history using an approved repository-history rewrite process.

## Limitations

- The graph represents relationships discovered by the extractor; it is not a complete Kubernetes exploit simulator.
- Risk scores and edge weights are heuristics, not probability estimates.
- Shortest paths require non-negative edge weights.
- Critical-node analysis enumerates simple paths and may be slow for dense graphs.
- The extractor requires sufficient Kubernetes API permissions and a reachable cluster.
- The browser visualizer is served from `frontend/visualize.html` and reads `data/cluster-graph.json`.

## License

No license file is currently included. Add a license before distributing this project outside its intended repository.