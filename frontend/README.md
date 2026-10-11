# K8s Security Analyzer — frontend (Vite + React + Tailwind)

Converted from the standalone `visualize.html` and wired to the FastAPI backend.

## Run

```bash
# 1. backend (from the repo root, with MONGODB_URI and JWT_SECRET_KEY in .env)
uvicorn api:app --reload --port 8000

# 2. frontend (this folder)
npm install
npm run dev          # http://localhost:5173
```

In dev, requests to `/api/*` are proxied to `http://127.0.0.1:8000` (see `vite.config.js`), so no CORS
setup is needed. For a different backend address use `VITE_BACKEND_URL=... npm run dev`.
For a production build served from another origin, set `VITE_API_URL` (see `.env.example`) and add the
site's origin to `FRONTEND_ORIGINS` in the backend `.env`.

## Flow

1. Create an account / sign in (password 12+ chars), or click **Try with sample data** (offline demo, no backend).
2. **Clusters & Scans** → register a cluster (name + kubectl context) → **Register agent** (token shown once)
   → run `python agent.py` with the printed env vars → **Run scan**.
3. When the scan completes the new snapshot loads automatically; every other tab then works on it.
   Attack-path analyses call `/snapshots/{id}/blast-radius|paths|analysis` and fall back to the in-browser
   implementation (identical results) if the backend call fails.

## Layout

```
src/
  App.jsx                 auth gate + tab shell
  context/GraphContext    loaded graph, source (sample/file/api), selection, highlight
  lib/api.js              backend client (JWT, 401 handling)
  lib/graph.js            normalisation, findings, mitigation mapping
  lib/analysis.js         BFS / Dijkstra / cycles / critical-node (same shapes as the backend)
  components/*Pane.jsx    Overview, Graph, Findings, Paths, Risk, Mitigation, Clusters
  legacy.css              the original page's stylesheet (kept so the look is unchanged)
  index.css               Tailwind import + styles for the node-detail panel
public/sample-graph.json  sample data for the offline demo
```

## Graph files that are not in the standard format

The app normalises most variants on load (risk as a number or a word, `from`/`to`, `vulnerabilities`,
string findings…). If a file has no findings list at all, findings are derived from risk ratings and flags,
and the Overview tab shows a **Data check** card describing what was adjusted or skipped.

To convert a file once and for all (for the CLI, the backend or `agent.py` too):

```bash
python tools/convert_graph.py my-graph.json -o my-graph.standard.json
```
