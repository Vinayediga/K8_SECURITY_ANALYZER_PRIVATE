/**
 * Thin client for the FastAPI backend (backend/api.py).
 * JWT access tokens last 15 minutes and there is no refresh endpoint, so a 401
 * clears the token and notifies the app, which sends the user back to login.
 */
const BASE = (import.meta.env.VITE_API_URL ?? "/api").replace(/\/$/, "");
const TOKEN_KEY = "k8s_access_token";

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => (onUnauthorized = fn);

export const getToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
};
export const setToken = (t) => {
  try {
    t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable */
  }
};

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function formatDetail(detail, fallback) {
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI/pydantic validation errors
    return detail.map((d) => `${(d.loc || []).slice(1).join(".") || "field"}: ${d.msg}`).join("; ");
  }
  return fallback;
}

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = getToken();
  if (auth && token) headers.Authorization = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "Cannot reach the backend. Is it running on port 8000?");
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }

  if (!res.ok) {
    if (res.status === 401 && auth) {
      setToken(null);
      onUnauthorized();
    }
    throw new ApiError(res.status, formatDetail(data?.detail, `Request failed (${res.status})`));
  }
  return data;
}

const qs = (params) => new URLSearchParams(params).toString();

export const api = {
  register: (email, password) => request("/auth/register", { method: "POST", body: { email, password }, auth: false }),
  login: async (email, password) => {
    const data = await request("/auth/login", { method: "POST", body: { email, password }, auth: false });
    setToken(data.access_token);
    return data;
  },
  loginWithGoogle: async (credential) => {
    const data = await request("/auth/google", { method: "POST", body: { credential }, auth: false });
    setToken(data.access_token);
    return data;
  },
  me: () => request("/auth/me"),

  listClusters: () => request("/clusters"),
  createCluster: (name, context_name) => request("/clusters", { method: "POST", body: { name, context_name } }),
  updateCluster: (id, name, context_name) => request(`/clusters/${id}`, { method: "PUT", body: { name, context_name } }),
  deleteCluster: (id) => request(`/clusters/${id}`, { method: "DELETE" }),
  registerAgent: (clusterId) => request(`/agents/register?${qs({ cluster_id: clusterId })}`, { method: "POST" }),
  rotateAgentToken: (agentId) => request(`/agents/${agentId}/rotate-token`, { method: "POST" }),

  createScan: (cluster_id) => request("/scans", { method: "POST", body: { cluster_id, scan_type: "scan_cluster" } }),
  listScans: () => request("/scans"),
  getScan: (id) => request(`/scans/${id}`),
  deleteScan: (id) => request(`/scans/${id}`, { method: "DELETE" }),

  listSnapshots: (clusterId) => request(`/snapshots?${qs({ cluster_id: clusterId })}`),
  getSnapshot: (id) => request(`/snapshots/${id}`),

  blastRadius: (id, source, hops) => request(`/snapshots/${id}/blast-radius?${qs({ source, hops })}`),
  shortestPath: (id, source, target) => request(`/snapshots/${id}/paths?${qs({ source, target })}`),
  analysis: (id) => request(`/snapshots/${id}/analysis`),
};
