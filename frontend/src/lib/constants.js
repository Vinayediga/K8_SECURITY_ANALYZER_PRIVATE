export const NODE_COLORS = {
  Pod: "#5aa9e6",
  ServiceAccount: "#9b7ede",
  Namespace: "#4fb286",
  Secret: "#e0c341",
  Node: "#e6e6e6",
  User: "#c084fc",
  ExternalActor: "#f97316",
  Role: "#60a5fa",
  ClusterRole: "#818cf8",
  Service: "#2dd4bf",
  ConfigMap: "#94a3b8",
  Database: "#fb7185",
  PersistentVolume: "#a78bfa",
};

export const RISK_COLORS = {
  info: "#3a7ca8",
  medium: "#c9962c",
  high: "#d9622b",
  critical: "#c0392b",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "info"];
export const TOPOLOGY_EDGES = new Set(["SCHEDULED_ON", "hosts"]);
export const SYSTEM_NAMESPACES = new Set(["kube-system"]);
