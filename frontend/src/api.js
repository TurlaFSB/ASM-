import axios from "axios";

// Same host as the page, port 8000, over the same scheme (so an HTTPS page talks HTTPS). VITE_API_URL overrides it at build time.
const API_BASE = import.meta.env.VITE_API_URL || `${window.location.protocol}//${window.location.hostname}:8000`;

// The session lives in an httpOnly cookie the browser attaches by itself, so script code never
// sees the login token. State-changing calls echo the readable CSRF cookie in a header.
const api = axios.create({ baseURL: API_BASE, withCredentials: true });

function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)asm_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

api.interceptors.request.use(config => {
  if (!["get", "head", "options"].includes((config.method || "get").toLowerCase())) {
    config.headers["X-CSRF-Token"] = csrfToken();
  }
  return config;
});

api.interceptors.response.use(
  res => res,
  async err => {
    // The CSRF cookie can go missing on its own (cleared, expired). /auth/me hands out a fresh one,
    // so repair it once and replay the call instead of failing silently.
    const cfg = err.config;
    if (err.response?.status === 403 && err.response?.data?.detail === "CSRF check failed" && cfg && !cfg._csrfRetried) {
      cfg._csrfRetried = true;
      try { await api.get("/auth/me"); return api(cfg); } catch { /* fall through to the original error */ }
    }
    // An expired session on a normal call sends the user back to the login screen.
    if (err.response?.status === 401 && !err.config?.url?.startsWith("/auth/")) window.location.reload();
    return Promise.reject(err);
  }
);

// Named exports for all pages
export const getMe = () => api.get("/auth/me");
export const login = (username, password) => {
  const params = new URLSearchParams({ username, password });
  return api.post("/auth/token", params);
};
export const logout = () => api.post("/auth/logout");
export const getSetupStatus = () => api.get("/auth/setup-status");
export const setupAccount = (data) => api.post("/auth/setup", data);
export const changePassword = (current_password, new_password) => api.post("/auth/change-password", { current_password, new_password });
export const getApiTokens = () => api.get("/auth/tokens/");
export const createApiToken = (data) => api.post("/auth/tokens/", data);
export const revokeApiToken = (id) => api.delete(`/auth/tokens/${id}`);
export const getUsers = () => api.get("/users/");
export const createUser = (data) => api.post("/users/", data);
export const updateUser = (id, data) => api.patch(`/users/${id}`, data);
export const resetUserPassword = (id, new_password) => api.post(`/users/${id}/reset-password`, { new_password });
export const getTargets = () => api.get("/targets/");
export const getScans = () => api.get("/scans/");
export const getTargetHistory = (id) => api.get(`/targets/${id}/history`);
export const getTargetInfrastructure = (id) => api.get(`/targets/${id}/infrastructure`);
export const getAssets = () => api.get("/assets/");
export const getAssetPaths = (id) => api.get(`/assets/${id}/paths`);
export const getAlerts = (params) => api.get("/alerts/", { params });
export const getDeliveries = (params) => api.get("/alerts/deliveries", { params });
export const getNotificationSettings = (id) => api.get(`/targets/${id}/notifications`);
export const updateNotificationSettings = (id, data) => api.put(`/targets/${id}/notifications`, data);
export const testWebhook = (id) => api.post(`/targets/${id}/notifications/test`);
export const testEmail = (id) => api.post(`/targets/${id}/notifications/test-email`);
export const getUnreadAlerts = (params) => api.get("/alerts/unread", { params });
export const markAlertRead = (id) => api.patch(`/alerts/${id}/read`);
export const markAllAlertsRead = () => api.patch("/alerts/mark-all-read");
export const getVulnerabilities = (params) => api.get("/vulnerabilities/", { params });
export const getVulnRollup = (params) => api.get("/vulnerabilities/rollup", { params });
export const getScanChanges = (id, params) => api.get(`/changes/scans/${id}`, { params });
export const getChanges = (params) => api.get("/changes/", { params });
export const setFindingTriage = (data) => api.post("/vulnerabilities/triage", data);
export const getHiddenFindings = (params) => api.get("/vulnerabilities/hidden-count", { params });
export const getVulnSummary = (params) => api.get("/vulnerabilities/summary", { params });
export const createTarget = (data) => api.post("/targets/", data);
export const updateTargetTags = (id, tags) => api.put(`/targets/${id}/tags`, { tags });
export const deleteTarget = (id) => api.delete(`/targets/${id}`);
export const updateDirbusterToggle = (id, enabled) => api.patch(`/targets/${id}/dirbuster-toggle`, { dirbuster_enabled: enabled });
export const triggerScan = (data) => api.post("/scans/", data);
export const getScanProfiles = () => api.get("/scans/profiles");
export const updateTargetProfile = (id, profile) => api.patch(`/targets/${id}/profile`, { default_profile: profile });
export const cancelScan = (id) => api.patch(`/scans/${id}/cancel`);
export const getScanProgress = (id) => api.get(`/scans/${id}/progress`);

export default api;

export const getScanAssets = (id) => api.get(`/scans/${id}/assets`);

export const downloadScanReport = (id) =>
  api.get(`/scans/${id}/report`, { responseType: "blob" });

export const getSchedules = () => api.get("/schedules/");
export const createSchedule = (data) => api.post("/schedules/", data);
export const toggleSchedule = (id) => api.patch(`/schedules/${id}/toggle`);
export const deleteSchedule = (id) => api.delete(`/schedules/${id}`);

export const downloadAssetsCsv = (id) =>
  api.get(`/scans/${id}/export/assets.csv`, { responseType: "blob" });

export const downloadVulnerabilitiesCsv = (id) =>
  api.get(`/scans/${id}/export/vulnerabilities.csv`, { responseType: "blob" });

// name: assets.csv | vulnerabilities.csv | vulnerabilities.json | vulnerabilities.sarif
export const downloadScanExport = (id, name) =>
  api.get(`/scans/${id}/export/${name}`, { responseType: "blob" });

export const getExposureSources = (targetId) => api.get(`/exposure/targets/${targetId}/sources`);
export const setExposureSources = (targetId, sources) => api.put(`/exposure/targets/${targetId}/sources`, { sources });
export const runExposureNow = (targetId) => api.post(`/exposure/targets/${targetId}/run`);
export const getExposureFindings = (params) => api.get("/exposure/findings", { params });
export const setExposureFindingStatus = (id, status) => api.patch(`/exposure/findings/${id}`, { status });
export const getExposureRuns = (params) => api.get("/exposure/runs", { params });
