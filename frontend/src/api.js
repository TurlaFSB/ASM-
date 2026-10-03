import axios from "axios";

const API_BASE = `http://${window.location.hostname}:8000`;

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
  err => {
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
export const getUnreadAlerts = (params) => api.get("/alerts/unread", { params });
export const markAlertRead = (id) => api.patch(`/alerts/${id}/read`);
export const markAllAlertsRead = () => api.patch("/alerts/mark-all-read");
export const getVulnerabilities = (params) => api.get("/vulnerabilities/", { params });
export const getVulnRollup = (params) => api.get("/vulnerabilities/rollup", { params });
export const getScanChanges = (id, params) => api.get(`/changes/scans/${id}`, { params });
export const getChanges = (params) => api.get("/changes/", { params });
export const getVulnSummary = (params) => api.get("/vulnerabilities/summary", { params });
export const createTarget = (data) => api.post("/targets/", data);
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

export const getExposureSources = (targetId) => api.get(`/exposure/targets/${targetId}/sources`);
export const setExposureSources = (targetId, sources) => api.put(`/exposure/targets/${targetId}/sources`, { sources });
export const runExposureNow = (targetId) => api.post(`/exposure/targets/${targetId}/run`);
export const getExposureFindings = (params) => api.get("/exposure/findings", { params });
export const setExposureFindingStatus = (id, status) => api.patch(`/exposure/findings/${id}`, { status });
export const getExposureRuns = (params) => api.get("/exposure/runs", { params });
