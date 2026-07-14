import axios from "axios";

const api = axios.create({
  baseURL: "http://192.168.16.130:8000"
});

api.interceptors.request.use(config => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token");
      window.location.reload();
    }
    return Promise.reject(err);
  }
);

// Named exports for all pages
export const getTargets = () => api.get("/targets/");
export const getScans = () => api.get("/scans/");
export const getAssets = () => api.get("/assets/");
export const getAlerts = () => api.get("/alerts/");
export const getUnreadAlerts = () => api.get("/alerts/unread");
export const markAlertRead = (id) => api.patch(`/alerts/${id}/read`);
export const markAllAlertsRead = () => api.patch("/alerts/mark-all-read");
export const getVulnerabilities = () => api.get("/vulnerabilities/");
export const getVulnSummary = () => api.get("/vulnerabilities/summary");
export const createTarget = (data) => api.post("/targets/", data);
export const deleteTarget = (id) => api.delete(`/targets/${id}`);
export const triggerScan = (data) => api.post("/scans/", data);
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
