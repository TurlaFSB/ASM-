import axios from 'axios';

const API = axios.create({
  baseURL: 'http://192.168.16.130:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getTargets = () => API.get('/targets/');
export const createTarget = (data) => API.post('/targets/', data);
export const deleteTarget = (id) => API.delete(`/targets/${id}`);
export const triggerScan = (target_id) => API.post('/scans/', { target_id });
export const getScans = () => API.get('/scans/');
export const getScan = (id) => API.get(`/scans/${id}`);
export const getScanAssets = (id) => API.get(`/scans/${id}/assets`);

export default API;
