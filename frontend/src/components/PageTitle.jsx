import { useEffect } from "react";
import { useLocation } from "react-router-dom";

const TITLES = {
  "/": "Overview", "/targets": "Targets", "/scans": "Scans", "/assets": "Assets", "/schedules": "Schedules",
  "/changes": "Changes", "/vulnerabilities": "Vulnerabilities", "/alerts": "Alerts",
  "/exposure": "Exposure", "/users": "Users", "/account": "Account",
};

// Keeps the browser tab title in step with the page, so several tabs stay distinguishable.
export default function PageTitle() {
  const { pathname } = useLocation();
  useEffect(() => {
    document.title = `${TITLES[pathname] || "Not found"} · ASM Platform`;
  }, [pathname]);
  return null;
}
