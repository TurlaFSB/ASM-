import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { getUnreadAlerts } from "../api";
import { Shield, Target, Activity, Database, Bell, AlertTriangle, LogOut, Clock, GitCompare } from "lucide-react";
import turlaLogo from "../assets/TURLA.png";

export default function Navbar({ onLogout }) {
  const location = useLocation();
  const [unread, setUnread] = useState(0);

  // Unread alert count: refreshed every minute, on navigation, and right after alerts are read.
  useEffect(() => {
    let live = true;
    const load = () => getUnreadAlerts({ limit: 100 }).then(r => live && setUnread(r.data.length)).catch(() => {});
    load();
    const timer = setInterval(load, 60000);
    window.addEventListener("asm:alerts-changed", load);
    return () => { live = false; clearInterval(timer); window.removeEventListener("asm:alerts-changed", load); };
  }, [location.pathname]);

  const links = [
    { path: "/", label: "Dashboard", icon: <Shield size={18} /> },
    { path: "/targets", label: "Targets", icon: <Target size={18} /> },
    { path: "/scans", label: "Scans", icon: <Activity size={18} /> },
    { path: "/assets", label: "Assets", icon: <Database size={18} /> },
    { path: "/schedules", label: "Schedules", icon: <Clock size={18} /> },
    { path: "/changes", label: "Changes", icon: <GitCompare size={18} /> },
    { path: "/vulnerabilities", label: "Vulnerabilities", icon: <AlertTriangle size={18} /> },
    { path: "/alerts", label: "Alerts", icon: <Bell size={18} /> },
  ];

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <img src={turlaLogo} alt="Turla" style={{ width: 52, height: 52, borderRadius: '50%', objectFit: 'cover' }} />
        <span>ASM Platform</span>
      </div>
      <ul className="navbar-links">
        {links.map(link => (
          <li key={link.path}>
            <Link
              to={link.path}
              className={location.pathname === link.path ? "active" : ""}
            >
              {link.icon}
              {link.label}
              {link.path === "/alerts" && unread > 0 && (
                <span className="nav-badge" aria-label={`${unread} unread alerts`}>{unread > 99 ? "99+" : unread}</span>
              )}
            </Link>
          </li>
        ))}
      </ul>
      <div className="navbar-footer">
        <button className="logout-btn" onClick={onLogout}>
          <LogOut size={16} />
          Logout
        </button>
      </div>
    </nav>
  );
}
