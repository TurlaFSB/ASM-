import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { getUnreadAlerts, getMe } from "../api";
import { Sun, Moon, Monitor, Shield, Target, Activity, Database, Bell, AlertTriangle, LogOut, Clock, GitCompare, Radar, Users, Settings } from "lucide-react";
import { getThemePref, setThemePref } from "../lib/theme";
import ChangePassword from "./ChangePassword";
import turlaLogo from "../assets/TURLA.png";

export default function Navbar({ onLogout }) {
  const location = useLocation();
  const [unread, setUnread] = useState(0);
  const [role, setRole] = useState(null);
  const [username, setUsername] = useState("");
  const [pwOpen, setPwOpen] = useState(false);
  const [theme, setTheme] = useState(getThemePref);
  const pickTheme = (t) => { setTheme(t); setThemePref(t); };

  useEffect(() => { getMe().then(r => { setRole(r.data.role); setUsername(r.data.username); }).catch(() => {}); }, []);
  useEffect(() => {
    const open = () => setPwOpen(true);
    window.addEventListener("asm:change-password", open);
    return () => window.removeEventListener("asm:change-password", open);
  }, []);

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
    { path: "/exposure", label: "Exposure", icon: <Radar size={18} /> },
    { path: "/alerts", label: "Alerts", icon: <Bell size={18} /> },
    ...(role === "admin" ? [{ path: "/users", label: "Users", icon: <Users size={18} /> }] : []),
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
        {role === "viewer" && (
          <p className="nav-readonly" title="Viewer accounts can look at everything but cannot change anything.">Read-only account</p>
        )}
        <div className="theme-seg" role="group" aria-label="Appearance">
          {[["light", Sun, "Light"], ["system", Monitor, "Match system"], ["dark", Moon, "Dark"]].map(([v, Icon, label]) => (
            <button key={v} type="button" className={theme === v ? "active" : ""} aria-pressed={theme === v} aria-label={label} title={label} onClick={() => pickTheme(v)}>
              <Icon size={15} />
            </button>
          ))}
        </div>
        {username && (
          <Link to="/account" className="account-btn" title="Password and API tokens" aria-label={`Signed in as ${username}. Account settings`}
            aria-current={location.pathname === "/account" ? "page" : undefined}>
            <span className="account-name">{username}</span>
            <Settings size={15} className="account-key" />
          </Link>
        )}
        <ChangePassword open={pwOpen} onClose={() => setPwOpen(false)} />
        <button className="logout-btn" onClick={onLogout}>
          <LogOut size={16} />
          Logout
        </button>
        <div className="build-stamp" title="When this frontend build was made">Build {__BUILD_TIME__}</div>
      </div>
    </nav>
  );
}
