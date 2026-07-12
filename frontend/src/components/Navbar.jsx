import { Link, useLocation } from "react-router-dom";
import { Shield, Target, Activity, Database } from "lucide-react";

export default function Navbar() {
  const location = useLocation();

  const links = [
    { path: "/", label: "Dashboard", icon: <Shield size={18} /> },
    { path: "/targets", label: "Targets", icon: <Target size={18} /> },
    { path: "/scans", label: "Scans", icon: <Activity size={18} /> },
    { path: "/assets", label: "Assets", icon: <Database size={18} /> },
  ];

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Shield size={24} />
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
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}