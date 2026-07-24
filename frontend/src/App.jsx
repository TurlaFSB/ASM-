import { useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Scans from "./pages/Scans";
import Assets from "./pages/Assets";
import Alerts from "./pages/Alerts";
import Vulnerabilities from "./pages/Vulnerabilities";
import Schedules from "./pages/Schedules";
import Login from "./pages/Login";
import "./App.css";

export default function App() {
  const [authed, setAuthed] = useState(!!localStorage.getItem("token"));

  if (!authed) return <Login onLogin={() => setAuthed(true)} />;

  return (
    <BrowserRouter>
      <div className="app">
        <Navbar onLogout={() => { localStorage.removeItem("token"); setAuthed(false); }} />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/schedules" element={<Schedules />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
