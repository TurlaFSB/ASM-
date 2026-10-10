import { useEffect, useState } from "react";
import { getMe, logout } from "./api";
import { resetRole } from "./components/useRole";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Scans from "./pages/Scans";
import Assets from "./pages/Assets";
import Alerts from "./pages/Alerts";
import Vulnerabilities from "./pages/Vulnerabilities";
import Changes from "./pages/Changes";
import Schedules from "./pages/Schedules";
import Exposure from "./pages/Exposure";
import Account from "./pages/Account";
import Users from "./pages/Users";
import Audit from "./pages/Audit";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import ToastProvider from "./components/Toast";
import ErrorBoundary from "./components/ErrorBoundary";
import PageTitle from "./components/PageTitle";
import "./App.css";

export default function App() {
  // null = still checking the session cookie, false = show login, true = signed in
  const [authed, setAuthed] = useState(null);

  useEffect(() => {
    getMe().then(() => setAuthed(true)).catch(() => setAuthed(false));
  }, []);

  if (authed === null) return null;
  if (!authed) return <Login onLogin={() => setAuthed(true)} />;

  return (
    <BrowserRouter>
      <ToastProvider>
      <PageTitle />
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="app">
        <Navbar onLogout={() => { logout().catch(() => {}).finally(() => { resetRole(); setAuthed(false); }); }} />
        <main className="main-content" id="main" tabIndex={-1}>
          <ErrorBoundary>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/changes" element={<Changes />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/schedules" element={<Schedules />} />
            <Route path="/exposure" element={<Exposure />} />
            <Route path="/users" element={<Users />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/account" element={<Account />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
          </ErrorBoundary>
        </main>
      </div>
      </ToastProvider>
    </BrowserRouter>
  );
}
