import { useState } from "react";
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
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import ToastProvider from "./components/Toast";
import ErrorBoundary from "./components/ErrorBoundary";
import PageTitle from "./components/PageTitle";
import "./App.css";

export default function App() {
  const [authed, setAuthed] = useState(!!localStorage.getItem("token"));

  if (!authed) return <Login onLogin={() => setAuthed(true)} />;

  return (
    <BrowserRouter>
      <ToastProvider>
      <PageTitle />
      <div className="app">
        <Navbar onLogout={() => { localStorage.removeItem("token"); setAuthed(false); }} />
        <main className="main-content">
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
            <Route path="*" element={<NotFound />} />
          </Routes>
          </ErrorBoundary>
        </main>
      </div>
      </ToastProvider>
    </BrowserRouter>
  );
}
