import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Scans from "./pages/Scans";
import Assets from "./pages/Assets";
import "./App.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/assets" element={<Assets />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
