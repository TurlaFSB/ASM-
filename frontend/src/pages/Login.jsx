import { useState } from "react";
import axios from "axios";

const API = `http://${window.location.hostname}:8000`;

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      params.append("username", username);
      params.append("password", password);
      const res = await axios.post(`${API}/auth/token`, params);
      localStorage.setItem("token", res.data.access_token);
      onLogin();
    } catch (e) {
      setError("Invalid username or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "center",
      height: "100vh", background: "var(--bg)"
    }}>
      <div style={{
        background: "var(--surface)", border: "1px solid var(--border)",
        borderRadius: "var(--radius)", padding: "40px", width: "360px"
      }}>
        <h2 style={{ marginBottom: 24, color: "var(--text-primary)" }}>ASM Platform</h2>
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 12, color: "var(--text-secondary)", display: "block", marginBottom: 6 }}>Username</label>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSubmit()}
            style={{
              width: "100%", padding: "10px 12px", background: "var(--surface-2)",
              border: "1px solid var(--border)", borderRadius: 6,
              color: "var(--text-primary)", fontSize: 14, boxSizing: "border-box"
            }}
          />
        </div>
        <div style={{ marginBottom: 24 }}>
          <label style={{ fontSize: 12, color: "var(--text-secondary)", display: "block", marginBottom: 6 }}>Password</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSubmit()}
            style={{
              width: "100%", padding: "10px 12px", background: "var(--surface-2)",
              border: "1px solid var(--border)", borderRadius: 6,
              color: "var(--text-primary)", fontSize: 14, boxSizing: "border-box"
            }}
          />
        </div>
        {error && <div style={{ color: "var(--red)", fontSize: 13, marginBottom: 16 }}>{error}</div>}
        <button
          onClick={handleSubmit}
          disabled={loading}
          style={{
            width: "100%", padding: "10px", background: "var(--accent)",
            color: "#000", border: "none", borderRadius: 6,
            fontWeight: 600, cursor: "pointer", fontSize: 14
          }}
        >
          {loading ? "Signing in..." : "Sign In"}
        </button>
      </div>
    </div>
  );
}
