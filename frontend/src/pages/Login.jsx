import { useState } from "react";
import axios from "axios";
import turlaLogo from "../assets/TURLA.png";

const API = `http://${window.location.hostname}:8000`;

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      params.append("username", username);
      params.append("password", password);
      const res = await axios.post(`${API}/auth/token`, params);
      localStorage.setItem("token", res.data.access_token);
      onLogin();
    } catch (err) {
      // Distinguish "too many attempts" and "server not reachable" from a wrong password
      const status = err.response?.status;
      setError(status === 429 ? "Too many attempts. Wait a few minutes and try again."
        : !err.response ? "Cannot reach the server. Check that the API is running."
        : "Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          <img src={turlaLogo} alt="" />
          <h1>ASM Platform</h1>
        </div>
        <label className="login-field">
          <span>Username</span>
          <input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoFocus required />
        </label>
        <label className="login-field">
          <span>Password</span>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        {error && <div className="login-error" role="alert">{error}</div>}
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}
