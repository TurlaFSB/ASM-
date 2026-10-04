import { useEffect, useState } from "react";
import { login, getSetupStatus, setupAccount } from "../api";
import { resetRole } from "../components/useRole";
import turlaLogo from "../assets/TURLA.png";

function detail(err, fallback) {
  const d = err.response?.data?.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x.msg).join(", ");
  return fallback;
}

export default function Login({ onLogin }) {
  const [setup, setSetup] = useState(false);            // true until the first admin account exists
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => { getSetupStatus().then(r => setSetup(!!r.data.needs_setup)).catch(() => {}); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (setup && password !== confirm) { setError("The two passwords do not match."); return; }
    setLoading(true);
    try {
      if (setup) await setupAccount({ setup_code: code, username, password });
      else await login(username, password);
      resetRole();
      onLogin();
    } catch (err) {
      const status = err.response?.status;
      setError(!err.response ? "Cannot reach the server. Check that the API is running."
        : status === 429 ? "Too many attempts. Wait a few minutes and try again."
        : setup ? detail(err, "Could not create the account.")
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
          <h1>{setup ? "Set up ASM Platform" : "ASM Platform"}</h1>
        </div>
        {setup && (
          <>
            <p className="login-note">Create the first admin account. The setup code is in the backend log:
              {" "}<code>docker compose logs backend | grep "setup code"</code></p>
            <label className="login-field">
              <span>Setup code</span>
              <input value={code} onChange={e => setCode(e.target.value)} autoComplete="off" spellCheck="false" autoFocus required placeholder="xxxx-xxxx-xxxx" />
            </label>
          </>
        )}
        <label className="login-field">
          <span>Username</span>
          <input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoFocus={!setup} required />
        </label>
        <label className="login-field">
          <span>{setup ? "Password (at least 12 characters)" : "Password"}</span>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete={setup ? "new-password" : "current-password"} required />
        </label>
        {setup && (
          <label className="login-field">
            <span>Confirm password</span>
            <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="new-password" required />
          </label>
        )}
        {error && <div className="login-error" role="alert">{error}</div>}
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? (setup ? "Creating..." : "Signing in...") : (setup ? "Create admin account" : "Sign in")}
        </button>
      </form>
    </div>
  );
}
