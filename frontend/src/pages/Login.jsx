import { useEffect, useState } from "react";
import { login, getSetupStatus, setupAccount, mfaVerify } from "../api";
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
  const [challenge, setChallenge] = useState(null);     // { token } while the second step is pending
  const [otp, setOtp] = useState("");

  useEffect(() => { getSetupStatus().then(r => setSetup(!!r.data.needs_setup)).catch(() => {}); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (setup && password !== confirm) { setError("The two passwords do not match."); return; }
    setLoading(true);
    try {
      if (challenge) {
        await mfaVerify(challenge.token, otp);
      } else if (setup) {
        await setupAccount({ setup_code: code, username, password });
      } else {
        const r = await login(username, password);
        if (r.data?.mfa_required) { setChallenge({ token: r.data.mfa_token }); setOtp(""); return; }
      }
      resetRole();
      onLogin();
    } catch (err) {
      const status = err.response?.status;
      setError(challenge ? (status === 429 ? "Too many attempts. Wait a few minutes and try again."
        : status === 401 ? "That code is wrong or the sign-in expired. Check the code, or start again."
        : "Could not verify the code.") : !err.response ? "Cannot reach the server. Check that the API is running."
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
        {challenge ? (
          <>
            <p className="login-note">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
            <label className="login-field">
              <span>Code</span>
              <input value={otp} onChange={e => setOtp(e.target.value)} autoComplete="one-time-code" inputMode="text" spellCheck="false" autoFocus required />
            </label>
          </>
        ) : (<>
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
        </>)}
        {error && <div className="login-error" role="alert">{error}</div>}
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? (challenge ? "Checking..." : setup ? "Creating..." : "Signing in...") : (challenge ? "Verify" : setup ? "Create admin account" : "Sign in")}
        </button>
        {challenge && <button type="button" className="btn btn-secondary" onClick={() => { setChallenge(null); setOtp(""); setPassword(""); setError(""); }}>Start again</button>}
      </form>
    </div>
  );
}
