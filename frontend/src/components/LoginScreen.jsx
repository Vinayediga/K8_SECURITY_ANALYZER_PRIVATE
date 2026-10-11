import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api.js";

export default function LoginScreen({ onLoggedIn, onOffline }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const googleButton = useRef(null);
  const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

  useEffect(() => {
    if (!googleClientId || !googleButton.current) return undefined;
    const render = () => {
      if (!window.google?.accounts?.id || !googleButton.current) return;
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: async ({ credential }) => {
          setError("");
          setNotice("");
          setBusy(true);
          try {
            await api.loginWithGoogle(credential);
            onLoggedIn(await api.me());
          } catch (err) {
            setError(err.message);
          } finally {
            setBusy(false);
          }
        },
      });
      googleButton.current.replaceChildren();
      window.google.accounts.id.renderButton(googleButton.current, {
        theme: "outline",
        size: "large",
        width: Math.max(240, Math.floor(googleButton.current.clientWidth)),
        text: "continue_with",
        shape: "rectangular",
        logo_alignment: "center",
      });
    };
    if (window.google?.accounts?.id) {
      render();
      return undefined;
    }
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = render;
    script.onerror = () => setError("Google sign-in could not load.");
    document.head.appendChild(script);
    return () => { script.onload = null; };
  }, [googleClientId, onLoggedIn]);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setNotice("");
    setBusy(true);
    try {
      if (mode === "register") {
        await api.register(email.trim(), password);
        setNotice("Account created. Signing you in…");
      }
      await api.login(email.trim(), password);
      onLoggedIn(await api.me());
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const input =
    "w-full rounded-lg border px-3 py-2.5 text-sm outline-none focus:ring-2";
  const inputStyle = { background: "#0a0d11", borderColor: "var(--border)", color: "var(--text)" };

  return (
    <div className="auth-shell grid min-h-screen place-items-center p-5 sm:p-8">
      <div className="auth-layout w-full">
        <aside className="auth-intro">
          <div className="auth-mark">K8</div>
          <p className="auth-kicker">KUBERNETES SECURITY</p>
          <h1>See the risk before it becomes an incident.</h1>
          <p className="auth-intro-copy">Map cluster exposure, understand attack paths, and prioritize remediation from one focused workspace.</p>
          <div className="auth-points">
            <span><b>01</b> Scan local cluster configuration</span>
            <span><b>02</b> Visualize findings and blast radius</span>
            <span><b>03</b> Track mitigation from one dashboard</span>
          </div>
        </aside>

        <form
          onSubmit={submit}
          className="auth-card space-y-6 rounded-2xl border p-7 sm:p-9"
          style={{ background: "var(--surface)", borderColor: "var(--border)", boxShadow: "var(--shadow)" }}
        >
          <div className="auth-header">
            <p className="auth-form-kicker">{mode === "login" ? "WELCOME BACK" : "GET STARTED"}</p>
            <h2 className="mt-2 text-2xl font-bold">{mode === "login" ? "Sign in to your workspace" : "Create your workspace"}</h2>
            <p className="mt-2 text-sm leading-6" style={{ color: "var(--text-dim)" }}>
              {mode === "login" ? "Use your account details to continue." : "Set up your account to start analyzing your clusters."}
            </p>
          </div>

        <div className="auth-fields">
        <label className="auth-field text-sm font-medium" style={{ color: "var(--text-dim)" }}>
          Email
          <input className={`${input} mt-3`} style={inputStyle} type="email" required autoComplete="email"
            value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="auth-field block text-sm font-medium" style={{ color: "var(--text-dim)" }}>
          Password
          <input className={`${input} mt-3`} style={inputStyle} type="password" required minLength={12} maxLength={128}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        </div>

        <div className="auth-feedback">
          {error && <p className="rounded-lg border p-3 text-sm" style={{ borderColor: "var(--risk-critical)", color: "#e8836b" }}>{error}</p>}
          {notice && <p className="text-sm" style={{ color: "#7bd88f" }}>{notice}</p>}
        </div>

        <div className="auth-submit-stack">
          <button disabled={busy} className="auth-submit rounded-lg text-base font-semibold disabled:opacity-60"
            style={{ background: "var(--accent)", color: "#0a0d11" }}>
            {busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
          </button>

          {googleClientId ? (
            <div className="google-signin" ref={googleButton} aria-label="Continue with Google" />
          ) : (
            <button
              type="button"
              className="google-signin-fallback"
              onClick={() => setError("Google sign-in is not configured. Add VITE_GOOGLE_CLIENT_ID to the frontend environment and restart the app.")}
            >
              <svg className="google-mark" viewBox="0 0 24 24" aria-hidden="true">
                <path fill="#4285F4" d="M21.35 12.23c0-.72-.06-1.42-.18-2.09H12v3.96h5.24a4.48 4.48 0 0 1-1.94 2.94v2.45h3.14c1.84-1.69 2.91-4.18 2.91-7.26Z" />
                <path fill="#34A853" d="M12 21.5c2.63 0 4.84-.87 6.45-2.36l-3.14-2.45c-.87.58-1.98.92-3.31.92-2.54 0-4.7-1.72-5.47-4.03H3.29v2.53A9.75 9.75 0 0 0 12 21.5Z" />
                <path fill="#FBBC05" d="M6.53 13.58A5.86 5.86 0 0 1 6.22 12c0-.55.11-1.08.31-1.58V7.89H3.29A9.75 9.75 0 0 0 2.25 12c0 1.57.38 3.05 1.04 4.11l3.24-2.53Z" />
                <path fill="#EA4335" d="M12 6.39c1.43 0 2.71.49 3.72 1.45l2.79-2.79C16.83 3.48 14.63 2.5 12 2.5a9.75 9.75 0 0 0-8.71 5.39l3.24 2.53C7.3 8.11 9.46 6.39 12 6.39Z" />
              </svg>
              Continue with Google
            </button>
          )}
        </div>

        <div className="auth-actions flex flex-wrap items-center justify-between gap-3 text-sm">
          <button type="button" className="rounded-lg px-1 py-1 underline underline-offset-4" style={{ color: "var(--accent)" }}
            onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}>
            {mode === "login" ? "Create an account" : "I already have an account"}
          </button>
          <button type="button" className="rounded-lg px-1 py-1 underline underline-offset-4" style={{ color: "var(--text-dim)" }} onClick={onOffline}>
            Try with sample data
          </button>
        </div>
        </form>
      </div>
    </div>
  );
}
