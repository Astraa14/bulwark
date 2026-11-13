import { useState, type FormEvent } from "react";
import { useAuth } from "@/lib/auth";

type Mode = "in" | "up";

export default function AuthScreen() {
  const { signIn, signUp, signInWithGitHub } = useAuth();
  const [mode, setMode] = useState<Mode>("in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [githubBusy, setGithubBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setError(null);
    setNotice(null);
    setBusy(true);

    const result =
      mode === "in" ? await signIn(email.trim(), password) : await signUp(email.trim(), password);

    setBusy(false);

    if (result.error) {
      setError(result.error);
      return;
    }
    if (mode === "up" && "needsConfirm" in result && result.needsConfirm) {
      setNotice("Check your inbox to confirm your email, then sign in.");
    }
  }

  async function signInWithGithub() {
    setGithubBusy(true);
    setError(null);
    try {
      const result = await signInWithGitHub();
      if (result.error) setError(result.error);
    } finally {
      setGithubBusy(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <img src="/bulwark-logo.svg" alt="Bulwark" className="auth-logo" />
        </div>
        <p className="auth-sub">External website posture monitoring for people who ship.</p>

        <div className="auth-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "in"}
            className={mode === "in" ? "active" : ""}
            onClick={() => {
              setMode("in");
              setError(null);
              setNotice(null);
            }}
          >
            Sign in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "up"}
            className={mode === "up" ? "active" : ""}
            onClick={() => {
              setMode("up");
              setError(null);
              setNotice(null);
            }}
          >
            Create account
          </button>
        </div>

        <form onSubmit={submit} noValidate>
          <label htmlFor="auth-email">Email</label>
          <input
            id="auth-email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
          />

          <label htmlFor="auth-password">Password</label>
          <input
            id="auth-password"
            type="password"
            autoComplete={mode === "in" ? "current-password" : "new-password"}
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="At least 8 characters"
          />

          {error && <p className="auth-error">{error}</p>}
          {notice && <p className="auth-notice">{notice}</p>}

          <button className="button dark auth-submit" type="submit" disabled={busy}>
            {busy ? "Please wait…" : mode === "in" ? "Sign in" : "Create account"}
          </button>
        </form>

        <hr className="auth-divider" />

        <button
          className="button auth-github"
          onClick={signInWithGithub}
          disabled={githubBusy}
          style={{
            background: "#24292e",
            color: "#fff",
            border: "1px solid rgba(255,255,255,0.2)",
            borderRadius: "6px",
            width: "100%",
            padding: "10px 16px",
            fontSize: "14px",
            fontWeight: "500",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            transition: "background 0.2s",
          }}
        >
          {githubBusy ? "Redirecting…" : "Sign in with GitHub"}
        </button>

        <p className="auth-foot">Bring your own AI key · No token markup · Free to start</p>
      </div>
    </div>
  );
}
