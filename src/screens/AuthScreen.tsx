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
          type="button"
          className="button auth-github"
          onClick={signInWithGithub}
          disabled={githubBusy}
        >
          <svg
            className="auth-github-icon"
            viewBox="0 0 24 24"
            fill="currentColor"
            aria-hidden="true"
          >
            <path
              fillRule="evenodd"
              clipRule="evenodd"
              d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2Z"
            />
          </svg>
          <span>{githubBusy ? "Redirecting…" : "Sign in with GitHub"}</span>
        </button>

        <p className="auth-foot">Bring your own AI key · No token markup · Free to start</p>
      </div>
    </div>
  );
}
