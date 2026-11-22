import { useEffect, useState, type FormEvent } from "react";
import { KEY_PROVIDERS } from "@/lib/scanOutcomes";
import { createSite, scanSiteNow, verifySite, type SiteRow } from "@/lib/workspace";
import { Button, Dot } from "./Ui";

export function Modal({
  type,
  close,
  onChanged,
  onAddKey,
  initialSite,
}: {
  type: "site" | "key";
  close: () => void;
  onChanged: () => void;
  onAddKey?: (input: { provider: string; key: string; label?: string; model?: string }) => Promise<unknown>;
  initialSite?: SiteRow | null;
}) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [close]);
  const [step, setStep] = useState<"form" | "verify" | "done">(initialSite ? "verify" : "form");
  const [domain, setDomain] = useState("");
  const [site, setSite] = useState<SiteRow | null>(initialSite ?? null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [method, setMethod] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [provider, setProvider] = useState<keyof typeof KEY_PROVIDERS>("openai");
  const [keyValue, setKeyValue] = useState("");
  const [keyLabel, setKeyLabel] = useState("");
  const [keyModel, setKeyModel] = useState<string>(KEY_PROVIDERS.openai.model);

  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setError("Could not access the clipboard. Select the value and copy manually.");
    }
  };

  if (type === "key") {
    const submitKey = async (e: FormEvent) => {
      e.preventDefault();
      if (!onAddKey || busy) return;
      setBusy(true);
      setError(null);
      try {
        await onAddKey({
          provider,
          key: keyValue,
          label: keyLabel.trim() || undefined,
          model: keyModel.trim() || undefined,
        });
        onChanged();
        close();
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setBusy(false);
      }
    };

    return (
      <div className="modal-wrap">
        <button type="button" className="modal-scrim" onClick={close} aria-label="Close" />
        <div className="modal card" role="dialog" aria-modal="true" aria-labelledby="modal-key-title">
          <div className="modal-head">
            <div>
              <h2 id="modal-key-title">Add an API key</h2>
              <p>Keys are encrypted server-side and never returned to the browser.</p>
            </div>
            <button type="button" className="modal-close" onClick={close} aria-label="Close">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/></svg>
            </button>
          </div>
          <form onSubmit={submitKey}>
            <label>Provider</label>
            <select
              value={provider}
              onChange={(e) => {
                const next = e.target.value as keyof typeof KEY_PROVIDERS;
                setProvider(next);
                setKeyModel(KEY_PROVIDERS[next].model);
              }}
            >
              {Object.entries(KEY_PROVIDERS).map(([id, info]) => (
                <option value={id} key={id}>
                  {info.label}
                </option>
              ))}
            </select>
            <label>Secret key</label>
            <input
              type="password"
              value={keyValue}
              onChange={(e) => setKeyValue(e.target.value)}
              placeholder={KEY_PROVIDERS[provider].placeholder}
              autoComplete="off"
              autoFocus
            />
            <label>Label (optional)</label>
            <input
              value={keyLabel}
              onChange={(e) => setKeyLabel(e.target.value)}
              placeholder="Production"
            />
            <label>Model</label>
            <input value={keyModel} onChange={(e) => setKeyModel(e.target.value)} />
            {error && <p className="modal-error">{error}</p>}
            <Button type="submit" dark disabled={busy}>{busy ? "Saving…" : "Save key"}</Button>
            <p className="modal-note">
              Used only for explanations and workspace briefs you request. Bulwark cannot read the
              key back — it can only decrypt it on the server to call your provider.
            </p>
          </form>
        </div>
      </div>
    );
  }

  const submitDomain = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createSite(domain);
      setSite(created);
      setStep("verify");
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (!site || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await verifySite(site.id);
      setMethod(res.method);
      setStep("done");
      onChanged();
      scanSiteNow(site.id).then(onChanged).catch(() => undefined);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-wrap">
      <button type="button" className="modal-scrim" onClick={close} aria-label="Close" />
      <div className="modal card" role="dialog" aria-modal="true" aria-labelledby="modal-site-title">
        <div className="modal-head">
          <div>
            <h2 id="modal-site-title">{step === "form" ? "Add a site" : step === "verify" ? "Prove you own it" : "Site connected"}</h2>
            <p>
              {step === "form"
                ? "Connect a domain to begin monitoring."
                : step === "verify"
                  ? "Add one of these records, then verify."
                  : "Bulwark will scan it within a minute."}
            </p>
          </div>
          <button type="button" className="modal-close" onClick={close} aria-label="Close">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"/></svg>
          </button>
        </div>

        {step === "form" && (
          <form onSubmit={submitDomain}>
            <label>Domain</label>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              autoFocus
            />
            {error && <p className="modal-error">{error}</p>}
            <Button type="submit" dark disabled={busy}>{busy ? "Adding…" : "Continue"}</Button>
            <p className="modal-note">
              Next you will prove ownership with a DNS record or a meta tag. Only add sites you
              control — Bulwark refuses to scan a domain you have not verified.
            </p>
          </form>
        )}

        {step === "verify" && site && (
          <>
            <p className="modal-note">
              Choose one method. DNS is fastest, but records can take a few minutes to propagate.
            </p>
            <div className="verify-box">
              <small>OPTION 1 — DNS TXT RECORD</small>
              <div className="code-line">
                <code>_bulwark.{site.domain}</code>
                <button type="button" onClick={() => copy("dns", `_bulwark.${site.domain}`)}>
                  {copied === "dns" ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="code-line">
                <code className="token">{site.verify_token}</code>
                <button type="button" onClick={() => copy("token", site.verify_token)}>
                  {copied === "token" ? "Copied" : "Copy"}
                </button>
              </div>
              <ol className="verify-steps">
                <li>In your DNS provider, add a <code>TXT</code> record at the name above.</li>
                <li>Paste the token as its value, with nothing else in the record.</li>
                <li>Wait for propagation, then press Verify now.</li>
              </ol>
            </div>
            <div className="verify-box">
              <small>OPTION 2 — HTML META TAG IN THE HOMEPAGE &lt;HEAD&gt;</small>
              <div className="code-line">
                <code className="token">{`<meta name="bulwark-verify" content="${site.verify_token}" />`}</code>
                <button
                  type="button"
                  onClick={() =>
                    copy("meta", `<meta name="bulwark-verify" content="${site.verify_token}" />`)
                  }
                >
                  {copied === "meta" ? "Copied" : "Copy"}
                </button>
              </div>
              <ol className="verify-steps">
                <li>Paste the tag into the <code>&lt;head&gt;</code> of your homepage's HTML.</li>
                <li>
                  Deploy it so the live page serves the tag. Bulwark reads the HTML your server
                  sends, so a tag injected by JavaScript will not be found.
                </li>
                <li>Press Verify now.</li>
              </ol>
            </div>
            {error && <p className="modal-error">{error}</p>}
            <div className="modal-actions">
              <Button dark onClick={verify} disabled={busy}>
                {busy ? "Checking…" : "Verify now"}
              </Button>
              <Button onClick={close} disabled={busy}>Later</Button>
            </div>
          </>
        )}

        {step === "done" && (
          <div className="success">
            <Dot />
            <h2>Verified via {method === "dns" ? "DNS TXT" : "meta tag"}</h2>
            <p>Monitoring has started. The first scan is running now.</p>
            <Button dark onClick={close}>
              Done
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
