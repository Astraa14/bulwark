import { useState } from "react";
import { Button, Dot, PageTitle } from "@/components/Ui";
import { relTime, shortDate, type ApiKeyRow } from "@/lib/workspace";

export function ApiKeys({
  openModal,
  keys,
  loading,
  error,
  onRemove,
}: {
  openModal: () => void;
  keys: ApiKeyRow[];
  loading: boolean;
  error: string | null;
  onRemove: (id: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const remove = async (id: string) => {
    if (!window.confirm("Remove this key? Explanations will stop working until you add another.")) return;
    setBusy(id);
    setLocalError(null);
    try {
      await onRemove(id);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <PageTitle
        title="API keys"
        subtitle="Bring your own intelligence. Keep control of your spend."
        action={
          <Button dark onClick={openModal}>
            + Add API key
          </Button>
        }
      />
      <div className="notice card">
        <strong>Encrypted at rest</strong>
        <span>
          Keys are encrypted with AES-256-GCM before they reach the database. The browser only ever
          sees a masked preview.
        </span>
      </div>
      {(error || localError) && <p className="modal-error">{localError ?? error}</p>}
      <div className="integration-body">
        <div className="api-grid">
          <div>
            <section className="card setting-list">
              <div className="setting-title">
                <h3>Connected providers</h3>
                <p>
                  {keys.length} active key{keys.length === 1 ? "" : "s"}. Keys are used only when
                  you ask Bulwark to explain a finding or generate a brief.
                </p>
              </div>
              {loading ? (
                <p className="muted pad">Loading keys…</p>
              ) : keys.length === 0 ? (
                <div className="key-empty">
                  <p>
                    No AI key yet. Add an OpenAI, Anthropic, or Google Gemini key to unlock
                    plain-English explanations.
                  </p>
                  <span className="key-empty-hint">
                    Use “Add API key” above. Nothing is generated until you request an explanation.
                  </span>
                </div>
              ) : (
                keys.map((k) => (
                  <div className="record" key={k.id}>
                    <div className="record-head">
                      <div className="record-title">
                        <h3>{k.providerLabel}</h3>
                        <p>
                          {k.label ?? "Key"} · {k.model}
                        </p>
                      </div>
                      <span className="record-status">
                        <Dot />
                        Connected
                      </span>
                    </div>
                    <dl className="record-facts">
                      <div>
                        <dt>Key</dt>
                        <dd>
                          <code>{k.preview}</code>
                        </dd>
                      </div>
                      <div>
                        <dt>Model</dt>
                        <dd>
                          <code>{k.model}</code>
                        </dd>
                      </div>
                      <div>
                        <dt>Added</dt>
                        <dd>{shortDate(k.createdAt)}</dd>
                      </div>
                      <div>
                        <dt>Last used</dt>
                        <dd>{relTime(k.lastUsedAt)}</dd>
                      </div>
                    </dl>
                    <div className="record-actions">
                      <Button onClick={() => remove(k.id)}>
                        {busy === k.id ? "Removing…" : "Remove key"}
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </section>
            <section className="card preferences">
              <h3>How Bulwark uses your key</h3>
              <p>Only to explain findings or briefs you explicitly request. Nothing runs automatically.</p>
              <hr />
              <div>
                <span>
                  <strong>Explanation model</strong>
                  <small>Chosen when the key is added</small>
                </span>
                <code>{keys[0]?.model ?? "—"}</code>
              </div>
              <div>
                <span>
                  <strong>Cost</strong>
                  <small>Billed directly by your provider</small>
                </span>
                <code>$0 markup</code>
              </div>
            </section>
          </div>
          <div>
            <section className="card side-setting">
              <h3>Billing</h3>
              <div>
                <span>Token markup</span>
                <code>$0</code>
              </div>
              <div>
                <span>Charged by</span>
                <code>Your provider</code>
              </div>
              <div>
                <span>Explanations</span>
                <code>Cached</code>
              </div>
              <p>Viewing a cached explanation costs nothing.</p>
            </section>
            <section className="card activity api-activity">
              <h3>Provider status</h3>
              {["OpenAI", "Anthropic", "Google Gemini"].map((name) => {
                const key = keys.find((x) => x.providerLabel === name);
                return (
                  <div key={name}>
                    <span>
                      <Dot tone={key ? "healthy" : "info"} />
                      {name}
                    </span>
                    <span>
                      <strong>{key ? key.model : "Not connected"}</strong>
                    </span>
                  </div>
                );
              })}
            </section>
          </div>
        </div>
      </div>
    </>
  );
}
