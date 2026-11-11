import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

function key() {
  const raw = process.env.BULWARK_ENCRYPTION_KEY;
  if (!raw) throw new Error("Missing BULWARK_ENCRYPTION_KEY in .env.local");
  // Accept any length; derive a stable 32-byte key.
  return createHash("sha256").update(raw).digest();
}

/** AES-256-GCM. Format: v1:<iv>:<tag>:<ciphertext> (base64 segments). */
export function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const body = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  return [
    "v1",
    iv.toString("base64"),
    cipher.getAuthTag().toString("base64"),
    body.toString("base64"),
  ].join(":");
}

export function decrypt(blob) {
  const [version, ivB64, tagB64, bodyB64] = String(blob ?? "").split(":");
  if (version !== "v1" || !ivB64 || !tagB64 || !bodyB64) {
    throw new Error("Stored key is not in a readable format.");
  }
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(bodyB64, "base64")), decipher.final()]).toString(
    "utf8",
  );
}

/** Safe display form: keeps enough to recognise a key, never enough to use it. */
export function maskSecret(secret) {
  const s = String(secret ?? "");
  if (s.length <= 8) return "••••••••";
  return `${s.slice(0, 4)}••••••••${s.slice(-4)}`;
}
