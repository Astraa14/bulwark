import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

function deriveKey(raw) {
  // Accept any length; derive a stable 32-byte key.
  return createHash("sha256").update(raw).digest();
}

/**
 * Key ring. New writes always use BULWARK_ENCRYPTION_KEY; decryption also
 * tries BULWARK_ENCRYPTION_KEY_OLD (comma-separated) so a key can be rotated
 * without losing already-encrypted credentials.
 */
function encryptionKeys() {
  const primary = String(process.env.BULWARK_ENCRYPTION_KEY ?? "").trim();
  const old = String(process.env.BULWARK_ENCRYPTION_KEY_OLD ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return [primary, ...old].filter(Boolean).map(deriveKey);
}

function key() {
  const keys = encryptionKeys();
  if (!keys.length) throw new Error("Missing BULWARK_ENCRYPTION_KEY in .env.local");
  return keys[0];
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

  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const body = Buffer.from(bodyB64, "base64");
  let lastError = null;

  for (const candidate of encryptionKeys()) {
    try {
      const decipher = createDecipheriv("aes-256-gcm", candidate, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError ?? new Error("Missing BULWARK_ENCRYPTION_KEY in .env.local");
}

/** Safe display form: keeps enough to recognise a key, never enough to use it. */
export function maskSecret(secret) {
  const s = String(secret ?? "");
  if (s.length <= 8) return "••••••••";
  return `${s.slice(0, 4)}••••••••${s.slice(-4)}`;
}
