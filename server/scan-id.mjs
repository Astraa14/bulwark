import { createHash } from "node:crypto";

/**
 * Stable scan identity.
 *
 * A scan UUID belongs to one logical scan job. Retrying that job reuses the
 * same UUID; a new scan (next due slot, new manual request, new delivery) gets
 * a new UUID. Values are derived with UUIDv5 so the same slot always maps to
 * the same UUID without storing extra state.
 *
 * Never derive a scan id from user/connection/resource/commit strings: those
 * are not UUIDs and the scans/platform_scan_jobs columns are `uuid`.
 */

export const SCAN_ID_NAMESPACE = "6f1c2b8a-3d4e-5f60-9a1b-2c3d4e5f6a7b";
export const IDEMPOTENCY_NAMESPACE = "b2d4f6a8-1c3e-5f70-8a9b-0c1d2e3f4a5b";

export const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** RFC 4122 §4.3 UUIDv5 (SHA-1, name-based). */
export function uuidv5(name, namespace) {
  if (!UUID_RE.test(String(namespace ?? ""))) {
    throw new Error("uuidv5 namespace must be a UUID.");
  }

  const hash = createHash("sha1");
  hash.update(Buffer.from(namespace.replace(/-/g, ""), "hex"));
  hash.update(Buffer.from(String(name), "utf8"));

  const bytes = hash.digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytes.subarray(0, 16).toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

/**
 * Identity for one website scan slot. The slot is the site's `next_scan_at`
 * when the scan was claimed; retries of that slot reuse both values, while the
 * next slot produces a new pair.
 */
export function websiteScanIdentity({ siteId, slot }) {
  if (!siteId) throw new Error("websiteScanIdentity requires a siteId.");
  const base = `${siteId}|${slot ?? ""}`;
  return {
    scanId: uuidv5(base, SCAN_ID_NAMESPACE),
    idempotencyKey: uuidv5(base, IDEMPOTENCY_NAMESPACE),
  };
}

export function assertScanId(value) {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new Error("scanId must be a UUID.");
  }
  return value;
}