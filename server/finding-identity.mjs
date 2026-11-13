function resourceForFinding(finding) {
  const raw = finding.affected_resource ?? finding.url ?? "";
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    parsed.hash = "";
    // Query parameters can contain user data or tokens and should not be part
    // of the finding identity. Keep the path because it identifies the asset.
    parsed.search = "";
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return String(raw).split(/[?#]/, 1)[0].trim();
  }
}

export function findingIdentity(finding) {
  return `${finding.check_key}\u0000${resourceForFinding(finding)}`;
}
