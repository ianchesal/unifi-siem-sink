export function stripEnvelope(raw: string): string | null {
  const idx = raw.indexOf('CEF:');
  if (idx === -1) return null;
  return raw.slice(idx);
}
