/** Defensive redaction: even if the backend sends a raw value, never show more than a hint. */
export function redact(value: string): string {
  const v = value.trim();
  if (v.includes("[REDACTED]") || /^\*+$/.test(v) || /•{3,}|\*{4,}/.test(v)) return v.slice(0, 120);
  if (v.length <= 4) return "****";
  const keep = Math.min(4, Math.floor(v.length / 6));
  return `${v.slice(0, keep)}${"*".repeat(8)}[REDACTED]`;
}
