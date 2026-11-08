const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const MASK = '[REDACTED]';

/** Strips control/bidi/zero-width characters and collapses whitespace. */
export function cleanText(input: string): string {
  return input.replace(CONTROL_CHARS, ' ').replace(/\s{2,}/g, ' ').trim();
}

const RULES: ReadonlyArray<readonly [RegExp, (match: string) => string]> = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*/g, () => `-----BEGIN PRIVATE KEY----- ${MASK}`],
  [/\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g, () => `eyJ****.${MASK}`],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, (m) => `${m.slice(0, 4)}************${MASK}`],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, (m) => `${m.slice(0, 4)}****${MASK}`],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, () => `github_pat_****${MASK}`],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, () => `xox*-****${MASK}`],
  [/\bsk-[A-Za-z0-9_-]{20,}/g, () => `sk-****${MASK}`],
  [
    /\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)+\b/g,
    (m) => {
      const at = m.indexOf('@');
      return `${m.slice(0, 1)}***${m.slice(at)}`;
    },
  ],
  [/\b\d{3}-\d{2}-\d{4}\b/g, (m) => `***-**-${m.slice(-4)}`],
  [/\b(?:\d[ -]?){13,19}\b/g, (m) => `****${m.replace(/\D/g, '').slice(-4)}`],
  [
    /[A-Za-z0-9_+=-]{32,}/g,
    (m) => (/\d/.test(m) && /[A-Za-z]/.test(m) ? `${m.slice(0, 4)}…${MASK}` : m),
  ],
];

/**
 * Defense-in-depth: masks anything that still looks like a credential or PII
 * even though the backend is expected to have redacted it already.
 */
export function redactText(input: string): string {
  let out = input;
  for (const [pattern, replacer] of RULES) {
    out = out.replace(pattern, replacer);
  }
  return out;
}

export function sanitizePreview(input: string, max = 240): string {
  const bounded = input.length > max * 4 ? input.slice(0, max * 4) : input;
  const redacted = redactText(cleanText(bounded));
  return redacted.length > max ? `${redacted.slice(0, max - 1)}…` : redacted;
}
