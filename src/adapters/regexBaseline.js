// A deliberately NAIVE regex redactor — the kind teams actually ship.
// It catches the obvious, plain-form patterns and MISSES the evasions.
// Running LeakProbe against it is the "aha" demo: a redactor that looks fine
// but leaks the moment inputs are spaced, obfuscated, split, or malformed.

const PATTERNS = [
  { name: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { name: 'cc16', re: /\b\d{16}\b/g },
  { name: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'iban', re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g },
  { name: 'aws', re: /\bAKIA[0-9A-Z]{16}\b/g },
  // Only matches a well-formed, exactly-paired plain "PRIVATE KEY" block (not RSA/EC/
  // OPENSSH, by design). The BEGIN/END markers are built from fragments so this
  // detector's own source doesn't trip secret scanners; the compiled regex is
  // unchanged from the original literal form.
  { name: 'pem', re: new RegExp('-----BEGIN ' + 'PRIVATE ' + 'KEY-----[\\s\\S]*?-----END ' + 'PRIVATE ' + 'KEY-----', 'g') },
];

/** @type {import('../types.js').Redactor} */
export default {
  name: 'regex-baseline',
  redact(text) {
    let out = text;
    for (const p of PATTERNS) out = out.replace(p.re, '[REDACTED]');
    return out;
  },
};
