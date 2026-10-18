// Type definitions (JSDoc) for LeakProbe. Plain ESM JS — no build step.
// Migrating to TypeScript later is straightforward; the shapes below are the contract.

/**
 * A single adversarial test case.
 * @typedef {Object} Payload
 * @property {string} id         Unique id, e.g. "iban-spaced-01".
 * @property {string} category   Data class, e.g. "iban", "pem_private_key".
 * @property {string} technique  Evasion technique, e.g. "plain", "spaced", "truncated_footer".
 * @property {string} input      The full text fed to the redactor.
 * @property {string[]} sensitive  Substrings that MUST NOT survive verbatim in the output.
 *                                 If any survives, the case is a LEAK.
 * @property {string} [note]     Optional human note explaining the trick.
 */

/**
 * A redaction target. `redact` takes raw text and returns the redacted text.
 * @typedef {Object} Redactor
 * @property {string} name
 * @property {(text: string) => (string | Promise<string>)} redact
 */

/**
 * Result for one payload.
 * @typedef {Object} ProbeResult
 * @property {string} id
 * @property {string} category
 * @property {string} technique
 * @property {boolean} leaked
 * @property {string[]} leakedSpans   Which sensitive substrings survived.
 * @property {string|null} error      Adapter error, if any (counts as inconclusive, not a pass).
 * @property {string} input
 * @property {string} output
 */

export {};
