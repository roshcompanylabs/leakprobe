// Example custom adapter.
//   leakprobe run --target examples/my-adapter.js
//
// Replace the body of `redact` with a call to the real redaction you want to test:
// your own library, a local Presidio/LLM-Guard server, a cloud guardrail, etc.
// Return the redacted text as a string.

export default {
  name: 'my-custom-redactor',
  redact(text) {
    // Toy example: only strips plain emails. Everything else will "leak"
    // so you can see LeakProbe working against a weak target.
    return text.replace(/[\w.+-]+@[\w.-]+\.\w+/g, '[EMAIL]');
  },
};
