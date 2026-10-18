# LeakProbe

**Does your LLM redaction layer actually stop secrets? Most don't. Prove it.**

Teams put a redactor in front of their LLM (Microsoft Presidio, LLM Guard, a cloud guardrail, home-grown regex) to strip sensitive data — then *trust* it. Independent benchmarks already measure how well these tools catch **PII**. Almost nobody checks whether **secrets** get through: the API keys, tokens, connection strings and private keys that end up in prompts via pasted stack traces, env dumps and config blobs.

LeakProbe is a vendor-neutral, adversarial harness focused on exactly that — **secret leakage** (with PII coverage alongside) — so you can prove to an auditor, a customer, or yourself that credentials don't reach the model.

It is **not** a guardrail. It tests the one you already use.

> Status: `0.1.0` MVP. Zero runtime dependencies. ESM, Node ≥ 20.

## Quick start

```bash
# See a naive redactor leak against the built-in adversarial corpus:
node src/cli.js run --target src/adapters/regexBaseline.js

# Test your own redaction (library or API):
node src/cli.js run --target ./my-adapter.js

# CI mode — fail the build on any leak:
node src/cli.js run --target ./my-adapter.js --threshold 0 --json
```

## Write an adapter

An adapter is any module that turns text into redacted text:

```js
// my-adapter.js
export default {
  name: 'my-redactor',
  async redact(text) {
    // call your library or redaction API, return the redacted string
    return myRedact(text);
  },
};
```

Point LeakProbe at a running HTTP service instead:

```js
import { createHttpRedactor } from '@roshcompanylabs/leakprobe';
export default createHttpRedactor({
  name: 'presidio',
  url: 'http://localhost:3000/anonymize',
  buildBody: (t) => JSON.stringify({ text: t }),
  extract: (j) => j.text,
});
```

## How it scores

Each corpus payload carries the exact sensitive span(s) that must be removed or masked. If a span survives **verbatim** in the output, that payload **leaked**. LeakProbe reports a per-category leak rate and lists every failing case so you can reproduce it.

The corpus targets the evasions naive redactors miss: spacing, obfuscation, values split across a sentence, malformed/truncated private keys, and locale-specific identifiers (including MENA/Moroccan formats).

## What it is not (yet)

CLI + report only. No dashboard, no hosted service, no partial-mask scoring. Those belong in a later "LeakProbe Cloud" tier, not the MVP.

## Legal

Test only redaction you are allowed to test — open-source tools, your own services and accounts, or APIs whose terms permit it. Some commercial APIs restrict benchmarking or publishing named results; check each target's terms before publishing a named comparison. LeakProbe performs no DRM/auth/paywall bypass; it only sends test text to a redactor you point it at.

## License

MIT (provisional — the corpus licensing may be revisited).

— ROSH Company Labs
