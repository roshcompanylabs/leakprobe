// LeakProbe adapter for the real npm library `redact-pii` (OSS).
// Run from this folder:
//   node ../src/cli.js run --target ./redact-pii-adapter.js
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { SyncRedactor } = require('redact-pii');

const redactor = new SyncRedactor();

export default {
  name: 'redact-pii (npm, OSS)',
  redact(text) {
    return redactor.redact(text);
  },
};
