#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { runProbe } from './runner.js';
import { summarize, formatHuman, toReportObject } from './report.js';
import { loadBuiltinCorpus } from './corpus/index.js';

const HELP = `leakprobe — prove where PII/secret redaction leaks

USAGE
  leakprobe run --target <adapter> [options]

OPTIONS
  --target <path>     Adapter module to test. Must export a redactor:
                        export default { name, redact(text) { ... } }
                      or a bare function:  export default (text) => redacted
                      or:  export function redact(text) { ... }
  --corpus <path>     Custom corpus (.js exporting default [], or .json array).
                      Defaults to the built-in adversarial corpus.
  --category <name>   Only run payloads in this category (e.g. iban, pem_private_key).
  --json              Emit a machine-readable JSON report instead of text.
  --threshold <pct>   CI mode: exit 1 if the leak rate exceeds this percent.
  -h, --help          Show this help.

EXAMPLES
  leakprobe run --target examples/my-adapter.js
  leakprobe run --target src/adapters/regexBaseline.js --json
  leakprobe run --target ./myredactor.js --threshold 0     # fail on ANY leak`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--json') args.json = true;
    else if (a === '--target') args.target = argv[++i];
    else if (a === '--corpus') args.corpus = argv[++i];
    else if (a === '--category') args.category = argv[++i];
    else if (a === '--threshold') args.threshold = Number(argv[++i]);
    else if (a.startsWith('--')) { /* ignore unknown flag */ }
    else args._.push(a);
  }
  return args;
}

async function loadRedactor(target) {
  const abs = resolve(process.cwd(), target);
  const mod = await import(pathToFileURL(abs).href);
  const def = mod.default;
  if (def && typeof def.redact === 'function') return def;
  if (typeof def === 'function') return { name: target, redact: def };
  if (typeof mod.redact === 'function') return { name: mod.name || target, redact: mod.redact };
  throw new Error(
    'target must export a redactor: `export default { name, redact }`, a function, or `export function redact(text)`'
  );
}

async function loadCorpus(corpusPath) {
  if (!corpusPath) return loadBuiltinCorpus();
  const abs = resolve(process.cwd(), corpusPath);
  if (abs.endsWith('.json')) {
    return JSON.parse(await readFile(abs, 'utf8'));
  }
  const mod = await import(pathToFileURL(abs).href);
  return mod.default || mod.corpus || mod.PII_CORPUS;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];

  if (args.help || !cmd || cmd === 'help') {
    console.log(HELP);
    process.exit(args.help || cmd === 'help' ? 0 : 1);
  }
  if (cmd !== 'run') {
    console.error(`Unknown command: ${cmd}\n`);
    console.log(HELP);
    process.exit(1);
  }
  if (!args.target) {
    console.error('Error: --target <adapter> is required.\n');
    console.log(HELP);
    process.exit(1);
  }

  let redactor;
  try {
    redactor = await loadRedactor(args.target);
  } catch (e) {
    console.error(`Failed to load target: ${e.message}`);
    process.exit(2);
  }

  let corpus;
  try {
    corpus = await loadCorpus(args.corpus);
  } catch (e) {
    console.error(`Failed to load corpus: ${e.message}`);
    process.exit(2);
  }

  if (args.category) corpus = corpus.filter((p) => p.category === args.category);
  if (!corpus.length) {
    console.error('No payloads to run (check --category / --corpus).');
    process.exit(2);
  }

  const results = await runProbe(redactor, corpus);
  const summary = summarize(results);

  if (args.json) {
    console.log(JSON.stringify(toReportObject(redactor, results, summary), null, 2));
  } else {
    console.log(formatHuman(redactor, results, summary));
  }

  if (typeof args.threshold === 'number' && !Number.isNaN(args.threshold)) {
    if (summary.leakRate * 100 > args.threshold) process.exit(1);
  }
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
