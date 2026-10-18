/**
 * Aggregate probe results.
 * @param {import('./types.js').ProbeResult[]} results
 */
export function summarize(results) {
  /** @type {Record<string,{total:number,leaked:number,errors:number}>} */
  const byCategory = {};
  let leaked = 0;
  let errors = 0;
  for (const r of results) {
    const c = byCategory[r.category] || (byCategory[r.category] = { total: 0, leaked: 0, errors: 0 });
    c.total++;
    if (r.error) { c.errors++; errors++; }
    else if (r.leaked) { c.leaked++; leaked++; }
  }
  const total = results.length;
  const conclusive = total - errors;
  const leakRate = conclusive > 0 ? leaked / conclusive : 0;
  return { total, conclusive, leaked, passed: conclusive - leaked, errors, leakRate, byCategory };
}

function pct(n) { return (n * 100).toFixed(1) + '%'; }
function trunc(s, n = 44) { return s.length > n ? s.slice(0, n) + '…' : s; }

function table(header, rows) {
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  const fmt = (cols) => cols.map((c, i) => c.padEnd(widths[i])).join('  ');
  const out = [fmt(header), widths.map((w) => '-'.repeat(w)).join('  ')];
  for (const r of rows) out.push(fmt(r));
  return out.join('\n');
}

/**
 * Human-readable report.
 * @param {import('./types.js').Redactor} redactor
 * @param {import('./types.js').ProbeResult[]} results
 * @param {ReturnType<typeof summarize>} summary
 */
export function formatHuman(redactor, results, summary) {
  const lines = [];
  lines.push('');
  lines.push(`LeakProbe  ·  target: ${redactor.name}`);
  lines.push('='.repeat(52));

  const cats = Object.keys(summary.byCategory).sort();
  const rows = cats.map((c) => {
    const v = summary.byCategory[c];
    const conclusive = v.total - v.errors;
    const rate = conclusive > 0 ? v.leaked / conclusive : 0;
    return [c, String(v.total), String(v.leaked), pct(rate)];
  });
  lines.push(table(['CATEGORY', 'TOTAL', 'LEAKED', 'LEAK RATE'], rows));

  lines.push('');
  lines.push(
    `OVERALL: ${summary.leaked}/${summary.conclusive} leaked  (leak rate ${pct(summary.leakRate)})` +
      (summary.errors ? `  [${summary.errors} errored]` : '')
  );

  const fails = results.filter((r) => r.leaked);
  if (fails.length) {
    lines.push('');
    lines.push('LEAKING CASES:');
    for (const r of fails.slice(0, 40)) {
      const spans = r.leakedSpans.map((s) => JSON.stringify(trunc(s))).join(', ');
      lines.push(`  x ${r.id}  [${r.category}/${r.technique}]  survived: ${spans}`);
    }
    if (fails.length > 40) lines.push(`  ... and ${fails.length - 40} more`);
  }

  const errs = results.filter((r) => r.error);
  if (errs.length) {
    lines.push('');
    lines.push('ERRORS (inconclusive):');
    for (const r of errs.slice(0, 10)) lines.push(`  ! ${r.id}: ${r.error}`);
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Machine-readable report (for CI, dashboards, compliance export).
 */
export function toReportObject(redactor, results, summary) {
  return {
    tool: 'leakprobe',
    version: '0.1.0',
    target: redactor.name,
    summary: {
      total: summary.total,
      conclusive: summary.conclusive,
      leaked: summary.leaked,
      passed: summary.passed,
      errors: summary.errors,
      leakRate: Number(summary.leakRate.toFixed(4)),
    },
    byCategory: summary.byCategory,
    results: results.map((r) => ({
      id: r.id,
      category: r.category,
      technique: r.technique,
      leaked: r.leaked,
      leakedSpans: r.leakedSpans,
      error: r.error,
    })),
  };
}
