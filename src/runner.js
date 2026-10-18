/**
 * Run every payload through the redactor and detect leaks.
 * A payload LEAKS if any of its `sensitive` spans survives verbatim in the output.
 *
 * @param {import('./types.js').Redactor} redactor
 * @param {import('./types.js').Payload[]} corpus
 * @returns {Promise<import('./types.js').ProbeResult[]>}
 */
export async function runProbe(redactor, corpus) {
  const results = [];
  for (const p of corpus) {
    let output = p.input;
    let error = null;
    try {
      const r = await redactor.redact(p.input);
      output = typeof r === 'string' ? r : String(r);
    } catch (e) {
      error = e && e.message ? e.message : String(e);
    }

    const leakedSpans = [];
    if (!error) {
      for (const s of p.sensitive) {
        if (output.includes(s)) leakedSpans.push(s);
      }
    }

    results.push({
      id: p.id,
      category: p.category,
      technique: p.technique,
      leaked: leakedSpans.length > 0,
      leakedSpans,
      error,
      input: p.input,
      output,
    });
  }
  return results;
}
