// Generic HTTP adapter factory. Wire LeakProbe to any redaction API
// (e.g. a Microsoft Presidio server, AWS Bedrock Guardrails proxy, your own service).
//
// Usage (in your own adapter file):
//   import { createHttpRedactor } from '@roshcompanylabs/leakprobe';
//   export default createHttpRedactor({
//     name: 'presidio',
//     url: 'http://localhost:3000/anonymize',
//     buildBody: (t) => JSON.stringify({ text: t, anonymizers: {} }),
//     extract: (j) => j.text,
//   });

/**
 * @param {Object} opts
 * @param {string} opts.url
 * @param {string} [opts.name]
 * @param {string} [opts.method]
 * @param {Record<string,string>} [opts.headers]
 * @param {(text:string)=>string} [opts.buildBody]
 * @param {(json:any)=>string} [opts.extract]
 * @returns {import('../types.js').Redactor}
 */
export function createHttpRedactor({
  url,
  name = 'http',
  method = 'POST',
  headers = {},
  buildBody = (t) => JSON.stringify({ text: t }),
  extract = (j) => (j && (j.redacted ?? j.text ?? j.output)) ?? j,
}) {
  if (!url) throw new Error('createHttpRedactor: `url` is required');
  return {
    name,
    async redact(text) {
      const res = await fetch(url, {
        method,
        headers: { 'content-type': 'application/json', ...headers },
        body: buildBody(text),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      const ct = res.headers.get('content-type') || '';
      const data = ct.includes('json') ? await res.json() : await res.text();
      const out = typeof data === 'string' ? data : extract(data);
      return typeof out === 'string' ? out : JSON.stringify(out);
    },
  };
}
