// LeakProbe adversarial corpus v1.
// Every value here is FAKE / published-example data — safe to commit.
// The "sensitive" array lists the exact spans that must be removed or masked.
// If a span survives verbatim in the redactor's output, that payload LEAKED.
//
// This corpus is the product's moat: it encodes evasions that naive redactors miss
// (spacing, obfuscation, malformed/truncated keys, locale-specific identifiers).
//
// Secret-shaped values come from ./_fixtures.js (assembled from fragments so no
// real-looking literal sits in source and trips secret scanners). PII values below
// (IBAN, card, email, SSN, phone, CIN) are not credentials and stay inline.

import {
  AWS_AKID, OPENAI_FULL, OPENAI_SPLIT_A, OPENAI_SPLIT_B, GHP_PAT, JWT,
  PEM_BODY1, PEM_WELLFORMED, PEM_TRUNCATED, PEM_MISMATCHED,
} from './_fixtures.js';

/** @type {import('../types.js').Payload[]} */
export const PII_CORPUS = [
  // ---------- IBAN ----------
  {
    id: 'iban-plain-01',
    category: 'iban',
    technique: 'plain',
    input: 'Please wire the refund to GB33BUKB20201555555555 before Friday.',
    sensitive: ['GB33BUKB20201555555555'],
  },
  {
    id: 'iban-spaced-01',
    category: 'iban',
    technique: 'spaced',
    input: 'Account IBAN: GB33 BUKB 2020 1555 5555 55 — thanks.',
    sensitive: ['GB33 BUKB 2020 1555 5555 55'],
    note: 'Group-of-4 spacing defeats \\b[A-Z]{2}\\d{2}[A-Z0-9]+\\b style regexes.',
  },
  {
    id: 'iban-ma-plain-01',
    category: 'iban',
    technique: 'locale_morocco',
    input: 'RIB du client: MA64011519000001205000534921.',
    sensitive: ['MA64011519000001205000534921'],
    note: 'Moroccan IBAN (MA + 26). Many EN-centric detectors ignore MA.',
  },
  {
    id: 'iban-ma-spaced-01',
    category: 'iban',
    technique: 'locale_morocco_spaced',
    input: 'Virement vers MA64 0115 1900 0001 2050 0053 4921 svp.',
    sensitive: ['MA64 0115 1900 0001 2050 0053 4921'],
  },

  // ---------- Credit card ----------
  {
    id: 'cc-plain-01',
    category: 'credit_card',
    technique: 'plain',
    input: 'Card charged: 4111111111111111 exp 12/29.',
    sensitive: ['4111111111111111'],
  },
  {
    id: 'cc-spaced-01',
    category: 'credit_card',
    technique: 'spaced',
    input: 'Card on file 4111 1111 1111 1111, cvv omitted.',
    sensitive: ['4111 1111 1111 1111'],
  },
  {
    id: 'cc-dashed-01',
    category: 'credit_card',
    technique: 'dashed',
    input: 'PAN 4111-1111-1111-1111 declined.',
    sensitive: ['4111-1111-1111-1111'],
  },

  // ---------- Email ----------
  {
    id: 'email-plain-01',
    category: 'email',
    technique: 'plain',
    input: 'Contact the patient at jane.doe@example.com for results.',
    sensitive: ['jane.doe@example.com'],
  },
  {
    id: 'email-obfuscated-01',
    category: 'email',
    technique: 'obfuscated',
    input: 'Reach me at jane.doe [at] example [dot] com anytime.',
    sensitive: ['jane.doe [at] example [dot] com'],
    note: 'Human-readable but defeats @/. based email regexes.',
  },

  // ---------- US SSN ----------
  {
    id: 'ssn-dashed-01',
    category: 'us_ssn',
    technique: 'dashed',
    input: 'SSN on record: 123-45-6789.',
    sensitive: ['123-45-6789'],
  },
  {
    id: 'ssn-spaced-01',
    category: 'us_ssn',
    technique: 'spaced',
    input: 'Social 123 45 6789 verified.',
    sensitive: ['123 45 6789'],
  },

  // ---------- Phone ----------
  {
    id: 'phone-us-01',
    category: 'phone',
    technique: 'plain',
    input: 'Call back on +1 (415) 555-0132.',
    sensitive: ['+1 (415) 555-0132'],
  },
  {
    id: 'phone-ma-01',
    category: 'phone',
    technique: 'locale_morocco',
    input: 'Numéro du client: +212 6 12 34 56 78.',
    sensitive: ['+212 6 12 34 56 78'],
  },
  {
    id: 'phone-ma-local-01',
    category: 'phone',
    technique: 'locale_morocco_local',
    input: 'Tel: 0612345678 (whatsapp).',
    sensitive: ['0612345678'],
  },

  // ---------- Moroccan national ID (CIN) ----------
  {
    id: 'cin-ma-01',
    category: 'ma_cin',
    technique: 'locale_morocco',
    input: 'CIN du titulaire: AB123456.',
    sensitive: ['AB123456'],
    note: 'Moroccan CIN: 1–2 letters + 6 digits. Rarely covered by default detectors.',
  },

  // ---------- API keys / tokens (all FAKE or AWS published example) ----------
  {
    id: 'aws-key-plain-01',
    category: 'aws_access_key',
    technique: 'plain',
    input: `export AWS_ACCESS_KEY_ID=${AWS_AKID}`,
    sensitive: [AWS_AKID],
    note: 'AWS documented EXAMPLE key — safe, non-live.',
  },
  {
    id: 'openai-key-fake-01',
    category: 'api_key',
    technique: 'plain',
    input: `OPENAI_API_KEY=${OPENAI_FULL}`,
    sensitive: [OPENAI_FULL],
    note: 'Fabricated, clearly fake token.',
  },
  {
    id: 'openai-key-split-01',
    category: 'api_key',
    technique: 'split',
    input: `key starts ${OPENAI_SPLIT_A} and ends ${OPENAI_SPLIT_B}`,
    sensitive: [OPENAI_SPLIT_A, OPENAI_SPLIT_B],
    note: 'Secret split across the sentence defeats single-token matchers.',
  },
  {
    id: 'github-pat-fake-01',
    category: 'api_key',
    technique: 'plain',
    input: `GH_TOKEN=${GHP_PAT}`,
    sensitive: [GHP_PAT],
  },
  {
    id: 'jwt-fake-01',
    category: 'jwt',
    technique: 'plain',
    input: `Authorization: Bearer ${JWT}`,
    sensitive: [JWT],
  },

  // ---------- Private keys (PEM) — all FAKE bodies ----------
  {
    id: 'pem-wellformed-01',
    category: 'pem_private_key',
    technique: 'plain',
    input: PEM_WELLFORMED,
    sensitive: [PEM_BODY1],
  },
  {
    id: 'pem-truncated-footer-01',
    category: 'pem_private_key',
    technique: 'truncated_footer',
    input: PEM_TRUNCATED,
    sensitive: [PEM_BODY1],
    note: 'No END line. Regexes anchored on BEGIN...END miss the whole block.',
  },
  {
    id: 'pem-mismatched-footer-01',
    category: 'pem_private_key',
    technique: 'mismatched_footer',
    input: PEM_MISMATCHED,
    sensitive: [PEM_BODY1],
    note: 'BEGIN says "RSA PRIVATE KEY", END says "PRIVATE KEY" — footer mismatch breaks pair-matching.',
  },
];

export default PII_CORPUS;
