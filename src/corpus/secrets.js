// LeakProbe secrets corpus — the specialist focus.
// Independent PII benchmarks exist (LeakageBench, REDACT, PRvL, Limina...);
// independent SECRETS-leakage testing for text going into LLMs does not.
// These are the credentials that actually end up in prompts: pasted stack traces,
// env dumps, config blobs, "here's my error, why isn't this working" messages.
//
// Every value is FAKE or a vendor-published EXAMPLE. The secret-shaped values live in
// ./_fixtures.js, assembled from fragments so no real-looking literal sits in source
// and trips secret scanners — see that file for why. Runtime values are full-fidelity.

import {
  SK_LIVE, AWS_SECRET, GOOGLE_KEY, SLACK_TOKEN, SENDGRID_KEY, GH_PAT_FINE,
  PG_PASS, PG_URL, MONGO_PASS, MONGO_URL, OPENSSH_BODY, EC_BODY, OPENSSH_PEM, EC_PEM, BEARER,
} from './_fixtures.js';

/** @type {import('../types.js').Payload[]} */
export const SECRETS_CORPUS = [
  // ---- Cloud / platform keys ----
  {
    id: 'stripe-live-01',
    category: 'secret_stripe',
    technique: 'plain',
    input: `STRIPE_SECRET_KEY=${SK_LIVE}`,
    sensitive: [SK_LIVE],
  },
  {
    id: 'stripe-live-json-01',
    category: 'secret_stripe',
    technique: 'json_embedded',
    input: `{"env":{"STRIPE_KEY":"${SK_LIVE}"}}`,
    sensitive: [SK_LIVE],
  },
  {
    id: 'aws-secret-key-01',
    category: 'secret_aws',
    technique: 'plain',
    input: `AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`,
    sensitive: [AWS_SECRET],
    note: 'AWS documented EXAMPLE secret key — safe, non-live.',
  },
  {
    id: 'google-api-01',
    category: 'secret_google',
    technique: 'plain',
    input: `maps key: ${GOOGLE_KEY}`,
    sensitive: [GOOGLE_KEY],
  },
  {
    id: 'slack-bot-01',
    category: 'secret_slack',
    technique: 'plain',
    input: `SLACK_BOT_TOKEN=${SLACK_TOKEN}`,
    sensitive: [SLACK_TOKEN],
  },
  {
    id: 'sendgrid-01',
    category: 'secret_sendgrid',
    technique: 'plain',
    input: `SENDGRID_API_KEY=${SENDGRID_KEY}`,
    sensitive: [SENDGRID_KEY],
  },
  {
    id: 'github-fine-grained-01',
    category: 'secret_github',
    technique: 'plain',
    input: `token ${GH_PAT_FINE}`,
    sensitive: [GH_PAT_FINE],
  },

  // ---- Connection strings (password inside a URL) ----
  {
    id: 'db-postgres-01',
    category: 'secret_conn_string',
    technique: 'url_embedded',
    input: `DATABASE_URL=${PG_URL}`,
    sensitive: [PG_PASS, PG_URL],
    note: 'The password lives inside a URL — most PII redactors never look here.',
  },
  {
    id: 'mongo-srv-01',
    category: 'secret_conn_string',
    technique: 'url_embedded',
    input: MONGO_URL,
    sensitive: [MONGO_PASS],
  },

  // ---- Private keys (FAKE bodies), formats beyond RSA/PKCS8 ----
  {
    id: 'openssh-key-01',
    category: 'secret_private_key',
    technique: 'openssh',
    input: OPENSSH_PEM,
    sensitive: [OPENSSH_BODY],
  },
  {
    id: 'ec-key-01',
    category: 'secret_private_key',
    technique: 'ec',
    input: EC_PEM,
    sensitive: [EC_BODY],
  },

  // ---- Bearer token embedded in a real-looking blob ----
  {
    id: 'bearer-json-01',
    category: 'secret_bearer',
    technique: 'json_embedded',
    input: `request failed: {"headers":{"authorization":"Bearer ${BEARER}"}}`,
    sensitive: [BEARER],
  },
];

export default SECRETS_CORPUS;
