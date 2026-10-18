import { PII_CORPUS } from './pii.js';
import { SECRETS_CORPUS } from './secrets.js';

/** @returns {import('../types.js').Payload[]} */
export function loadBuiltinCorpus() {
  return [...SECRETS_CORPUS, ...PII_CORPUS];
}

export { PII_CORPUS, SECRETS_CORPUS };
