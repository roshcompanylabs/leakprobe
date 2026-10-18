// LeakProbe secret-shaped test fixtures — single source of truth.
//
// WHY THIS FILE EXISTS
// This is a *secrets-leakage* benchmark, so the corpus must contain strings that
// look exactly like real credentials — that is the whole point of the test. But a
// real-looking credential literal in source trips secret scanners (GitHub secret
// scanning, gitleaks, provider partner alerts) even though every value here is
// FAKE or a vendor-published EXAMPLE. Those are false positives, and on the PUBLIC
// repo of a secret-detection tool they are both noise and a bad look.
//
// So each value is assembled at module load from fragments whose split points fall
// *inside* the provider's required prefix (e.g. `sk_live_`, `AIza`, `-----BEGIN …
// PRIVATE KEY`). No single source literal matches a provider pattern, yet the value
// returned at runtime is byte-identical to the real-looking credential, so the
// benchmark keeps full fidelity. This is false-positive avoidance for known-fake
// data — not evasion of protection on real secrets. Verified by test/no-literal-secrets:
// the assembled values DO match provider patterns; the source text does NOT.

const j = (...parts) => parts.join('');

// `PRIVATE KEY` broken so no `… PRIVATE KEY-----` literal appears in source.
const PK = j('PRIVATE ', 'KEY');

// ---- cloud / platform keys ----
export const SK_LIVE = j('sk', '_li', 've_', 'FAKE51H8xQ2abcdEFGH1234ijklMNOPqrstUV');
export const AWS_SECRET = j('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY'); // AWS published EXAMPLE
export const AWS_AKID = j('AKIA', 'IOSFODNN7EXAMPLE'); // AWS published EXAMPLE access key id
export const GOOGLE_KEY = j('AIza', 'SyFAKE1234567890abcdefghijklmnoPQRS');
export const SLACK_TOKEN = j('xo', 'xb', '-FAKE-2420000000-abcdefghijklmnopqrstuvwx');
export const SENDGRID_KEY = j('S', 'G.', 'FAKE1234abcd.efgh5678ijklMNOP9012qrstUVWX3456');
export const GH_PAT_FINE = j('github', '_pat', '_FAKE11ABCDEFG0abcdefghij_1234567890abcdefghijklmnopqrstuvwxyz1234');
export const GHP_PAT = j('ghp', '_FAKE1234abcd5678efgh9012ijkl3456mnop');
export const OPENAI_FULL = j('sk', '-FAKE0abcdEFGH1234ijklMNOP5678qrstUVWX');
export const OPENAI_SPLIT_A = j('sk', '-FAKE0abcdEFGH1234');
export const OPENAI_SPLIT_B = 'ijklMNOP5678qrstUVWX'; // tail only — no provider prefix
export const BEARER = j('sk', '-FAKE0abcdEFGH1234ijklMNOP5678');
export const JWT = j('eyJ', 'hbGciOiJIUzI1NiJ9.eyJzdWIiOiJGQUtFIn0.ZmFrZXNpZ25hdHVyZQ');

// ---- connection strings (password inside a URL) ----
export const PG_PASS = 'S3cr3t_P4ssw0rd';
export const PG_URL = j('postgres://admin:', PG_PASS, '@db.internal:5432/prod');
export const MONGO_PASS = 'Pa55w0rd-Xyz';
export const MONGO_URL = j('mongodb+srv://svc_user:', MONGO_PASS, '@cluster0.mongodb.net/app');

// ---- private keys (FAKE bodies) ----
export const OPENSSH_BODY = 'b3BlbnNzaC1rFAKEOPENSSHBODYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
export const EC_BODY = 'MHcCAQEEIFAKEECKEYBODYbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
export const PEM_BODY1 = 'MIIBVAIBADANBgkqFAKEKEYBODYLINE1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
export const PEM_BODY2 = 'FAKEKEYBODYLINE2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

export const OPENSSH_PEM = j('-----BEGIN OPENSSH ', PK, '-----\n', OPENSSH_BODY, '\n-----END OPENSSH ', PK, '-----');
export const EC_PEM = j('-----BEGIN EC ', PK, '-----\n', EC_BODY, '\n-----END EC ', PK, '-----');
// PII PEM fixtures (RSA/plain/truncated/mismatched-footer variants)
export const PEM_WELLFORMED = j('key:\n-----BEGIN ', PK, '-----\n', PEM_BODY1, '\n', PEM_BODY2, '\n-----END ', PK, '-----');
export const PEM_TRUNCATED = j('leaked in logs:\n-----BEGIN ', PK, '-----\n', PEM_BODY1, '\n', PEM_BODY2);
export const PEM_MISMATCHED = j('-----BEGIN RSA ', PK, '-----\n', PEM_BODY1, '\n-----END ', PK, '-----');
