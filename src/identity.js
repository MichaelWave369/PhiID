// PhiID R0 account METADATA contract. These values are NEVER credentials.
// No token issuance, JWT verification, OIDC discovery, or authentication happens here.

export const SCHEMA_VERSION = 'phi-account/0.1';
const ACCOUNT_FIELDS = [
  'schema_version', 'issuer', 'sub', 'preferred_username', 'email', 'email_verified'
];

export const DEMO_ACCOUNT = Object.freeze({
  schema_version: SCHEMA_VERSION,
  issuer: 'https://example.invalid/phiid',
  sub: 'demo-subject-369-not-an-account',
  preferred_username: 'field-explorer',
  email: null,
  email_verified: false,
});

function isHttpsIssuer(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && Boolean(url.hostname) &&
      !url.username && !url.password && !url.search && !url.hash &&
      !url.pathname.includes('/../') && !url.pathname.includes('/./');
  } catch {
    return false;
  }
}

export function validatePreviewAccount(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('account must be a plain object');
  }
  const keys = Object.keys(value).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...ACCOUNT_FIELDS].sort())) {
    throw new TypeError('account contract contains missing or extra fields');
  }
  if (value.schema_version !== SCHEMA_VERSION) {
    throw new TypeError('unsupported account metadata schema');
  }
  if (!isHttpsIssuer(value.issuer)) {
    throw new TypeError('account issuer must be an HTTPS URL without credentials/query/fragment');
  }
  if (typeof value.sub !== 'string' || value.sub.length < 1 ||
      value.sub.length > 255 || /[\u0000-\u001f\u007f]/.test(value.sub)) {
    throw new TypeError('invalid opaque account subject');
  }
  if (typeof value.preferred_username !== 'string' ||
      value.preferred_username.length < 1 || value.preferred_username.length > 64 ||
      /[\u0000-\u001f\u007f]/.test(value.preferred_username)) {
    throw new TypeError('invalid preferred username');
  }
  if (value.email !== null &&
      (typeof value.email !== 'string' || value.email.length > 254 ||
       !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.email))) {
    throw new TypeError('invalid optional email address');
  }
  if (typeof value.email_verified !== 'boolean' || 
      (value.email === null && value.email_verified)) {
    throw new TypeError('invalid email verification metadata');
  }
  return Object.freeze({ ...value });
}

/**
 * Identity is the pair (issuer, sub), not mutable email or username.
 * This returns a comparison key ONLY; an unverified JSON object never proves identity.
 */
export function previewIdentityKey(account) {
  const accepted = validatePreviewAccount(account);
  return JSON.stringify([accepted.issuer, accepted.sub]);
}

export function createDemoExport(account) {
  const accepted = validatePreviewAccount(account);
  return {
    kind: 'phiid-preview-export-only',
    authentic_identity_proof: false,
    warning: 'Synthetic metadata only. This file cannot authenticate any PhiOS service.',
    account: accepted,
  };
}
