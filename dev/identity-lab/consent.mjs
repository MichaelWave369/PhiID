/**
 * PhiID R2 local-only, non-authoritative consent receipt contract.
 *
 * A receipt is an ephemeral record of a user's choice inside an already
 * VERIFIED local development identity session. It is not an OAuth grant,
 * token, account linkage, service permission, delegation or resource access.
 */
import { randomOpaqueId, ISSUER, SESSION_TTL_MS } from './security.mjs';

export const RECEIPT_SCHEMA = 'phiid.local-consent-receipt/0.1';
export const CONSENT_VERSION = 'local-consent/0.1';
export const SERVICE_CATALOG = Object.freeze({
  phimail: Object.freeze({
    name: 'PhiMail',
    purpose: 'Remember that I reviewed the proposed PhiMail identity profile integration.',
    scopes: Object.freeze(['profile.basic.read']),
    status: 'not_connected',
  }),
  phicloud: Object.freeze({
    name: 'PhiCloud',
    purpose: 'Remember that I reviewed the proposed PhiCloud identity profile integration.',
    scopes: Object.freeze(['profile.basic.read']),
    status: 'not_connected',
  }),
});

export class ConsentError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'ConsentError';
    this.status = status;
  }
}

export function publicConsentCatalog() {
  return Object.entries(SERVICE_CATALOG).map(([service, spec]) => ({
    service,
    name: spec.name,
    purpose: spec.purpose,
    available_scopes: [...spec.scopes],
    connected: false,
    enforced: false,
    schema: CONSENT_VERSION,
  }));
}

export function validateConsentRequest(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ConsentError('invalid_consent_request');
  }
  if (Object.keys(payload).sort().join(',') !== 'acknowledged,scopes,service') {
    throw new ConsentError('invalid_consent_request_fields');
  }
  if (typeof payload.service !== 'string' ||
      !Object.hasOwn(SERVICE_CATALOG, payload.service)) {
    throw new ConsentError('unsupported_service');
  }
  if (payload.acknowledged !== true) {
    throw new ConsentError('explicit_acknowledgment_required');
  }
  if (!Array.isArray(payload.scopes) || payload.scopes.length === 0 ||
      payload.scopes.length > 4 ||
      new Set(payload.scopes).size !== payload.scopes.length) {
    throw new ConsentError('invalid_scopes');
  }
  const allowed = SERVICE_CATALOG[payload.service].scopes;
  if (!payload.scopes.every(s => typeof s === 'string' && allowed.includes(s))) {
    throw new ConsentError('scope_not_offered');
  }
  return Object.freeze({ service: payload.service, scopes: [...payload.scopes].sort() });
}

export function requireSession(session, now = Date.now()) {
  if (!session || !session.profile || session.profile.authenticated !== true ||
      session.profile.issuer !== ISSUER ||
      typeof session.profile.sub !== 'string' || !session.profile.sub ||
      !Number.isFinite(session.expires) || session.expires <= now) {
    throw new ConsentError('verified_local_session_required', 401);
  }
  return session;
}

export function recordLocalConsent(session, payload, now = Date.now()) {
  requireSession(session, now);
  const approved = validateConsentRequest(payload);
  const expires = Math.min(session.expires, now + SESSION_TTL_MS);
  const previous = session.consents instanceof Map
    ? session.consents.get(approved.service)
    : undefined;

  const receipt = Object.freeze({
    schema: RECEIPT_SCHEMA,
    receipt_id: randomOpaqueId(),
    service: approved.service,
    consent_version: CONSENT_VERSION,
    subject: Object.freeze({
      issuer: session.profile.issuer,
      sub: session.profile.sub,
    }),
    requested_scopes: Object.freeze([...approved.scopes]),
    purpose: SERVICE_CATALOG[approved.service].purpose,
    recorded_at: new Date(now).toISOString(),
    expires_at: new Date(expires).toISOString(),
    status: 'recorded_not_enforced',
    connected: false,
    authority_granted: false,
    service_called: false,
    previous_receipt_replaced: Boolean(previous),
  });
  if (!(session.consents instanceof Map)) session.consents = new Map();
  session.consents.set(approved.service, receipt);
  return receipt;
}

export function listLocalConsents(session, now = Date.now()) {
  requireSession(session, now);
  if (!(session.consents instanceof Map)) return [];
  for (const [service, receipt] of session.consents) {
    if (Date.parse(receipt.expires_at) <= now) session.consents.delete(service);
  }
  return [...session.consents.values()];
}

export function removeLocalConsent(session, service, now = Date.now()) {
  requireSession(session, now);
  if (!Object.hasOwn(SERVICE_CATALOG, service)) {
    throw new ConsentError('unsupported_service');
  }
  const deleted = session.consents instanceof Map && session.consents.delete(service);
  return {
    service,
    removed: Boolean(deleted),
    connection_revoked: false,
    external_token_revoked: false,
    note: 'Only a temporary local consent record was removed. No external access existed.',
  };
}
