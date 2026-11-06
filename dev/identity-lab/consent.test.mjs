import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ConsentError, RECEIPT_SCHEMA, SERVICE_CATALOG,
  publicConsentCatalog, requireSession, validateConsentRequest,
  recordLocalConsent, listLocalConsents, removeLocalConsent,
} from './consent.mjs';
import { ISSUER } from './security.mjs';

const T = Date.parse('2026-11-06T22:00:00Z');
const createSession = (sub = 'test-subject') => ({
  profile: { authenticated: true, issuer: ISSUER, sub },
  expires: T + 12 * 60_000,
});
const req = (service = 'phimail') => ({
  service, scopes: ['profile.basic.read'], acknowledged: true,
});

test('only declared future integrations appear; no connection claim', () => {
  const catalog = publicConsentCatalog();
  assert.equal(catalog.length, 2);
  assert.deepEqual(new Set(Object.keys(SERVICE_CATALOG)), new Set(['phimail','phicloud']));
  for (const entry of catalog) {
    assert.equal(entry.connected, false);
    assert.equal(entry.enforced, false);
    assert.deepEqual(entry.available_scopes, ['profile.basic.read']);
  }
});

test('acknowledgment and exact allowlisted scopes are required', () => {
  assert.deepEqual(validateConsentRequest(req('phimail')).scopes, ['profile.basic.read']);
  const invalid = [
    null, {}, [], 'phimail',
    { ...req(), acknowledged: false },
    { ...req(), acknowledged: 'true' },
    { ...req(), service: '__proto__' },
    { ...req(), service: 'phios' },
    { ...req(), scopes: [] },
    { ...req(), scopes: ['profile.basic.read', 'profile.basic.read'] },
    { ...req(), scopes: ['files.write'] },
    { ...req(), scopes: ['profile.basic.read', 'vault.*'] },
    { ...req(), password: 'nope' },
  ];
  for (const item of invalid) {
    assert.throws(() => validateConsentRequest(item), ConsentError);
  }
});

test('unauthenticated, mismatched issuer and expired identity cannot create grants', () => {
  const s = createSession();
  for (const invalid of [
    undefined, {}, { ...s, profile: { authenticated: false } },
    { ...s, profile: { authenticated: true, issuer: 'https://attacker.test', sub: 'sub' } },
    { ...s, expires: T - 1 },
  ]) {
    assert.throws(() => requireSession(invalid, T), ConsentError);
    assert.throws(() => recordLocalConsent(invalid, req(), T), ConsentError);
  }
});

test('receipt is session-bound display evidence, never access authority', () => {
  const s = createSession();
  const receipt = recordLocalConsent(s, req('phicloud'), T);
  assert.equal(receipt.schema, RECEIPT_SCHEMA);
  assert.equal(receipt.service, 'phicloud');
  assert.deepEqual(receipt.requested_scopes, ['profile.basic.read']);
  assert.deepEqual(receipt.subject, { issuer: ISSUER, sub: 'test-subject' });
  assert.equal(receipt.connected, false);
  assert.equal(receipt.authority_granted, false);
  assert.equal(receipt.service_called, false);
  assert.equal(receipt.status, 'recorded_not_enforced');
  assert.equal(receipt.previous_receipt_replaced, false);
  assert.equal(listLocalConsents(s, T).length, 1);
  assert.equal(listLocalConsents(createSession('another-user'), T).length, 0);
});

test('receipt replacement and removal are explicit, isolated and reversible', () => {
  const s = createSession();
  const a = recordLocalConsent(s, req('phimail'), T);
  const b = recordLocalConsent(s, req('phimail'), T + 1000);
  assert.notEqual(a.receipt_id, b.receipt_id);
  assert.equal(b.previous_receipt_replaced, true);
  assert.equal(listLocalConsents(s, T + 1000).length, 1);
  const result = removeLocalConsent(s, 'phimail', T + 2000);
  assert.equal(result.removed, true);
  assert.equal(result.connection_revoked, false);
  assert.equal(result.external_token_revoked, false);
  assert.equal(listLocalConsents(s, T + 2000).length, 0);
  assert.equal(removeLocalConsent(s, 'phimail', T + 3000).removed, false);
});

test('records expire at or before the current session expiry', () => {
  const s = createSession();
  const receipt = recordLocalConsent(s, req('phimail'), T);
  assert.ok(Date.parse(receipt.expires_at) <= s.expires);
  assert.equal(listLocalConsents(s, s.expires - 1).length, 1);
  assert.throws(() => listLocalConsents(s, s.expires), ConsentError);
});
