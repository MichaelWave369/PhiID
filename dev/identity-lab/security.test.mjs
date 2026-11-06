import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ORIGIN, ISSUER, CLIENT_ID, REDIRECT_URI, randomOpaqueId,
  parseCookies, cookieHeader, isLocalRequest, isSameOriginMutation,
  publicProfile, pruneExpired, containsUnsafePath, isSameOriginAction,
  assertLoopbackProviderMetadata,
} from './security.mjs';

test('identity lab endpoints are fixed loopback addresses', () => {
  assert.equal(ORIGIN, 'http://127.0.0.1:8786');
  assert.equal(ISSUER, 'http://127.0.0.1:8080/realms/phiid-dev');
  assert.equal(CLIENT_ID, 'phiid-bff-dev');
  assert.equal(REDIRECT_URI, 'http://127.0.0.1:8786/auth/callback');
});

test('opaque IDs are high entropy and URL-safe', () => {
  const first = randomOpaqueId();
  const second = randomOpaqueId();
  assert.match(first, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first, second);
});

test('accept only unambiguous HttpOnly session cookie shapes', () => {
  const cookie = randomOpaqueId();
  const parsed = parseCookies(`ignored=foo; phiid_flow=${cookie}; phiid_session=bad; phiid_flow=duplicate`);
  assert.equal(parsed.get('phiid_flow'), cookie);
  assert.equal(parsed.has('phiid_session'), false);
  assert.match(cookieHeader('phiid_flow', cookie, 300), /HttpOnly; SameSite=Lax/);
  assert.throws(() => cookieHeader('junk', cookie, 300));
  assert.throws(() => cookieHeader('phiid_flow', 'abc', 300));
  assert.throws(() => cookieHeader('phiid_flow', cookie, -1));
});

test('reject DNS rebinding and non-loopback peers', () => {
  const req = { headers: { host: '127.0.0.1:8786' }, socket: { remoteAddress: '127.0.0.1' } };
  assert.equal(isLocalRequest(req), true);
  assert.equal(isLocalRequest({ ...req, headers: { host: 'malicious.example:8786' } }), false);
  assert.equal(isLocalRequest({ ...req, socket: { remoteAddress: '192.168.1.20' } }), false);
});

test('cross-origin logout mutations are rejected', () => {
  const good = {
    headers: { origin: ORIGIN, 'x-phiid-action': 'logout', 'sec-fetch-site': 'same-origin' }
  };
  assert.equal(isSameOriginMutation(good), true);
  assert.equal(isSameOriginMutation({ headers: { ...good.headers, origin: 'https://evil.invalid' } }), false);
  assert.equal(isSameOriginMutation({ headers: { ...good.headers, 'x-phiid-action': 'wrong' } }), false);
  assert.equal(isSameOriginMutation({ headers: { ...good.headers, 'sec-fetch-site': 'cross-site' } }), false);
});

test('profile redacts secrets, email and extra token claims', () => {
  const user = publicProfile({ sub: 'opaque', preferred_username: 'Explorer', email: 'secret@local.test',
    email_verified: true, access_token: 'secret', roles: ['admin'] });
  assert.deepEqual(Object.keys(user).sort(), [
    'authenticated','email_verified','environment','issuer','preferred_username','sub'
  ].sort());
  assert.equal(user.sub, 'opaque');
  assert.equal(user.email_verified, true);
  assert.equal(user.access_token, undefined);
  assert.throws(() => publicProfile({ sub: '' }));
});

test('prune stale state without disturbing active entries', () => {
  const m = new Map([['old', { expires: 99 }], ['new', { expires: 200 }]]);
  pruneExpired(m, 100);
  assert.deepEqual([...m.keys()], ['new']);
});

test('deny encoded/path traversal in static requests', () => {
  for (const path of ['/PhiID/%2e%2e', '/PhiID/../secrets', '/PhiID/a\\b']) {
    assert.equal(containsUnsafePath(path), true);
  }
  assert.equal(containsUnsafePath('/PhiID/assets/index-123.js'), false);
});

test('consent mutations require exact same origin and action', () => {
  const base = { headers: {
    origin: ORIGIN, 'x-phiid-action': 'consent', 'sec-fetch-site': 'same-origin'
  }};
  assert.equal(isSameOriginAction(base, 'consent'), true);
  assert.equal(isSameOriginAction(base, 'revoke'), false);
  assert.equal(isSameOriginAction(base, 'unknown'), false);
  assert.equal(isSameOriginAction({ headers: { ...base.headers, origin: 'http://evil.invalid' } }, 'consent'), false);
  assert.equal(isSameOriginAction({ headers: { ...base.headers, 'sec-fetch-site': 'cross-site' } }, 'consent'), false);
});

test('OIDC discovery endpoints must stay inside the expected loopback realm', () => {
  const good = {
    issuer: ISSUER,
    authorization_endpoint: ISSUER + '/protocol/openid-connect/auth',
    token_endpoint: ISSUER + '/protocol/openid-connect/token',
    jwks_uri: ISSUER + '/protocol/openid-connect/certs'
  };
  assert.equal(assertLoopbackProviderMetadata(good), true);
  for (const invalid of [
    { ...good, issuer: 'http://attacker.invalid' },
    { ...good, jwks_uri: 'http://attacker.invalid/keys' },
    { ...good, token_endpoint: 'http://127.0.0.1:8081/realms/phiid-dev/protocol/openid-connect/token' },
    { ...good, authorization_endpoint: 'http://localhost:8080/realms/phiid-dev/protocol/openid-connect/auth' },
    { ...good, jwks_uri: ISSUER + '/protocol/openid-connect/certs?redirect=https://evil.invalid' },
    { ...good, token_endpoint: 'https://127.0.0.1:8080/realms/phiid-dev/protocol/openid-connect/token' }
  ]) assert.throws(() => assertLoopbackProviderMetadata(invalid));
});
