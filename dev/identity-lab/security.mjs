import { randomBytes } from 'node:crypto';

export const ORIGIN = 'http://127.0.0.1:8786';
export const ISSUER = 'http://127.0.0.1:8080/realms/phiid-dev';
export const CLIENT_ID = 'phiid-bff-dev';
export const REDIRECT_URI = ORIGIN + '/auth/callback';
export const FLOW_TTL_MS = 5 * 60_000;
export const SESSION_TTL_MS = 15 * 60_000;

export function randomOpaqueId() {
  return randomBytes(32).toString('base64url');
}

export function parseCookies(header = '') {
  const parsed = new Map();
  for (const section of String(header).split(';')) {
    const index = section.indexOf('=');
    if (index < 0) continue;
    const name = section.slice(0, index).trim();
    const value = section.slice(index + 1).trim();
    if (!/^phiid_(flow|session)$/.test(name)) continue;
    if (!/^[A-Za-z0-9_-]{20,100}$/.test(value)) continue;
    if (!parsed.has(name)) parsed.set(name, value);
  }
  return parsed;
}

export function cookieHeader(name, value, maxAge) {
  if (!['phiid_flow', 'phiid_session'].includes(name)) throw new Error('unexpected cookie');
  if (value && !/^[A-Za-z0-9_-]{20,100}$/.test(value)) throw new Error('invalid cookie');
  if (!Number.isSafeInteger(maxAge) || maxAge < 0 || maxAge > 3600) throw new Error('invalid maxAge');
  // Intentionally no Secure attribute: this bridge is *only* HTTP loopback.
  return `${name}=${value}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

export function isLocalRequest(req) {
  const host = req.headers?.host;
  const remote = req.socket?.remoteAddress;
  return host === '127.0.0.1:8786' && (remote === '127.0.0.1' || remote === '::ffff:127.0.0.1');
}

export function isSameOriginMutation(req) {
  return req.headers?.origin === ORIGIN &&
    req.headers?.['x-phiid-action'] === 'logout' &&
    req.headers?.['sec-fetch-site'] !== 'cross-site';
}

export function publicProfile(claims) {
  if (!claims || typeof claims !== 'object' || typeof claims.sub !== 'string' ||
      claims.sub.length < 1 || claims.sub.length > 255) {
    throw new TypeError('validated OIDC subject required');
  }
  const preferred = typeof claims.preferred_username === 'string'
    ? claims.preferred_username.slice(0, 64) : null;
  return Object.freeze({
    authenticated: true,
    issuer: ISSUER,
    sub: claims.sub,
    preferred_username: preferred,
    email_verified: claims.email_verified === true,
    environment: 'local_development_only',
  });
}

export function pruneExpired(map, now = Date.now()) {
  for (const [key, value] of map.entries()) {
    if (!value || value.expires <= now) map.delete(key);
  }
}

export function containsUnsafePath(pathname) {
  return pathname.includes('%') || pathname.includes('\\') ||
    pathname.includes('..') || pathname.includes('\u0000');
}
