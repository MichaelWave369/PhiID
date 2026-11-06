/**
 * PhiID R1 LOCAL identity lab: verified OIDC sign-in, not a production account service.
 * Serves the built static preview and keeps ID/access tokens OUT of browser JavaScript.
 * Intentionally bound to IPv4 loopback, pinned issuer/client/redirect and no external API.
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as oidc from 'openid-client';
import {
  ORIGIN, ISSUER, CLIENT_ID, REDIRECT_URI, FLOW_TTL_MS, SESSION_TTL_MS,
  randomOpaqueId, parseCookies, cookieHeader, isLocalRequest,
  isSameOriginMutation, isSameOriginAction, assertLoopbackProviderMetadata,
  publicProfile, pruneExpired, containsUnsafePath,
} from './security.mjs';
import {
  ConsentError, publicConsentCatalog, recordLocalConsent,
  listLocalConsents, removeLocalConsent, requireSession,
} from './consent.mjs';
import {
  loadPocketApprovalConfig,stagePocketReview,approveStagedPocket
} from './pocket-approval.mjs';

const DIST = resolve(fileURLToPath(new URL('../../dist/', import.meta.url)));
const flows = new Map();
const sessions = new Map();
let configPromise;
// Optional, operator-owned LOCAL dev approval signer. Disabled by default.
const pocketConfig=process.env.PHIID_POCKET_APPROVAL_CONFIG
  ?loadPocketApprovalConfig(process.env.PHIID_POCKET_APPROVAL_CONFIG):null;

function json(res, status, obj, cookies = []) {
  const data = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(data.length),
    ...cookies.length ? { 'Set-Cookie': cookies } : {},
  });
  res.end(data);
}

function redirect(res, target, cookies = []) {
  res.writeHead(302, {
    'Location': target,
    ...cookies.length ? { 'Set-Cookie': cookies } : {},
  });
  res.end();
}

function getOidc() {
  if (!configPromise) {
    configPromise = oidc.discovery(
      new URL(ISSUER), CLIENT_ID,
      { token_endpoint_auth_method: 'none' }, oidc.None(),
      { execute: [oidc.allowInsecureRequests], timeout: 8 }, // localhost HTTP only
    ).then(config => {
      assertLoopbackProviderMetadata(config.serverMetadata());
      if (!config.serverMetadata().supportsPKCE()) throw new Error('S256 PKCE support is required');
      return config;
    }).catch(err => { configPromise = undefined; throw err; });
  }
  return configPromise;
}

function currentSession(req) {
  pruneExpired(sessions);
  const id = parseCookies(req.headers.cookie).get('phiid_session');
  return id ? sessions.get(id) : undefined;
}

async function login(res) {
  pruneExpired(flows);
  if (flows.size >= 256) {
    json(res, 429, { error: 'too_many_pending_flows' });
    return;
  }
  const config = await getOidc();
  const flowId = randomOpaqueId();
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const verifier = oidc.randomPKCECodeVerifier();
  const challenge = await oidc.calculatePKCECodeChallenge(verifier);
  flows.set(flowId, {
    state, nonce, verifier, expires: Date.now() + FLOW_TTL_MS,
  });
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  });
  redirect(res, url.href, [cookieHeader('phiid_flow', flowId, 300)]);
}

async function callback(req, res) {
  const id = parseCookies(req.headers.cookie).get('phiid_flow');
  const flow = id ? flows.get(id) : undefined;
  if (id) flows.delete(id); // one-time use even when exchange fails
  res.setHeader('Set-Cookie', cookieHeader('phiid_flow', '', 0));
  if (!flow || flow.expires <= Date.now()) {
    json(res, 400, { error: 'missing_or_expired_login_flow' });
    return;
  }
  const requested = new URL(req.url, ORIGIN);
  // Validate early, then let the audited OIDC library verify response and tokens.
  if (requested.searchParams.get('state') !== flow.state ||
      requested.searchParams.getAll('state').length !== 1 ||
      !requested.searchParams.get('code') ||
      requested.searchParams.getAll('code').length !== 1) {
    json(res, 400, { error: 'invalid_login_response' });
    return;
  }
  const config = await getOidc();
  const tokens = await oidc.authorizationCodeGrant(config, requested, {
    pkceCodeVerifier: flow.verifier,
    expectedState: flow.state,
    expectedNonce: flow.nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  if (!claims || claims.iss !== ISSUER || typeof claims.exp !== 'number') {
    json(res, 401, { error: 'identity_claims_unavailable' });
    return;
  }
  const remaining = Math.min(SESSION_TTL_MS, claims.exp * 1000 - Date.now());
  if (remaining <= 0) {
    json(res, 401, { error: 'identity_expired' });
    return;
  }
  pruneExpired(sessions);
  if (sessions.size >= 500) {
    json(res, 429, { error: 'too_many_local_sessions' });
    return;
  }
  const sessionId = randomOpaqueId();
  const profile = publicProfile(claims);
  // NEVER keep token contents in frontend JavaScript, cookies or exported JSON.
  // We discard the access token and refresh token, so this lab cannot call PhiCloud.
  sessions.set(sessionId, { profile, expires: Date.now() + remaining, createdAt:Date.now() });
  redirect(res, '/PhiID/', [
    cookieHeader('phiid_flow', '', 0),
    cookieHeader('phiid_session', sessionId, Math.max(1, Math.floor(remaining / 1000))),
  ]);
}

async function readBoundedJson(req, maxBytes = 2048) {
  if (req.headers['content-type'] !== 'application/json') {
    throw new ConsentError('json_content_type_required', 415);
  }
  if (req.headers['content-encoding'] &&
      req.headers['content-encoding'] !== 'identity') {
    throw new ConsentError('encoded_body_not_accepted', 415);
  }
  const length = req.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
    throw new ConsentError('request_body_too_large', 413);
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) throw new ConsentError('request_body_too_large', 413);
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new ConsentError('invalid_json');
  }
}

function consentSession(req) {
  return requireSession(currentSession(req));
}

const MIME = {
  js: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  html: 'text/html; charset=utf-8',
  svg: 'image/svg+xml',
  png: 'image/png',
  ico: 'image/x-icon',
};

async function staticFile(req, res, rawPath) {
  // Do not treat paths supplied by clients as filesystem paths.
  if (containsUnsafePath(rawPath)) {
    json(res, 404, { error: 'not_found' });
    return;
  }
  const name = rawPath.slice('/PhiID/'.length) || 'index.html';
  if (name !== 'index.html' && !/^assets\/[A-Za-z0-9_.-]+$/.test(name)) {
    json(res, 404, { error: 'not_found' });
    return;
  }
  const full = join(DIST, name);
  try {
    const data = await readFile(full);
    const extension = name.split('.').at(-1);
    res.writeHead(200, {
      'Content-Type': MIME[extension] || 'application/octet-stream',
      'Content-Length': String(data.length),
    });
    res.end(data);
  } catch {
    json(res, 404, { error: 'build_required_or_asset_not_found' });
  }
}

async function handle(req, res) {
  // The port is bound to loopback, and Host is separately pinned to prevent
  // DNS rebinding through hostile browser origins.
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
    "script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'");
  if (!isLocalRequest(req)) {
    json(res, 403, { error: 'loopback_only' });
    return;
  }
  const url = new URL(req.url, ORIGIN);
  const path = url.pathname;

  if (req.method === 'GET' && req.url === '/') {
    redirect(res, '/PhiID/');
  } else if (req.method === 'GET' && req.url === '/auth/session') {
    const session = currentSession(req);
    json(res, 200, session ? session.profile : { authenticated: false, environment: 'local_development_only' });
  } else if (req.method === 'GET' && req.url === '/auth/consents') {
    const session = consentSession(req);
    json(res, 200, {
      environment: 'local_development_only',
      service_calls: false,
      permissions_enforced: false,
      catalog: publicConsentCatalog(),
      receipts: listLocalConsents(session),
    });
  } else if (req.method === 'POST' && req.url === '/auth/consents') {
    if (!isSameOriginAction(req, 'consent')) {
      json(res, 403, { error: 'cross_origin_action_denied' });
      return;
    }
    const session = consentSession(req);
    const payload = await readBoundedJson(req);
    const receipt = recordLocalConsent(session, payload);
    json(res, 201, { receipt });
  } else if (req.method === 'DELETE' && /^\/auth\/consents\/(phimail|phicloud)$/.test(path) &&
             req.url === path) {
    if (!isSameOriginAction(req, 'revoke')) {
      json(res, 403, { error: 'cross_origin_action_denied' });
      return;
    }
    const session = consentSession(req);
    json(res, 200, removeLocalConsent(session, path.split('/').at(-1)));
  } else if (req.method === 'GET' && req.url === '/auth/pocket/status') {
    const s=currentSession(req);
    json(res,200,{environment:'local_development_only',enabled:!!pocketConfig,
      authenticated:s?.profile?.authenticated===true,
      permitted:!!(s&&pocketConfig&&pocketConfig.allowedSubjects.includes(s.profile.sub)),
      executionsPerformed:false});
  } else if (req.method === 'POST' && req.url === '/auth/pocket/review') {
    if(!pocketConfig){json(res,404,{error:'pocket_approval_lab_disabled'});return;}
    if(!isSameOriginAction(req,'pocket-review')){
      json(res,403,{error:'cross_origin_action_denied'});return;
    }
    const session=consentSession(req);
    const payload=await readBoundedJson(req,8192);
    json(res,200,stagePocketReview(session,payload,pocketConfig));
  } else if (req.method === 'POST' && req.url === '/auth/pocket/approve') {
    if(!pocketConfig){json(res,404,{error:'pocket_approval_lab_disabled'});return;}
    if(!isSameOriginAction(req,'pocket-approve')){
      json(res,403,{error:'cross_origin_action_denied'});return;
    }
    const session=consentSession(req);
    const payload=await readBoundedJson(req);
    json(res,200,approveStagedPocket(session,payload,pocketConfig));
  } else if (req.method === 'POST' && req.url === '/auth/pocket/cancel') {
    if(!pocketConfig){json(res,404,{error:'pocket_approval_lab_disabled'});return;}
    if(!isSameOriginAction(req,'pocket-cancel')){
      json(res,403,{error:'cross_origin_action_denied'});return;
    }
    const session=consentSession(req);
    delete session.pendingPocket;
    json(res,200,{cancelled:true,executionAuthorized:false});
  } else if (req.method === 'GET' && req.url === '/auth/login') {
    await login(res);
  } else if (req.method === 'GET' && path === '/auth/callback') {
    await callback(req, res);
  } else if (req.method === 'POST' && req.url === '/auth/logout') {
    if (!isSameOriginMutation(req)) {
      json(res, 403, { error: 'cross_origin_action_denied' });
      return;
    }
    const cookie = parseCookies(req.headers.cookie).get('phiid_session');
    if (cookie) sessions.delete(cookie);
    json(res, 200, { authenticated: false, note: 'Local bridge session ended; Keycloak SSO may remain active.' },
      [cookieHeader('phiid_session', '', 0)]);
  } else if (req.method === 'GET' && path.startsWith('/PhiID/') && !url.search && !url.hash) {
    await staticFile(req, res, path);
  } else {
    json(res, 404, { error: 'not_found' });
  }
}

if (process.env.NODE_ENV === 'production') {
  throw new Error('PhiID identity lab must never run as a production server');
}
const server = createServer((req, res) => {
  void handle(req, res).catch(err => {
    if (err instanceof ConsentError) {
      if (!res.headersSent) json(res, err.status, { error: err.message });
      else res.destroy();
      return;
    }
    // Do not log callback URLs, codes, secrets, ID tokens or user claims.
    console.error('Local OIDC lab operation failed:', err?.name || 'Error');
    if (!res.headersSent) json(res, 503, { error: 'local_identity_lab_operation_failed' });
    else res.destroy();
  });
});
server.listen(8786, '127.0.0.1', () => {
  console.log('PhiID R1 local-only identity lab: http://127.0.0.1:8786/PhiID/');
  console.log('Provider: http://127.0.0.1:8080/realms/phiid-dev');
  console.log('Development only. No PhiOS/PhiCloud authorization or production accounts.');
});
