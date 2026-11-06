/**
 * Real Keycloak 26.x localhost-only integration test.
 *
 * This script intentionally uses a REAL disposable Keycloak server and
 * vetted openid-client, not an OIDC/JWT test double. It never grants remote
 * resource access or sends private credentials to any non-loopback endpoint.
 *
 * Environment: PHIID_E2E_ENABLE=1, KC_BOOTSTRAP_ADMIN_USERNAME,
 * KC_BOOTSTRAP_ADMIN_PASSWORD. Generates, then deletes, one random test user.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as oidc from 'openid-client';
import { ISSUER, ORIGIN, REDIRECT_URI } from '../identity-lab/security.mjs';

const KEYCLOAK = 'http://127.0.0.1:8080';
const MAIL_CALLBACK = 'http://127.0.0.1:5173/auth/phiid/callback';
const ADMIN = process.env.KC_BOOTSTRAP_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KC_BOOTSTRAP_ADMIN_PASSWORD;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const randomString = () => randomBytes(24).toString('hex');

if (process.env.PHIID_E2E_ENABLE !== '1' || !ADMIN || !ADMIN_PASSWORD) {
  throw new Error('Explicit localhost E2E opt-in and ephemeral admin credentials required');
}
if (process.env.NODE_ENV === 'production') throw new Error('production environment forbidden');

function checkEndpoint(value, expectedOrigin = KEYCLOAK) {
  const url = new URL(value);
  assert.equal(url.origin, expectedOrigin, 'untrusted non-loopback URL');
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.hash, '');
  return url;
}

async function waitForKeycloak() {
  for (let attempt = 0; attempt < 120; attempt++) {
    try {
      const response = await fetch(ISSUER + '/.well-known/openid-configuration', {
        signal: AbortSignal.timeout(2500),
        redirect: 'manual',
      });
      if (response.ok) {
        const metadata = await response.json();
        assert.equal(metadata.issuer, ISSUER);
        return;
      }
    } catch { /* Keycloak has not finished its initial startup. */ }
    await sleep(2000);
  }
  throw new Error('Keycloak local discovery startup timed out');
}

async function adminToken() {
  const body = new URLSearchParams({
    client_id: 'admin-cli',
    grant_type: 'password', // bootstrap admin ONLY, never an application client
    username: ADMIN,
    password: ADMIN_PASSWORD,
  });
  const response = await fetch(KEYCLOAK + '/realms/master/protocol/openid-connect/token', {
    method: 'POST', body, redirect: 'manual',
    signal: AbortSignal.timeout(8000),
  });
  assert.equal(response.status, 200, 'bootstrap admin authentication failed');
  const data = await response.json();
  assert.equal(typeof data.access_token, 'string');
  assert.ok(data.access_token.length > 100);
  return data.access_token;
}

async function adminJson(token, path, options = {}) {
  assert.match(path, /^\/admin\/realms\/phiid-dev\//);
  const response = await fetch(KEYCLOAK + path, {
    ...options, redirect: 'manual',
    headers: {
      Authorization: 'Bearer ' + token,
      ...options.body ? { 'Content-Type': 'application/json' } : {},
    },
    signal: AbortSignal.timeout(8000),
  });
  return response;
}

async function createDisposableUser(token) {
  const id = randomBytes(8).toString('hex');
  const username = 'phiid-ci-' + id;
  const password = 'CI-test!8' + randomString();
  const create = await adminJson(token, '/admin/realms/phiid-dev/users', {
    method: 'POST',
    body: JSON.stringify({
      username, enabled: true, emailVerified: true,
      email: 'ci-' + id + '@example.invalid',
      firstName: 'Phi', lastName: 'Integration-Test',
      requiredActions: [],
    }),
  });
  assert.equal(create.status, 201, 'creating disposable test user failed');
  const location = create.headers.get('location');
  assert.ok(location, 'Keycloak did not return user Location');
  const loc = checkEndpoint(location);
  assert.match(loc.pathname, /^\/admin\/realms\/phiid-dev\/users\/[a-f0-9-]{16,40}$/i);
  const userId = loc.pathname.split('/').at(-1);
  const reset = await adminJson(token, '/admin/realms/phiid-dev/users/' + userId + '/reset-password', {
    method: 'PUT',
    body: JSON.stringify({ type: 'password', value: password, temporary: false }),
  });
  assert.equal(reset.status, 204, 'disposable user password setup failed');
  return { username, password, userId };
}

function recordCookies(jar, response) {
  const all = typeof response.headers.getSetCookie === 'function'
    ? response.headers.getSetCookie()
    : [response.headers.get('set-cookie')].filter(Boolean);
  for (const raw of all) {
    const first = raw.split(';', 1)[0];
    const i = first.indexOf('=');
    if (i <= 0) continue;
    const key = first.slice(0, i).trim();
    const value = first.slice(i + 1).trim();
    if (!/^[A-Za-z0-9_.-]+$/.test(key)) continue;
    if (!value) jar.delete(key);
    else jar.set(key, value);
  }
}
function cookieValue(jar) {
  return [...jar.entries()].map(([key,value]) => key + '=' + value).join('; ');
}

function decodeHtmlAttribute(value) {
  return value.replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#(\d+);/g, (_,code)=>String.fromCharCode(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_,code)=>String.fromCharCode(parseInt(code,16)));
}

function loginFormAction(html) {
  // We intentionally parse only the Keycloak login form's action; no injected
  // browser scripts, arbitrary redirects or synthetic protocol are used.
  const forms = html.match(/<form\b[^>]*>/gi) || [];
  const tag = forms.find(item => /\bid\s*=\s*["']kc-form-login["']/i.test(item));
  assert.ok(tag, 'Keycloak did not present the expected username/password login form');
  const attr = tag.match(/\baction\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
  assert.ok(attr, 'Keycloak login form action missing');
  const action = checkEndpoint(decodeHtmlAttribute(attr[1] ?? attr[2]));
  assert.match(action.pathname, /^\/realms\/phiid-dev\/login-actions\/authenticate$/);
  return action;
}

async function getKeycloakCode(startUrl, expectedCallback, credentials) {
  let url = checkEndpoint(startUrl);
  const kcCookies = new Map();
  for (let step = 0; step < 12; step++) {
    const response = await fetch(url, {
      headers: cookieValue(kcCookies) ? { Cookie: cookieValue(kcCookies) } : {},
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
    recordCookies(kcCookies, response);
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      assert.ok(location, 'Keycloak redirect without Location');
      const next = new URL(location, url);
      if (next.origin === new URL(expectedCallback).origin) {
        assert.equal(next.pathname, new URL(expectedCallback).pathname);
        assert.ok(next.searchParams.has('state'), 'missing OIDC state');
        assert.ok(next.searchParams.has('code'), 'missing OIDC code');
        return next;
      }
      url = checkEndpoint(next.href);
      continue;
    }
    assert.equal(response.status, 200, 'Keycloak login form request failed');
    const form = loginFormAction(await response.text());
    const login = await fetch(form, {
      method: 'POST',
      headers: {
        Cookie: cookieValue(kcCookies),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        username: credentials.username,
        password: credentials.password,
        credentialId: '',
      }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
    recordCookies(kcCookies, login);
    assert.ok(login.status >= 300 && login.status < 400,
      'Keycloak rejected the disposable test user or requires an unexpected action');
    const next = new URL(login.headers.get('location'), form);
    if (next.origin === new URL(expectedCallback).origin) {
      assert.equal(next.pathname, new URL(expectedCallback).pathname);
      assert.ok(next.searchParams.has('code'));
      assert.ok(next.searchParams.has('state'));
      return next;
    }
    url = checkEndpoint(next.href);
  }
  throw new Error('Keycloak authorization did not finish after bounded redirects');
}

async function appRequest(path, {method='GET',cookie='',body,action} = {}) {
  const res = await fetch(ORIGIN + path, {
    method, redirect:'manual', signal: AbortSignal.timeout(8000),
    headers: {
      ...cookie ? {Cookie:cookie} : {},
      ...body ? {'Content-Type':'application/json'} : {},
      ...action ? {Origin:ORIGIN,'X-PhiID-Action':action} : {},
    },
    ...body ? {body:JSON.stringify(body)} : {},
  });
  return res;
}

async function withBridge(callback) {
  const child = spawn(process.execPath, ['dev/identity-lab/server.mjs'], {
    env: {...process.env,NODE_ENV:'test'},
    stdio: ['ignore','pipe','pipe'],
  });
  let output = '';
  try {
    await new Promise((resolve,reject) => {
      const timer = setTimeout(()=>reject(new Error('local bridge startup timeout')), 12000);
      const onOutput = chunk => {
        output += String(chunk);
        if(output.includes('PhiID R1 local-only identity lab:')) {
          clearTimeout(timer);
          child.stdout.off('data',onOutput);
          resolve();
        }
      };
      child.stdout.on('data',onOutput);
      child.once('error', err => {clearTimeout(timer);reject(err);});
      child.once('exit', code => {clearTimeout(timer);reject(new Error('bridge exited before ready, code ' + code));});
    });
    return await callback();
  } finally {
    child.kill();
    if (child.exitCode === null && child.signalCode === null) {
      await Promise.race([once(child,'exit'),sleep(1800)]);
    }
  }
}

async function verifyPhiIdSession(user, token) {
  const before = await appRequest('/auth/session');
  assert.equal(before.status, 200);
  assert.equal((await before.json()).authenticated, false);

  const start = await appRequest('/auth/login');
  assert.equal(start.status, 302);
  const startLocation = start.headers.get('location');
  checkEndpoint(startLocation);
  const flowCookie = start.headers.get('set-cookie')?.split(';',1)[0];
  assert.match(flowCookie || '', /^phiid_flow=[A-Za-z0-9_-]{40,}/);
  const redirect = await getKeycloakCode(startLocation, REDIRECT_URI, user);

  // Missing flow state must not create a session or exchange any token.
  const missing = await appRequest(redirect.pathname + redirect.search);
  assert.equal(missing.status, 400);

  const completed = await appRequest(redirect.pathname + redirect.search, {cookie:flowCookie});
  assert.equal(completed.status, 302, 'verified PhiID callback did not redirect');
  assert.equal(completed.headers.get('location'), '/PhiID/');
  const sessionCookie = (completed.headers.getSetCookie?.() || [])
    .find(item=>item.startsWith('phiid_session='))?.split(';',1)[0];
  assert.match(sessionCookie || '', /^phiid_session=[A-Za-z0-9_-]{40,}/);

  const current = await appRequest('/auth/session',{cookie:sessionCookie});
  const profile = await current.json();
  assert.equal(profile.authenticated, true);
  assert.equal(profile.issuer, ISSUER);
  assert.equal(profile.sub, user.userId);
  assert.equal(profile.environment, 'local_development_only');
  assert.ok(!Object.hasOwn(profile,'access_token'));
  assert.ok(!Object.hasOwn(profile,'refresh_token'));
  assert.ok(!Object.hasOwn(profile,'permissions'));

  const denied = await appRequest('/auth/consents');
  assert.equal(denied.status, 401);
  const cannotMutate = await appRequest('/auth/consents', {
    method:'POST',cookie:sessionCookie,
    body:{service:'phimail',scopes:['profile.basic.read'],acknowledged:true}
  });
  assert.equal(cannotMutate.status, 403, 'cross-origin consent unexpectedly permitted');

  const approved = await appRequest('/auth/consents',{
    method:'POST',cookie:sessionCookie,action:'consent',
    body:{service:'phimail',scopes:['profile.basic.read'],acknowledged:true},
  });
  assert.equal(approved.status, 201);
  const receipt = (await approved.json()).receipt;
  assert.equal(receipt.subject.sub, user.userId);
  assert.equal(receipt.connected, false);
  assert.equal(receipt.authority_granted, false);
  assert.equal(receipt.service_called, false);

  const list = await appRequest('/auth/consents',{cookie:sessionCookie});
  assert.equal((await list.json()).receipts.length,1);

  const removed = await appRequest('/auth/consents/phimail',{
    method:'DELETE',cookie:sessionCookie,action:'revoke'
  });
  assert.equal(removed.status,200);
  assert.equal((await removed.json()).external_token_revoked,false);

  const logout = await appRequest('/auth/logout',{
    method:'POST',cookie:sessionCookie,action:'logout'
  });
  assert.equal(logout.status,200);
  const after=await appRequest('/auth/session',{cookie:sessionCookie});
  assert.equal((await after.json()).authenticated,false);

  const replay=await appRequest(redirect.pathname+redirect.search,{cookie:flowCookie});
  assert.equal(replay.status,400,'authorization code/flow replay was accepted');
  return profile.sub;
}

async function verifySecondClient(user, expectedSubject) {
  const config = await oidc.discovery(new URL(ISSUER),'phimail-bff-dev',
    {token_endpoint_auth_method:'none'},oidc.None(),
    {execute:[oidc.allowInsecureRequests],timeout:8});
  const meta=config.serverMetadata();
  assert.equal(meta.issuer,ISSUER);
  assert.equal(meta.authorization_endpoint,ISSUER+'/protocol/openid-connect/auth');
  assert.equal(meta.token_endpoint,ISSUER+'/protocol/openid-connect/token');
  assert.equal(meta.jwks_uri,ISSUER+'/protocol/openid-connect/certs');

  const verifier=oidc.randomPKCECodeVerifier();
  const state=oidc.randomState();
  const nonce=oidc.randomNonce();
  const challenge=await oidc.calculatePKCECodeChallenge(verifier);
  const authorize=oidc.buildAuthorizationUrl(config,{
    redirect_uri:MAIL_CALLBACK,scope:'openid profile',
    code_challenge:challenge,code_challenge_method:'S256',state,nonce,
  });
  const response = await getKeycloakCode(authorize.href, MAIL_CALLBACK, user);
  const tokens = await oidc.authorizationCodeGrant(config,response,{
    pkceCodeVerifier:verifier,expectedState:state,expectedNonce:nonce,
    idTokenExpected:true,
  });
  const claims=tokens.claims();
  assert.equal(claims.iss,ISSUER);
  assert.equal(claims.sub,expectedSubject);
  assert.ok(claims.aud==='phimail-bff-dev' || 
    (Array.isArray(claims.aud)&&claims.aud.includes('phimail-bff-dev')));
  // This does not invoke PhiMail's app session/cookies or grant mailbox access.
}

async function main() {
  await waitForKeycloak();
  const admin = await adminToken();
  let user;
  try {
    user = await createDisposableUser(admin);
    await withBridge(async()=>{
      const subject = await verifyPhiIdSession(user, admin);
      await verifySecondClient(user, subject);
    });
    console.log('PASS: real Keycloak PhiID login, signed claims, consent, logout and independent PhiMail-client token validation');
    console.log('BOUNDARY: PhiMail application bridge and production sign-in were not exercised');
  } finally {
    if (user?.userId) {
      const response=await adminJson(admin,'/admin/realms/phiid-dev/users/'+user.userId,{
        method:'DELETE'
      });
      assert.equal(response.status,204,'disposable test user cleanup failed');
    }
  }
}

// Reusable real-provider helpers for a separate dual-application CI smoke.
// Importing them never starts or modifies an account by itself.
export { waitForKeycloak, adminToken, adminJson, createDisposableUser,
  getKeycloakCode, appRequest, withBridge, checkEndpoint };

// Preserve the exact R4 standalone behavior when invoked as a script.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch(err=>{
    // Do not log identity tokens, callback URLs, HTML, username or passwords.
    console.error('Local Keycloak E2E FAILED:',err?.name || 'Error',
      err?.name==='AssertionError' ? String(err.message).slice(0,160) : 'inspect controlled CI steps');
    process.exitCode=1;
  });
}
