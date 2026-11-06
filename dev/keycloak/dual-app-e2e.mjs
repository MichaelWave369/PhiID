/**
 * R5: real two-application sign-in and isolation, with two actual Node bridges.
 *
 * Requires a disposable Keycloak process and a pinned PhiMail checkout in
 * ./integration/phimail. Nothing runs against production or real mailboxes.
 * Uses proven R4 Keycloak Admin and real-form helpers, NOT a mocked provider.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  waitForKeycloak, adminToken, adminJson, createDisposableUser,
  getKeycloakCode, appRequest, withBridge, checkEndpoint,
} from './live-e2e.mjs';
import { ISSUER, REDIRECT_URI } from '../identity-lab/security.mjs';

const ID_ORIGIN = 'http://127.0.0.1:8786';
const MAIL_ORIGIN = 'http://127.0.0.1:5173';
const MAIL_DIR = resolve('integration/phimail');
const MAIL_CALLBACK = MAIL_ORIGIN + '/auth/phiid/callback';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

if (process.env.PHIID_DUAL_APP_E2E !== '1' || process.env.PHIID_E2E_ENABLE !== '1' ||
    process.env.NODE_ENV === 'production') {
  throw new Error('Explicit non-production R5 CI opt-in required');
}
if (!existsSync(resolve(MAIL_DIR, 'server/phiid-lab.js')) ||
    !existsSync(resolve(MAIL_DIR, 'node_modules/vite'))) {
  throw new Error('A checked-out, installed PhiMail test fixture is required');
}

function cookieFrom(res, name) {
  const all = res.headers.getSetCookie?.() || [res.headers.get('set-cookie')].filter(Boolean);
  const hit = all.map(v => v.split(';', 1)[0]).find(v => v.startsWith(name + '='));
  assert.match(hit || '', new RegExp('^' + name + '=[A-Za-z0-9_-]{40,}$'),
    'missing expected session or flow cookie');
  return hit;
}

async function mailRequest(path, { method='GET', cookie='', action='' } = {}) {
  return fetch(MAIL_ORIGIN + path, {
    method,
    redirect:'manual',
    signal:AbortSignal.timeout(10000),
    headers: {
      ...cookie ? { Cookie:cookie } : {},
      ...action ? { Origin:MAIL_ORIGIN, 'X-PhiMail-Action':action } : {},
    },
  });
}

async function waitForMailProxy(children) {
  for (let step=0; step<75; step++) {
    if (children.some(child=>child.exitCode !== null || child.signalCode !== null)) {
      throw new Error('PhiMail bridge or Vite process terminated before ready');
    }
    try {
      const response=await mailRequest('/api/identity/session');
      if(response.status===200) {
        const state=await response.json();
        assert.equal(state.enabled,true,'PhiMail local identity flag was disabled');
        assert.equal(state.authenticated,false);
        return;
      }
    } catch { /* Vite/Node startup still in progress. */ }
    await sleep(600);
  }
  throw new Error('PhiMail Vite-to-Node localhost proxy startup timed out');
}

async function withMailApps(callback) {
  const env = {
    ...process.env,
    NODE_ENV:'test',
    BRIDGE_PUBLIC_ORIGIN:MAIL_ORIGIN,
    BRIDGE_LISTEN_HOST:'127.0.0.1',
    BRIDGE_PORT:'8787',
    PHIMAIL_LOCAL_PHIID:'1',
    GOOGLE_CLIENT_ID:'',
    GOOGLE_CLIENT_SECRET:'',
  };
  const backend=spawn(process.execPath,['server/index.js'],{
    cwd:MAIL_DIR,env,stdio:['ignore','pipe','pipe'],
  });
  const vite=spawn('npm',['run','dev','--','--strictPort','--port','5173'],{
    cwd:MAIL_DIR,
    env:{...env,NODE_ENV:'development'},
    stdio:['ignore','pipe','pipe'],
  });
  // Drain output without writing potentially sensitive future provider responses.
  for (const child of [backend,vite]) {
    child.stdout.on('data',()=>{});
    child.stderr.on('data',()=>{});
  }
  try {
    await waitForMailProxy([backend,vite]);
    return await callback();
  } finally {
    for(const child of [vite,backend]) {
      if(child.exitCode===null && child.signalCode===null) child.kill('SIGTERM');
    }
    await Promise.all([backend,vite].map(child =>
      (child.exitCode !== null || child.signalCode !== null)
        ? Promise.resolve()
        : Promise.race([once(child,'exit'),sleep(2500)])
    ));
  }
}

async function phiIdSignIn(user) {
  const start=await appRequest('/auth/login');
  assert.equal(start.status,302);
  const destination=checkEndpoint(start.headers.get('location'));
  const flowCookie=cookieFrom(start,'phiid_flow');
  const callback=await getKeycloakCode(destination.href, REDIRECT_URI,user);
  const done=await appRequest(callback.pathname+callback.search,{cookie:flowCookie});
  assert.equal(done.status,302,'PhiID real callback failed');
  assert.equal(done.headers.get('location'),'/PhiID/');
  const cookie=cookieFrom(done,'phiid_session');
  const session=await appRequest('/auth/session',{cookie});
  assert.equal(session.status,200);
  const profile=await session.json();
  assert.equal(profile.authenticated,true);
  assert.equal(profile.issuer,ISSUER);
  assert.equal(profile.sub,user.userId);
  assert.ok(!Object.hasOwn(profile,'access_token'));
  assert.ok(!Object.hasOwn(profile,'id_token'));
  return {cookie,profile};
}

async function phiMailSignIn(user) {
  const start=await mailRequest('/auth/phiid/start');
  assert.equal(start.status,302,'PhiMail app start rejected');
  const destination=checkEndpoint(start.headers.get('location'));
  assert.equal(destination.pathname,
    '/realms/phiid-dev/protocol/openid-connect/auth');
  assert.equal(destination.searchParams.get('client_id'),'phimail-bff-dev');
  assert.equal(destination.searchParams.get('redirect_uri'),MAIL_CALLBACK);
  assert.equal(destination.searchParams.get('code_challenge_method'),'S256');
  const flowCookie=cookieFrom(start,'pm_oidc_flow');
  const callback=await getKeycloakCode(destination.href,MAIL_CALLBACK,user);

  // No flow cookie means an untrusted callback, never a login.
  const denied=await mailRequest(callback.pathname+callback.search);
  assert.equal(denied.status,400);

  const done=await mailRequest(callback.pathname+callback.search,{cookie:flowCookie});
  assert.equal(done.status,302,'PhiMail real OIDC callback failed');
  assert.equal(done.headers.get('location'),MAIL_ORIGIN+'/?phiid=connected');
  const cookie=cookieFrom(done,'pm_identity');
  const session=await mailRequest('/api/identity/session',{cookie});
  assert.equal(session.status,200);
  const profile=await session.json();
  assert.equal(profile.enabled,true);
  assert.equal(profile.authenticated,true);
  assert.equal(profile.issuer,ISSUER);
  assert.equal(profile.sub,user.userId);
  assert.deepEqual(profile.grants,[]);
  assert.equal(profile.mailbox_linked,false);
  assert.equal(profile.cloud_authorized,false);
  assert.ok(!Object.hasOwn(profile,'access_token'));
  assert.ok(!Object.hasOwn(profile,'refresh_token'));
  assert.ok(!Object.hasOwn(profile,'id_token'));
  assert.ok(!Object.hasOwn(profile,'email'));
  const replay=await mailRequest(callback.pathname+callback.search,{cookie:flowCookie});
  assert.equal(replay.status,400,'PhiMail callback replay accepted');
  return {cookie,profile};
}

async function assertNoMailAuthority(mailCookie, idCookie) {
  const gmailSession=await mailRequest('/api/session',{cookie:mailCookie});
  assert.equal(gmailSession.status,200);
  const state=await gmailSession.json();
  assert.equal(state.connected,false);
  assert.deepEqual(state.capabilities,[]);

  const inbox=await mailRequest('/api/mail/messages',{cookie:mailCookie});
  assert.equal(inbox.status,401,'PhiID login incorrectly unlocked Gmail messages');

  const review=await mailRequest('/api/identity/mailbox-review',{cookie:mailCookie});
  assert.equal(review.status,200);
  const reviewState=await review.json();
  assert.equal(reviewState.authenticated_identity,true);
  assert.equal(reviewState.connected_gmail_session,false);
  assert.equal(reviewState.eligible_to_review,false);
  assert.equal(reviewState.account_linked,false);
  assert.equal(reviewState.mailbox_access_granted,false);

  const foreignIdentity=await mailRequest('/api/identity/session',{cookie:idCookie});
  assert.equal((await foreignIdentity.json()).authenticated,false,
    'PhiMail accidentally accepted PhiID app session cookie');
  const foreignPhiID=await appRequest('/auth/session',{cookie:mailCookie});
  assert.equal((await foreignPhiID.json()).authenticated,false,
    'PhiID accidentally accepted PhiMail app session cookie');
  const foreignConsent=await appRequest('/auth/consents',{cookie:mailCookie});
  assert.equal(foreignConsent.status,401);
}

async function testDualApp(user) {
  const phiBefore=await appRequest('/auth/session');
  assert.equal((await phiBefore.json()).authenticated,false);
  const mailBefore=await mailRequest('/api/identity/session');
  assert.equal((await mailBefore.json()).authenticated,false);

  // First authenticating PhiMail proves PhiID does not silently sign it in.
  let mail=await phiMailSignIn(user);
  let phi=await appRequest('/auth/session');
  assert.equal((await phi.json()).authenticated,false);

  const mailOnlyView=await mailRequest('/api/identity/session',{cookie:mail.cookie});
  assert.equal((await mailOnlyView.json()).sub,user.userId);

  // PhiID must perform its own, independent authorization-code login.
  let identity=await phiIdSignIn(user);
  assert.equal(identity.profile.sub,mail.profile.sub);
  await assertNoMailAuthority(mail.cookie,identity.cookie);

  // Ending PhiMail's session must not terminate PhiID's app session.
  const badLogout=await mailRequest('/api/identity/logout',{
    method:'POST',cookie:mail.cookie,action:'wrong'
  });
  assert.equal(badLogout.status,403);
  const mailLogout=await mailRequest('/api/identity/logout',{
    method:'POST',cookie:mail.cookie,action:'logout'
  });
  assert.equal(mailLogout.status,200);
  const afterMail=await mailRequest('/api/identity/session',{cookie:mail.cookie});
  assert.equal((await afterMail.json()).authenticated,false);
  const phiStill=await appRequest('/auth/session',{cookie:identity.cookie});
  assert.equal((await phiStill.json()).authenticated,true);

  // Re-authenticate PhiMail while PhiID remains signed in.
  mail=await phiMailSignIn(user);
  const stillSame=await appRequest('/auth/session',{cookie:identity.cookie});
  assert.equal((await stillSame.json()).sub,mail.profile.sub);

  // Ending PhiID's session must NOT terminate PhiMail's app session.
  const phiLogout=await appRequest('/auth/logout',{
    method:'POST',cookie:identity.cookie,action:'logout'
  });
  assert.equal(phiLogout.status,200);
  const phiAfter=await appRequest('/auth/session',{cookie:identity.cookie});
  assert.equal((await phiAfter.json()).authenticated,false);
  const mailStill=await mailRequest('/api/identity/session',{cookie:mail.cookie});
  assert.equal((await mailStill.json()).authenticated,true);

  // Full cleanup, with no Gmail or cloud access throughout.
  const cleanup=await mailRequest('/api/identity/logout',{
    method:'POST',cookie:mail.cookie,action:'logout'
  });
  assert.equal(cleanup.status,200);
  const finalMail=await mailRequest('/api/identity/session',{cookie:mail.cookie});
  assert.equal((await finalMail.json()).authenticated,false);
}

async function main() {
  await waitForKeycloak();
  const token=await adminToken();
  let user;
  try {
    user=await createDisposableUser(token);
    await withBridge(()=>withMailApps(()=>testDualApp(user)));
    console.log('PASS: genuine Keycloak -> PhiMail Vite proxy -> PhiMail Node OIDC bridge, independently of PhiID Node bridge');
    console.log('PASS: same verified issuer/sub, separate PKCE, sessions and logout; Gmail inbox/consent access remains denied');
    console.log('BOUNDARY: localhost-only disposable dev realm, no live accounts or mailboxes, no production deployment');
  } finally {
    if(user?.userId){
      const removed=await adminJson(token,
        '/admin/realms/phiid-dev/users/'+user.userId,{method:'DELETE'});
      assert.equal(removed.status,204,'disposable Keycloak test user cleanup failed');
    }
  }
}

await main().catch(error=>{
  // Intentionally never print raw error messages; URLs can contain auth codes.
  console.error('R5 dual-application localhost E2E FAILED:',
    error?.name==='AssertionError' ? 'contract assertion failed' :
    (error?.name || 'Error'));
  process.exitCode=1;
});
