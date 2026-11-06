import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';

const ORIGIN = 'http://127.0.0.1:8786';

function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: '127.0.0.1', port: 8786, path,
      method: options.method || 'GET',
      headers: options.headers || {},
    }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('R1 server denies remote/CSRF access and has no anonymous principal', async t => {
  const child = spawn(process.execPath, ['dev/identity-lab/server.mjs'], {
    cwd: process.cwd(), env: { ...process.env, NODE_ENV: 'test' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await Promise.race([once(child, 'exit'), new Promise(resolve => setTimeout(resolve, 2000))]);
    }
  });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('loopback bridge did not start')), 8000);
    const done = chunk => {
      if (String(chunk).includes('PhiID R1 local-only identity lab')) {
        clearTimeout(timeout);
        child.stdout.off('data', done);
        resolve();
      }
    };
    child.stdout.on('data', done);
    child.once('exit', code => { clearTimeout(timeout); reject(new Error('bridge exited ' + code)); });
    child.once('error', err => { clearTimeout(timeout); reject(err); });
  });

  const anonymous = await request('/auth/session');
  assert.equal(anonymous.status, 200);
  assert.equal(JSON.parse(anonymous.body).authenticated, false);
  assert.match(String(anonymous.headers['cache-control']), /no-store/);
  assert.match(String(anonymous.headers['content-security-policy']), /default-src 'self'/);

  const spoofed = await request('/auth/session', { headers: { host: 'attacker.invalid:8786' } });
  assert.equal(spoofed.status, 403);

  const blocked = await request('/auth/logout', { method: 'POST', headers: { origin: 'https://attacker.invalid', 'x-phiid-action': 'logout' } });
  assert.equal(blocked.status, 403);

  const local = await request('/auth/logout', { method: 'POST', headers: { origin: ORIGIN, 'x-phiid-action': 'logout' } });
  assert.equal(local.status, 200);
  assert.equal(JSON.parse(local.body).authenticated, false);

  const missingFlow = await request('/auth/callback?code=x&state=wrong');
  assert.equal(missingFlow.status, 400);
  assert.equal(JSON.parse(missingFlow.body).error, 'missing_or_expired_login_flow');


  const noIdentity = await request('/auth/consents');
  assert.equal(noIdentity.status, 401);
  assert.equal(JSON.parse(noIdentity.body).error, 'verified_local_session_required');

  const crossSiteConsent = await request('/auth/consents', {
    method: 'POST',
    headers: { origin: 'https://attacker.invalid', 'x-phiid-action': 'consent',
      'content-type': 'application/json' },
  });
  assert.equal(crossSiteConsent.status, 403);

  const noAuthConsent = await request('/auth/consents', {
    method: 'POST',
    headers: { origin: ORIGIN, 'x-phiid-action': 'consent',
      'content-type': 'application/json' },
  });
  assert.equal(noAuthConsent.status, 401);

  const crossSiteRevoke = await request('/auth/consents/phimail', {
    method: 'DELETE',
    headers: { origin: 'https://attacker.invalid', 'x-phiid-action': 'revoke' },
  });
  assert.equal(crossSiteRevoke.status, 403);

  const noAuthRevoke = await request('/auth/consents/phicloud', {
    method: 'DELETE',
    headers: { origin: ORIGIN, 'x-phiid-action': 'revoke' },
  });
  assert.equal(noAuthRevoke.status, 401);


  const anonLedger = await request('/auth/ledger');
  assert.equal(anonLedger.status, 401);

  const disabledWrite = await request('/auth/ledger', {
    method:'POST',headers:{origin:ORIGIN,'x-phiid-action':'ledger-record','content-type':'application/json'}
  });
  assert.equal(disabledWrite.status, 404);
  assert.equal(JSON.parse(disabledWrite.body).error,'local_choice_ledger_disabled');

  const disabledRevoke = await request('/auth/ledger/phimail', {
    method:'DELETE',headers:{origin:ORIGIN,'x-phiid-action':'ledger-revoke'}
  });
  assert.equal(disabledRevoke.status, 404);

  const absent = await request('/v1/users');
  assert.equal(absent.status, 404);
  const forbiddenQuery = await request('/auth/session?probe=true');
  assert.equal(forbiddenQuery.status, 404);
});
