import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const realm = JSON.parse(readFileSync(new URL('./realm/phiid-dev-realm.json', import.meta.url), 'utf8'));

test('two separately registered clients share the local issuer but no redirect/session', () => {
  assert.equal(realm.realm, 'phiid-dev');
  assert.equal(realm.registrationAllowed, false);
  assert.equal(realm.sslRequired, 'none');
  const ids = realm.clients.map(c=>c.clientId);
  assert.deepEqual(ids.sort(), ['phiid-bff-dev', 'phimail-phiid-dev'].sort());
  const first=realm.clients.find(c=>c.clientId==='phiid-bff-dev');
  const mail=realm.clients.find(c=>c.clientId==='phimail-phiid-dev');
  assert.deepEqual(first.redirectUris, ['http://127.0.0.1:8786/auth/callback']);
  assert.deepEqual(mail.redirectUris, ['http://localhost:5173/auth/phiid/callback']);
  assert.notEqual(first.redirectUris[0], mail.redirectUris[0]);
});

test('clients use authorization code with PKCE S256, no direct grants or wildcards', () => {
  for(const c of realm.clients){
    assert.equal(c.publicClient,true);
    assert.equal(c.standardFlowEnabled,true);
    assert.equal(c.implicitFlowEnabled,false);
    assert.equal(c.directAccessGrantsEnabled,false);
    assert.equal(c.serviceAccountsEnabled,false);
    assert.equal(c.bearerOnly,false);
    assert.equal(c.attributes['pkce.code.challenge.method'],'S256');
    assert.deepEqual(c.webOrigins,[]);
    assert.ok(c.redirectUris.every(uri => !uri.includes('*')));
    assert.equal(Object.hasOwn(c,'secret'),false);
  }
});

test('realm import never contains real users, admin credentials or mailboxes',()=>{
  for(const key of ['users','credentials','smtpServer','components']){
    assert.equal(Object.hasOwn(realm,key),false);
  }
});
