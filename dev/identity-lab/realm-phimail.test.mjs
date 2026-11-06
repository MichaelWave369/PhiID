import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const realm=JSON.parse(readFileSync(new URL('../keycloak/realm/phiid-dev-realm.json',import.meta.url),'utf8'));
test('PhiID and PhiMail have separately pinned loopback OAuth clients',()=>{
 const clients=realm.clients.filter(c=>['phiid-bff-dev','phimail-bff-dev'].includes(c.clientId));
 assert.equal(clients.length,2);
 assert.deepEqual(new Set(clients.flatMap(c=>c.redirectUris)),new Set([
  'http://127.0.0.1:8786/auth/callback','http://127.0.0.1:5173/auth/phiid/callback'
 ]));
 for(const c of clients){
  assert.equal(c.publicClient,true);
  assert.equal(c.standardFlowEnabled,true);
  assert.equal(c.implicitFlowEnabled,false);
  assert.equal(c.directAccessGrantsEnabled,false);
  assert.equal(c.serviceAccountsEnabled,false);
  assert.deepEqual(c.webOrigins,[]);
  assert.equal(c.attributes['pkce.code.challenge.method'],'S256');
  assert.equal(c.redirectUris.length,1);
 }
});
test('development clients contain no secrets or configured mailbox grants',()=>{
 for(const c of realm.clients){
  assert.ok(!('secret' in c));
  assert.equal(c.serviceAccountsEnabled,false);
 }
});


test('R3 has exactly two separate public clients, no accidental third identity integration',()=>{
 const ids=realm.clients.map(client=>client.clientId).sort();
 assert.deepEqual(ids,['phiid-bff-dev','phimail-bff-dev']);
 assert.notEqual(realm.clients[0].redirectUris[0],realm.clients[1].redirectUris[0]);
 assert.equal(realm.registrationAllowed,false);
 assert.equal(realm.sslRequired,'none'); // dev-only, not a production TLS setting
});

test('R3 clients enforce PKCE S256 and never use wildcard redirects or embedded credentials',()=>{
 for(const client of realm.clients){
  assert.equal(client.enabled,true);
  assert.equal(client.protocol,'openid-connect');
  assert.equal(client.publicClient,true);
  assert.equal(client.bearerOnly,false);
  assert.equal(client.standardFlowEnabled,true);
  assert.equal(client.implicitFlowEnabled,false);
  assert.equal(client.directAccessGrantsEnabled,false);
  assert.equal(client.serviceAccountsEnabled,false);
  assert.deepEqual(client.webOrigins,[]);
  assert.equal(client.attributes['pkce.code.challenge.method'],'S256');
  assert.ok(client.redirectUris.every(uri=>!uri.includes('*')));
  assert.equal(Object.hasOwn(client,'secret'),false);
  assert.equal(Object.hasOwn(client,'clientAuthenticatorType'),false);
 }
});

test('R3 realm import contains no seeded users, passwords, or mail service configuration',()=>{
 for(const key of ['users','credentials','smtpServer']) {
  assert.equal(Object.hasOwn(realm,key),false);
 }
});
