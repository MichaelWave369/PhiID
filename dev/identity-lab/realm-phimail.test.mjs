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
