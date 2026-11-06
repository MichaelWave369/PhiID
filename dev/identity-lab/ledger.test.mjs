import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, lstatSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openLocalChoiceLedger, LEDGER_SCHEMA } from './ledger.mjs';
import { ISSUER } from './security.mjs';
import { ConsentError } from './consent.mjs';

const NOW = Date.parse('2026-11-06T23:30:00Z');
const allowed = service => ({
  service, scopes: ['profile.basic.read'],
  acknowledged: true, persist_acknowledged: true,
});
const identity = (sub = 'test-user', issuer = ISSUER, now = NOW) => ({
  profile: {authenticated:true,issuer,sub},
  expires:now + 15 * 60_000,
});
function temporaryDatabase(t) {
  const dir = mkdtempSync(join(tmpdir(),'phiid-r6-private-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  return {path:join(dir,'review-ledger.sqlite'),dir};
}

test('durable choice survives both identity session and SQLite connection restarts', t=>{
  const {path}=temporaryDatabase(t);
  const first=openLocalChoiceLedger(path);
  const record=first.record(identity(),allowed('phimail'),NOW);
  assert.equal(record.schema,LEDGER_SCHEMA);
  assert.equal(record.status,'recorded_not_enforced');
  assert.equal(record.authority_granted,false);
  assert.equal(record.connected,false);
  assert.equal(record.service_called,false);
  assert.equal(record.external_token_revoked,false);
  assert.equal(record.requested_scopes[0],'profile.basic.read');
  assert.match(record.receipt_id,/^[A-Za-z0-9_-]{40,}$/);
  assert.equal(Object.hasOwn(record,'subject'),false,'database response must not expose account identifier');
  first.close();

  const second=openLocalChoiceLedger(path);
  const restored=second.list(identity(),NOW + 1_000);
  assert.equal(restored.persistent,true);
  assert.equal(restored.active.length,1);
  assert.equal(restored.active[0].receipt_id,record.receipt_id);
  assert.equal(restored.history.length,1);
  assert.equal(restored.permissions_enforced,false);
  assert.equal(restored.service_calls,false);
  second.close();
});

test('different issuer and subject cannot read or revoke another principal choice',t=>{
  const {path}=temporaryDatabase(t);
  const db=openLocalChoiceLedger(path);
  const one=identity('user-one');
  const two=identity('user-two');
  db.record(one,allowed('phicloud'),NOW);
  assert.equal(db.list(two,NOW).active.length,0);
  assert.equal(db.revoke(two,'phicloud',NOW + 100).removed,false);
  assert.equal(db.list(one,NOW + 101).active.length,1);
  const invalid=identity('user-one','http://attacker.invalid');
  assert.throws(()=>db.list(invalid,NOW),ConsentError);
  assert.throws(()=>db.record(invalid,allowed('phimail'),NOW),ConsentError);
  db.close();
});

test('explicit durable acknowledgement and an allowlisted scope are compulsory',t=>{
  const {path}=temporaryDatabase(t);
  const db=openLocalChoiceLedger(path);
  const s=identity();
  for(const bad of [
    null,{...allowed('phimail'),persist_acknowledged:false},
    {...allowed('phimail'),persist_acknowledged:'true'},
    {...allowed('phimail'),acknowledged:false},
    {...allowed('phimail'),service:'phios'},
    {...allowed('phimail'),scopes:['mailbox.read']},
    {...allowed('phimail'),scopes:['profile.basic.read','vault.*']},
    {...allowed('phimail'),sub:'attacker'},
    {...allowed('phimail'),token:'x'},
  ]) assert.throws(()=>db.record(s,bad,NOW),ConsentError);
  assert.equal(db.list(s,NOW).history.length,0);
  db.close();
});

test('revoke survives restart with explicit audit trail but no external token revocation',t=>{
  const {path}=temporaryDatabase(t);
  const db=openLocalChoiceLedger(path);
  const s=identity();
  const old=db.record(s,allowed('phimail'),NOW);
  const fresh=db.record(s,allowed('phimail'),NOW+10);
  assert.notEqual(old.receipt_id,fresh.receipt_id);
  let result=db.list(s,NOW+20);
  assert.equal(result.active.length,1);
  assert.equal(result.active[0].receipt_id,fresh.receipt_id);
  assert.equal(result.history.length,2);
  assert.equal(result.history.find(x=>x.receipt_id===old.receipt_id).revocation_reason,'superseded');
  const removed=db.revoke(s,'phimail',NOW+30);
  assert.equal(removed.removed,true);
  assert.equal(removed.external_token_revoked,false);
  assert.equal(removed.connection_revoked,false);
  assert.equal(db.revoke(s,'phimail',NOW+31).removed,false);
  db.close();
  const again=openLocalChoiceLedger(path);
  result=again.list(identity('test-user',ISSUER,NOW+1000),NOW+1000);
  assert.equal(result.active.length,0);
  assert.equal(result.history.length,2);
  assert.equal(result.history.find(x=>x.receipt_id===fresh.receipt_id).status,'revoked_choice');
  assert.equal(result.history.find(x=>x.receipt_id===fresh.receipt_id).revocation_reason,'user_revoked');
  again.close();
});

test('expired choice is never active although its audit record remains',t=>{
  const {path}=temporaryDatabase(t);
  const db=openLocalChoiceLedger(path);
  db.record(identity(),allowed('phicloud'),NOW);
  const future=NOW+31*24*60*60_000;
  const s=identity('test-user',ISSUER,future);
  const data=db.list(s,future);
  assert.equal(data.active.length,0);
  assert.equal(data.history[0].status,'expired_choice');
  assert.throws(()=>db.list(identity('test-user',ISSUER,NOW),NOW+31*24*60*60_000),ConsentError);
  db.close();
});

test('private database and directory reject shared permissions and symlinks',t=>{
  const {path,dir}=temporaryDatabase(t);
  let db=openLocalChoiceLedger(path);
  db.close();
  assert.equal(lstatSync(path).mode & 0o077,0);
  assert.equal(lstatSync(dir).mode & 0o077,0);
  chmodSync(path,0o644);
  assert.throws(()=>openLocalChoiceLedger(path),/ledger_file_must_be_private/);
  chmodSync(path,0o600);
  const linked=join(dir,'linked.sqlite');
  symlinkSync(path,linked);
  assert.throws(()=>openLocalChoiceLedger(linked),/ledger_file_must_be_private/);
  chmodSync(dir,0o755);
  assert.throws(()=>openLocalChoiceLedger(path),/ledger_directory_must_be_private/);
  chmodSync(dir,0o700);
});
