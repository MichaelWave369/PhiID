import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,sign as signRaw,verify as verifyRaw} from 'node:crypto';
import {mkdtempSync,writeFileSync,rmSync,chmodSync,symlinkSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {ISSUER} from './security.mjs';
import {
  CONFIG_SCHEMA,APPROVAL_SCHEMA,STATEMENT_SCHEMA,ENVELOPE_SCHEMA,
  PERMIT_AUDIENCE,PURPOSE,SCOPE,loadPocketApprovalConfig,
  verifySignedPocketPermit,stagePocketReview,approveStagedPocket
} from './pocket-approval.mjs';

const T=Date.parse('2026-11-06T23:20:00Z');
const SHA='a'.repeat(64);
const identity={authenticated:true,issuer:ISSUER,sub:'disposable-fixture-user'};
function canonical(v){
  if(v===null||typeof v==='boolean'||typeof v==='string'||typeof v==='number')return JSON.stringify(v);
  if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
  return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
}
function fixture(){
  const folder=mkdtempSync(join(tmpdir(),'phiid-pocket-r6-'));
  const permits=generateKeyPairSync('ed25519');
  const approvals=generateKeyPairSync('ed25519');
  const keyFile=join(folder,'approver.pem');
  const configFile=join(folder,'config.json');
  writeFileSync(keyFile,approvals.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
  const definition={
    schema:CONFIG_SCHEMA,policyEpoch:1,approvalKeyId:'review-signer',
    permitKeyId:'permit-signer',allowedSubjects:[identity.sub],
    allowedProfiles:['observe','triage','health'],
    permitPublicKeyPem:permits.publicKey.export({format:'pem',type:'spki'}),
    approvalPrivateKeyFile:keyFile
  };
  writeFileSync(configFile,JSON.stringify(definition),{mode:0o600,flag:'wx'});
  const config=loadPocketApprovalConfig(configFile);
  const session=()=>({profile:{...identity},createdAt:T,expires:T+10*60_000});
  function permit(patch={},signaturePatch={}){
    const request={
      schema:'NBGPocketMesh.SignedExecutionRequest.v1',
      audience:PERMIT_AUDIENCE,policyEpoch:1,
      nonce:randomBytes(16).toString('hex'),issuedAtMs:T,expiresAtMs:T+60000,
      librarySha256:SHA,albumId:'network-health',albumRevision:2,
      albumSha256:SHA,profile:'health',mode:'selective',
      e0ReceiptSha256:SHA,taskSha256:SHA,manifestDigest:SHA,inputSha256:SHA,
      ...patch
    };
    const unsigned={schema:'NBGPocketMesh.SignedExecutionPermit.v1',
      algorithm:'Ed25519',keyId:'permit-signer',request};
    const signature=signRaw(null,Buffer.from(canonical(unsigned)),permits.privateKey).toString('base64url');
    return {...unsigned,signature,...signaturePatch};
  }
  return {folder,configFile,keyFile,definition,config,permits,approvals,session,permit,
    cleanup:()=>rmSync(folder,{recursive:true,force:true})};
}
async function withFixture(fn){const f=fixture();try{await fn(f);}finally{f.cleanup();}}
test('operator policy is loaded only from restricted private files with independent Ed25519 keys',async()=>{
  await withFixture(async f=>{
    assert.equal(f.config.policyEpoch,1);
    assert.equal(f.config.permitKey.type,'public');
    assert.equal(f.config.approvalKey.type,'private');
    chmodSync(f.configFile,0o644);
    assert.throws(()=>loadPocketApprovalConfig(f.configFile),/Unprotected/);
    chmodSync(f.configFile,0o600);
    const alias=join(f.folder,'alias.json');
    symlinkSync(f.configFile,alias);
    assert.throws(()=>loadPocketApprovalConfig(alias),/Unsafe/);
  });
});
test('review validates a real Ed25519-signed v1 permit and shows only bounded descriptive fields',async()=>{
  await withFixture(async f=>{
    const p=f.permit();
    const r=stagePocketReview(f.session(),{permit:p},f.config,T+10);
    assert.match(r.reviewId,/^[A-Za-z0-9_-]{32}$/);
    assert.equal(r.details.profile,'health');
    assert.equal(r.details.albumId,'network-health');
    assert.equal(r.details.purpose,PURPOSE);
    assert.equal(r.details.scope,SCOPE);
    assert.equal(r.details.permitSha256.length,64);
    assert.ok(!('signature' in r.details));
  });
});
test('confirm requires explicit acknowledgement and signs the exact staged permit once',async()=>{
  await withFixture(async f=>{
    const session=f.session(),permit=f.permit();
    const stage=stagePocketReview(session,{permit},f.config,T+1);
    assert.throws(()=>approveStagedPocket(session,{reviewId:stage.reviewId,acknowledged:false},f.config,T+2),/explicit/);
    const result=approveStagedPocket(session,{reviewId:stage.reviewId,acknowledged:true},f.config,T+2);
    assert.equal(result.schema,ENVELOPE_SCHEMA);
    assert.deepEqual(result.permit,permit);
    assert.equal(result.approval.schema,APPROVAL_SCHEMA);
    assert.equal(result.approval.statement.schema,STATEMENT_SCHEMA);
    assert.equal(result.approval.statement.subject.iss,ISSUER);
    assert.equal(result.approval.statement.subject.sub,identity.sub);
    assert.equal(result.approval.statement.subjectAssurance,'DECLARED_BY_SIGNER_UNVERIFIED');
    const {signature,...unsigned}=result.approval;
    assert.equal(verifyRaw(null,Buffer.from(canonical(unsigned)),
      f.approvals.publicKey,Buffer.from(signature,'base64url')),true);
    assert.throws(()=>approveStagedPocket(session,{reviewId:stage.reviewId,acknowledged:true},f.config,T+3),/missing_or_expired/);
  });
});
test('anonymous, forged issuer, another subject, expired and old sessions all refuse',async()=>{
  await withFixture(async f=>{
    const invalid=[
      undefined,{profile:{authenticated:false,issuer:ISSUER,sub:identity.sub},expires:T+600000,createdAt:T},
      {profile:{...identity,issuer:'https://attacker.invalid'},expires:T+600000,createdAt:T},
      {profile:{...identity,sub:'other-sub'},expires:T+600000,createdAt:T},
      {profile:{...identity},expires:T-1,createdAt:T},
      {profile:{...identity},expires:T+600000,createdAt:T-600000}
    ];
    for(const s of invalid)
      assert.throws(()=>stagePocketReview(s,{permit:f.permit()},f.config,T+1));
  });
});
test('forged permit and unexpected code/credential fields refuse',async()=>{
  await withFixture(async f=>{
    const valid=f.permit();
    for(const bad of [
      {...valid,signature:'A'.repeat(86)},
      {...valid,request:{...valid.request,albumId:'other-album'}},
      {...valid,request:{...valid.request,profile:'observe'}},
      {...valid,exec:"require('child_process').exec('bad')"},
      {...valid,request:{...valid.request,allowShell:true}},
      {schema:'phiid.local-consent-receipt/0.1',authority_granted:false},
    ])assert.throws(()=>stagePocketReview(f.session(),{permit:bad},f.config,T+1));
  });
});
test('expired, future, incompatible and remote-looking permit scope refuse',async()=>{
  await withFixture(async f=>{
    for(const patch of [
      {issuedAtMs:T-200000,expiresAtMs:T-100000},
      {issuedAtMs:T+1000,expiresAtMs:T+60000},
      {expiresAtMs:T+140000},
      {audience:'https://attacker.invalid'},
      {mode:'remote'},
      {albumId:'network-triage'}
    ])assert.throws(()=>verifySignedPocketPermit(f.permit(patch),f.config,T+1));
  });
});
test('review identifier cannot be invented or reused after expiry',async()=>{
  await withFixture(async f=>{
    const s=f.session(),r=stagePocketReview(s,{permit:f.permit()},f.config,T+1);
    assert.throws(()=>approveStagedPocket(s,{reviewId:'not-valid',acknowledged:true},f.config,T+2),/missing_or_expired/);
    assert.throws(()=>approveStagedPocket(s,{reviewId:r.reviewId,acknowledged:true},f.config,T+61000),/missing_or_expired/);
  });
});
test('replaced pending review does not authorize the previous signed permit',async()=>{
  await withFixture(async f=>{
    const s=f.session();
    const a=stagePocketReview(s,{permit:f.permit()},f.config,T+1);
    const b=stagePocketReview(s,{permit:f.permit()},f.config,T+2);
    assert.notEqual(a.reviewId,b.reviewId);
    assert.throws(()=>approveStagedPocket(s,{reviewId:a.reviewId,acknowledged:true},f.config,T+3),/missing_or_expired/);
    const result=approveStagedPocket(s,{reviewId:b.reviewId,acknowledged:true},f.config,T+4);
    assert.equal(result.schema,ENVELOPE_SCHEMA);
  });
});
test('session expiry caps signed approval lifetime',async()=>{
  await withFixture(async f=>{
    const s=f.session();s.expires=T+5000;
    const r=stagePocketReview(s,{permit:f.permit()},f.config,T+1);
    const confirmed=approveStagedPocket(s,{reviewId:r.reviewId,acknowledged:true},f.config,T+2);
    assert.equal(confirmed.approval.statement.expiresAtMs,T+5000);
  });
});
test('operator config rejects unreviewed subjects and disabled profiles',async()=>{
  await withFixture(async f=>{
    const altered={...f.config,allowedProfiles:['observe']};
    assert.throws(()=>stagePocketReview(f.session(),{permit:f.permit()},altered,T+1));
    const denied={...f.config,allowedSubjects:['someone-else']};
    assert.throws(()=>stagePocketReview(f.session(),{permit:f.permit()},denied,T+1));
  });
});
test('a pending approval never doubles as PhiID R2 profile consent',async()=>{
  await withFixture(async f=>{
    assert.throws(()=>stagePocketReview(f.session(),{
      permit:{schema:'phiid.local-consent-receipt/0.1',
        requested_scopes:['profile.basic.read'],authority_granted:false}
    },f.config,T+1));
  });
});
test('malformed private key, duplicate subjects, and same signer keys are refused',async()=>{
  await withFixture(async f=>{
    const cfg={...f.definition,allowedSubjects:[identity.sub,identity.sub]};
    writeFileSync(f.configFile,JSON.stringify(cfg));
    assert.throws(()=>loadPocketApprovalConfig(f.configFile),/policy/);
    cfg.allowedSubjects=[identity.sub];
    cfg.permitPublicKeyPem=f.approvals.publicKey.export({format:'pem',type:'spki'});
    writeFileSync(f.configFile,JSON.stringify(cfg));
    assert.throws(()=>loadPocketApprovalConfig(f.configFile),/independent/);
  });
});
