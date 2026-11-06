/**
 * PhiID R6: experimental action approval in an already verified LOCAL OIDC
 * session. Not OAuth scopes, passkeys, a production human-approval service,
 * or PhiOS authority. Existing R2 consent records NEVER satisfy this API.
 * The signer config is operator-owned, and the private key never enters web
 * responses, static bundles or client-supplied JSON.
 */
import {
  randomBytes,createHash,createPublicKey,createPrivateKey,
  sign as signRaw,verify as verifyRaw
} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {isAbsolute} from 'node:path';
import {ISSUER} from './security.mjs';
import {ConsentError,requireSession} from './consent.mjs';

export const CONFIG_SCHEMA='phiid.local-pocket-approval-config/0.1';
export const APPROVAL_SCHEMA='NBGPocketMesh.PhiIDApproval.v0';
export const STATEMENT_SCHEMA='NBGPocketMesh.PhiIDApprovalStatement.v0';
export const ENVELOPE_SCHEMA='NBGPocketMesh.PhiIDAuthorizedRequest.v0';
export const PURPOSE='execute-reviewed-pocket-album';
export const SCOPE='pocket.album.execute';
export const AUDIENCE='NBGPocketMesh.local-signed-executor.v0';
export const PERMIT_AUDIENCE='NBGPocketMesh.offline-local-runner.v1';
const PERMIT_SCHEMA='NBGPocketMesh.SignedExecutionPermit.v1';
const REQUEST_SCHEMA='NBGPocketMesh.SignedExecutionRequest.v1';
const SESSION_FRESH_MS=5*60_000;
const REVIEW_TTL_MS=60_000;
const TRACKS=Object.freeze({
  observe:'network-observe',triage:'network-triage',health:'network-health'
});
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
function exact(v,keys,label){
  if(!plain(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...keys].sort()))
    throw new ConsentError('invalid_'+label+'_shape');
}
function canonical(v){
  if(v===null||typeof v==='boolean'||typeof v==='string')return JSON.stringify(v);
  if(typeof v==='number'&&Number.isFinite(v))return JSON.stringify(v);
  if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
  if(plain(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
  throw new ConsentError('noncanonical_pocket_value');
}
const sha=v=>createHash('sha256').update(canonical(v)).digest('hex');
const token=v=>typeof v==='string'&&/^[a-z0-9][a-z0-9._-]{0,63}$/.test(v);
const hex64=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const validTime=v=>Number.isSafeInteger(v)&&v>=0;
const finger=key=>createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');
function secureFile(path,maxBytes){
  if(typeof path!=='string'||!isAbsolute(path))throw new TypeError('Absolute operator path required');
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.size<8||stat.size>maxBytes)
    throw new TypeError('Unsafe operator file');
  if(process.platform!=='win32'){
    if((stat.mode&0o077)!==0||(typeof process.getuid==='function'&&stat.uid!==process.getuid()))
      throw new TypeError('Unprotected operator file');
  }
  return readFileSync(path,'utf8');
}
export function loadPocketApprovalConfig(path){
  const doc=JSON.parse(secureFile(path,8192));
  exact(doc,['schema','policyEpoch','approvalKeyId','permitKeyId',
    'permitPublicKeyPem','approvalPrivateKeyFile','allowedSubjects','allowedProfiles'],'approval_config');
  if(doc.schema!==CONFIG_SCHEMA||doc.policyEpoch!==1||
     !token(doc.approvalKeyId)||!token(doc.permitKeyId)||
     doc.approvalKeyId===doc.permitKeyId||
     typeof doc.permitPublicKeyPem!=='string'||doc.permitPublicKeyPem.length>1024||
     !Array.isArray(doc.allowedSubjects)||doc.allowedSubjects.length<1||doc.allowedSubjects.length>16||
     !doc.allowedSubjects.every(s=>typeof s==='string'&&s.length>0&&s.length<=128)||
     new Set(doc.allowedSubjects).size!==doc.allowedSubjects.length||
     !Array.isArray(doc.allowedProfiles)||doc.allowedProfiles.length<1||doc.allowedProfiles.length>3||
     !doc.allowedProfiles.every(p=>Object.hasOwn(TRACKS,p))||
     new Set(doc.allowedProfiles).size!==doc.allowedProfiles.length)
    throw new TypeError('Invalid approval policy');
  const permitKey=createPublicKey(doc.permitPublicKeyPem);
  const privateKey=createPrivateKey(secureFile(doc.approvalPrivateKeyFile,4096));
  if(permitKey.asymmetricKeyType!=='ed25519'||privateKey.asymmetricKeyType!=='ed25519'||
     finger(permitKey)===finger(createPublicKey(privateKey)))
    throw new TypeError('Approval and permit signers must be independent Ed25519 keys');
  return Object.freeze({
    policyEpoch:doc.policyEpoch,approvalKeyId:doc.approvalKeyId,permitKeyId:doc.permitKeyId,
    permitKey,approvalKey:privateKey,
    allowedSubjects:Object.freeze([...doc.allowedSubjects]),
    allowedProfiles:Object.freeze([...doc.allowedProfiles])
  });
}
function requireApprovedSession(session,config,now){
  requireSession(session,now);
  if(!Number.isSafeInteger(session.createdAt)||session.createdAt>now||
     now-session.createdAt>SESSION_FRESH_MS)
    throw new ConsentError('fresh_local_login_required',401);
  if(!config||!config.allowedSubjects.includes(session.profile.sub))
    throw new ConsentError('pocket_operator_not_allowed',403);
  return session;
}
export function verifySignedPocketPermit(permit,config,now=Date.now()){
  exact(permit,['schema','algorithm','keyId','request','signature'],'permit');
  const r=permit.request;
  exact(r,['schema','audience','policyEpoch','nonce','issuedAtMs','expiresAtMs',
    'librarySha256','albumId','albumRevision','albumSha256','profile','mode',
    'e0ReceiptSha256','taskSha256','manifestDigest','inputSha256'],'permit_request');
  if(permit.schema!==PERMIT_SCHEMA||permit.algorithm!=='Ed25519'||
     permit.keyId!==config.permitKeyId||r.schema!==REQUEST_SCHEMA||
     r.audience!==PERMIT_AUDIENCE||r.policyEpoch!==1||
     !Object.hasOwn(TRACKS,r.profile)||!config.allowedProfiles.includes(r.profile)||
     r.albumId!==TRACKS[r.profile]||!['selective','eager'].includes(r.mode)||
     !Number.isSafeInteger(r.albumRevision)||r.albumRevision<1||
     !/^[a-f0-9]{32}$/.test(r.nonce)||
     ![r.librarySha256,r.albumSha256,r.e0ReceiptSha256,r.taskSha256,r.manifestDigest,r.inputSha256].every(hex64)||
     !validTime(r.issuedAtMs)||!validTime(r.expiresAtMs)||
     r.expiresAtMs<=now||r.issuedAtMs>now||
     r.expiresAtMs<=r.issuedAtMs||r.expiresAtMs-r.issuedAtMs>120000||
     typeof permit.signature!=='string'||!/^[a-zA-Z0-9_-]{86}$/.test(permit.signature))
    throw new ConsentError('unsupported_or_expired_pocket_permit');
  const signed=canonical({schema:PERMIT_SCHEMA,algorithm:'Ed25519',keyId:permit.keyId,request:r});
  const sig=Buffer.from(permit.signature,'base64url');
  if(sig.length!==64||sig.toString('base64url')!==permit.signature||
     !verifyRaw(null,Buffer.from(signed),config.permitKey,sig))
    throw new ConsentError('invalid_pocket_permit_signature');
  return Object.freeze({
    profile:r.profile,albumId:r.albumId,revision:r.albumRevision,
    mode:r.mode,expiresAtMs:r.expiresAtMs,
    permitSha256:sha(permit)
  });
}
/** Stage a one-minute, per-session explicit review. No approval is issued. */
export function stagePocketReview(session,payload,config,now=Date.now()){
  requireApprovedSession(session,config,now);
  exact(payload,['permit'],'review');
  const details=verifySignedPocketPermit(payload.permit,config,now);
  const reviewId=randomBytes(24).toString('base64url');
  session.pendingPocket={
    reviewId,permit:structuredClone(payload.permit),
    expiresAtMs:Math.min(details.expiresAtMs,session.expires,now+REVIEW_TTL_MS)
  };
  return {reviewId,details:{
    ...details,purpose:PURPOSE,scope:SCOPE,
    note:'Review and explicitly approve this exact local synthetic album execution.'
  }};
}
/** A session acknowledgement signs ONLY the exact staged permit once. */
export function approveStagedPocket(session,payload,config,now=Date.now()){
  requireApprovedSession(session,config,now);
  exact(payload,['reviewId','acknowledged'],'approval_confirmation');
  if(typeof payload.reviewId!=='string'||payload.acknowledged!==true)
    throw new ConsentError('explicit_pocket_approval_required');
  const pending=session.pendingPocket;
  if(!pending||pending.reviewId!==payload.reviewId||pending.expiresAtMs<=now)
    throw new ConsentError('missing_or_expired_pocket_review');
  // Consume pending approval BEFORE signing. Double-click and error paths
  // must never leave a reusable approval in an authenticated session.
  delete session.pendingPocket;
  const details=verifySignedPocketPermit(pending.permit,config,now);
  const expiresAtMs=Math.min(now+30000,session.expires,details.expiresAtMs);
  if(expiresAtMs<=now)throw new ConsentError('pocket_approval_expired');
  const statement={
    schema:STATEMENT_SCHEMA,audience:AUDIENCE,purpose:PURPOSE,scope:SCOPE,
    approvalId:randomBytes(16).toString('hex'),
    subject:{iss:session.profile.issuer,sub:session.profile.sub},
    // Required by NBGPocketMesh v0. A verified PhiID local BFF session was
    // checked here, but the downstream worker cannot independently verify it.
    subjectAssurance:'DECLARED_BY_SIGNER_UNVERIFIED',
    permitSha256:details.permitSha256,issuedAtMs:now,expiresAtMs,
    policyEpoch:config.policyEpoch
  };
  const unsigned={
    schema:APPROVAL_SCHEMA,algorithm:'Ed25519',
    authorityKeyId:config.approvalKeyId,statement
  };
  const signature=signRaw(null,Buffer.from(canonical(unsigned)),config.approvalKey).toString('base64url');
  const approval={...unsigned,signature};
  return {
    schema:ENVELOPE_SCHEMA,permit:pending.permit,approval
  };
}
