import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEMO_ACCOUNT, SCHEMA_VERSION,
  validatePreviewAccount, previewIdentityKey, createDemoExport
} from './identity.js';

const clone = () => ({ ...DEMO_ACCOUNT });

test('sample profile validates as metadata only', () => {
  assert.equal(validatePreviewAccount(clone()).schema_version, SCHEMA_VERSION);
});

test('issuer and sub together form stable comparison key', () => {
  const original = previewIdentityKey(clone());
  assert.equal(original, previewIdentityKey({ ...clone(), preferred_username: 'renamed' }));
  assert.equal(original, previewIdentityKey({ ...clone(), email: 'new@example.invalid' }));
  assert.notEqual(original, previewIdentityKey({ ...clone(), sub: 'another-user' }));
  assert.notEqual(original, previewIdentityKey({ ...clone(), issuer: 'https://other.invalid/phiid' }));
});

test('extra credential-bearing fields are rejected', () => {
  for (const key of ['token', 'refresh_token', 'password', 'private_key', 'access_token']) {
    assert.throws(() => validatePreviewAccount({ ...clone(), [key]: 'secret' }), /extra/);
  }
});

test('malformed and insecure issuer metadata is rejected', () => {
  for (const issuer of ['http://example.invalid', 'javascript:alert(1)',
    'https://user:pass@example.invalid', 'https://example.invalid/#x',
    'https://example.invalid/?code=x', 'not-a-url', 1, null]) {
    assert.throws(() => validatePreviewAccount({ ...clone(), issuer }));
  }
});

test('malformed account fields fail closed', () => {
  for (const account of [null, [], {}, { ...clone(), email_verified: 'true' },
    { ...clone(), email_verified: true }, { ...clone(), sub: '' },
    { ...clone(), sub: 'bad\nsubject' }, { ...clone(), email: 'broken-email' },
    { ...clone(), preferred_username: '' }]) {
    assert.throws(() => validatePreviewAccount(account));
  }
});

test('export states explicitly that it is not identity proof', () => {
  const result = createDemoExport(clone());
  assert.equal(result.authentic_identity_proof, false);
  assert.equal(result.kind, 'phiid-preview-export-only');
  assert.ok(!('token' in result.account));
  assert.deepEqual(Object.keys(result.account).sort(), Object.keys(DEMO_ACCOUNT).sort());
});

test('no email is required to have a subject', () => {
  const account = validatePreviewAccount({ ...clone(), email: null, email_verified: false });
  assert.ok(previewIdentityKey(account).includes(account.sub));
});


test('PhiMail consumer export wrapper remains a non-authenticating and portable contract',()=>{
  const exportObject=createDemoExport({...clone(),preferred_username:'another-name'});
  assert.deepEqual(Object.keys(exportObject).sort(),['kind','authentic_identity_proof','warning','account'].sort());
  assert.equal(exportObject.kind,'phiid-preview-export-only');
  assert.equal(exportObject.authentic_identity_proof,false);
  assert.ok(typeof exportObject.warning==='string' && exportObject.warning.length>0);
  assert.equal(exportObject.account.schema_version,'phi-account/0.1');
  assert.equal(exportObject.account.email_verified,false);
  assert.equal(previewIdentityKey(exportObject.account),previewIdentityKey(clone()));
  assert.ok(!('role' in exportObject.account));
  assert.ok(!('permissions' in exportObject.account));
});
