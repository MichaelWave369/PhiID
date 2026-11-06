/**
 * R6: opt-in LOCAL-ONLY durable consent-choice audit.
 *
 * No bearer tokens, delegated authority, email addresses, passwords, or
 * service-side effects. An entry records a verified user's human choice.
 * SQLite from Node 22+ ships with Node; no home-built auth/crypto protocol.
 */
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { mkdirSync, lstatSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireSession, validateConsentRequest, ConsentError, SERVICE_CATALOG } from './consent.mjs';
import { randomOpaqueId } from './security.mjs';

export const LEDGER_SCHEMA = 'phiid.local-choice-ledger/0.1';
export const MAX_CHOICE_AGE = 30 * 24 * 60 * 60_000;
export const AUDIT_RETENTION = 90 * 24 * 60 * 60_000;
export const DEFAULT_DB_PATH = fileURLToPath(new URL('./.private/local-consent.sqlite', import.meta.url));

function privatePathStat(path) {
  try { return lstatSync(path); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}
function checkPrivateDirectory(path) {
  let stat = privatePathStat(path);
  if (!stat) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    stat = privatePathStat(path);
  }
  if (!stat?.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('ledger_directory_must_be_private_and_not_symlink');
  }
}
function checkPrivateFile(path) {
  // lstat (NOT exists) also sees dangling symlinks. Never follow a link to
  // an outside path just because its target has not been created yet.
  const stat = privatePathStat(path);
  if (!stat) return;
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('ledger_file_must_be_private_and_not_symlink');
  }
}
function principalKey(session, now) {
  const valid = requireSession(session, now);
  const { issuer, sub } = valid.profile;
  // Pseudonymous indexing, not authentication, signing, or secrecy.
  return createHash('sha256')
    .update('PhiID-R6-subject-key/0.1\0').update(issuer).update('\0').update(sub)
    .digest('hex');
}
function normalized(row, now) {
  return {
    schema: LEDGER_SCHEMA,
    receipt_id: row.receipt_id,
    service: row.service,
    consent_version: row.consent_version,
    requested_scopes: JSON.parse(row.scopes),
    purpose: SERVICE_CATALOG[row.service].purpose,
    recorded_at: new Date(row.recorded_at).toISOString(),
    expires_at: new Date(row.expires_at).toISOString(),
    revoked_at: row.revoked_at === null ? null : new Date(row.revoked_at).toISOString(),
    revocation_reason: row.revocation_reason,
    status: row.revoked_at !== null ? 'revoked_choice'
      : row.expires_at <= now ? 'expired_choice'
      : 'recorded_not_enforced',
    connected: false,
    authority_granted: false,
    service_called: false,
    external_token_revoked: false,
  };
}
function transaction(db, work) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = work();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

/**
 * A local development audit file, NOT a credential store, token grant,
 * authorization server, vault, or remotely discoverable permission endpoint.
 */
export function openLocalChoiceLedger(dbPath = DEFAULT_DB_PATH) {
  if (typeof dbPath !== 'string' || !dbPath.endsWith('.sqlite')) {
    throw new Error('invalid_ledger_file');
  }
  checkPrivateDirectory(dirname(dbPath));
  checkPrivateFile(dbPath);
  // Ensure SQLite's newly created database is private from its first write.
  const oldMask = process.umask(0o077);
  let db;
  try { db = new DatabaseSync(dbPath); } finally { process.umask(oldMask); }
  chmodSync(dbPath, 0o600);
  db.exec([
    'PRAGMA journal_mode = DELETE;',
    'PRAGMA synchronous = FULL;',
    'PRAGMA trusted_schema = OFF;',
    'PRAGMA busy_timeout = 3000;',
    'CREATE TABLE IF NOT EXISTS choice_events (',
    '  receipt_id TEXT PRIMARY KEY NOT NULL,',
    '  principal_key TEXT NOT NULL,',
    '  service TEXT NOT NULL,',
    '  scopes TEXT NOT NULL,',
    '  consent_version TEXT NOT NULL,',
    '  recorded_at INTEGER NOT NULL,',
    '  expires_at INTEGER NOT NULL,',
    '  revoked_at INTEGER,',
    '  revocation_reason TEXT,',
    '  CHECK (service IN (\'phimail\', \'phicloud\')),',
    '  CHECK (revocation_reason IS NULL OR revocation_reason IN (\'user_revoked\', \'superseded\'))',
    ');',
    'CREATE INDEX IF NOT EXISTS idx_choices_owner ON choice_events (principal_key, recorded_at DESC);',
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_choices_one_active',
    'ON choice_events (principal_key, service) WHERE revoked_at IS NULL;',
  ].join('\n'));

  const activeByOwner = db.prepare(
    'SELECT * FROM choice_events WHERE principal_key = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY recorded_at DESC LIMIT 8');
  const historyByOwner = db.prepare(
    'SELECT * FROM choice_events WHERE principal_key = ? ORDER BY recorded_at DESC LIMIT 50');
  const revokeExisting = db.prepare(
    'UPDATE choice_events SET revoked_at = ?, revocation_reason = ? WHERE principal_key = ? AND service = ? AND revoked_at IS NULL');
  const insert = db.prepare(
    'INSERT INTO choice_events (receipt_id, principal_key, service, scopes, consent_version, recorded_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const deleteOld = db.prepare('DELETE FROM choice_events WHERE recorded_at < ?');

  function record(session, payload, now = Date.now()) {
    const key = principalKey(session, now);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
        Object.keys(payload).sort().join(',') !== 'acknowledged,persist_acknowledged,scopes,service' ||
        payload.persist_acknowledged !== true) {
      throw new ConsentError('explicit_durable_storage_acknowledgment_required');
    }
    const approved = validateConsentRequest({
      service: payload.service,
      scopes: payload.scopes,
      acknowledged: payload.acknowledged,
    });
    // Durable choice has an independent maximum age; it is NOT an access token.
    const entry = {
      receipt_id: randomOpaqueId(),
      service: approved.service,
      requested_scopes: approved.scopes,
      recorded_at: now,
      expires_at: now + MAX_CHOICE_AGE,
    };
    transaction(db, () => {
      // Supersedes an earlier choice atomically. Also removes expired active
      // rows, so only one unrevoked row can exist per subject and service.
      revokeExisting.run(now, 'superseded', key, approved.service);
      insert.run(entry.receipt_id, key, approved.service,
        JSON.stringify(approved.scopes), 'local-consent/0.1',
        entry.recorded_at, entry.expires_at);
      deleteOld.run(now - AUDIT_RETENTION);
    });
    const row = db.prepare('SELECT * FROM choice_events WHERE receipt_id = ?').get(entry.receipt_id);
    return normalized(row, now);
  }

  function list(session, now = Date.now()) {
    const key = principalKey(session, now);
    deleteOld.run(now - AUDIT_RETENTION);
    return {
      schema: LEDGER_SCHEMA,
      enabled: true,
      persistent: true,
      authority_granted: false,
      permissions_enforced: false,
      service_calls: false,
      active: activeByOwner.all(key, now).map(row => normalized(row, now)),
      history: historyByOwner.all(key).map(row => normalized(row, now)),
    };
  }

  function revoke(session, service, now = Date.now()) {
    const key = principalKey(session, now);
    if (typeof service !== 'string' || !Object.hasOwn(SERVICE_CATALOG, service)) {
      throw new ConsentError('unsupported_service');
    }
    const changes = transaction(db, () =>
      revokeExisting.run(now, 'user_revoked', key, service).changes);
    return {
      service, removed: changes > 0,
      choice_revoked_locally: changes > 0,
      connection_revoked: false,
      authority_granted: false,
      external_token_revoked: false,
      note: 'Only this local review choice was revoked. No OAuth grant or external service connection existed.',
    };
  }

  return { record, list, revoke, close: () => db.close() };
}
