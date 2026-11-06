# PhiID R6 — Durable local choice ledger (non-authoritative)

**Status:** development-only persistence for explicit consent-review history. **Not a live app connection, OAuth grant, permission, revocation propagation or production identity feature.**

R2 could save a consent-review receipt only for one verified local browser session. R6 optionally persists *review choices* across bridge restart and new verified logins. This is a deliberate intermediate rung before PhiCloud or PhiMail resource authorization.

## Local flow

1. Sign into PhiID with the real `phiid-dev` Keycloak development realm via `http://127.0.0.1:8786/PhiID/`.
2. In the local-only **Consent Lab**, the separate **R6: Persistent choice history** panel appears.
3. By default it reports **disabled**. No persistent records exist until the operator opts in.
4. To opt in, set `PHIID_LOCAL_LEDGER=1` **only in the localhost PhiID bridge process** and restart `npm run dev:identity`. This environment variable is **not** a publicly available server setting.
5. For PhiMail or PhiCloud, review the exact fixed scope `profile.basic.read`, check the dedicated persistent-storage acknowledgment, then click **Save local choice**.
6. A verified user can revisit their recorded choice after signing in again. They can explicitly revoke their local choice and inspect the retained, bounded audit history.

The existing R2 temporary receipt routes remain separate and unchanged. A persistent choice does not create or extend an R2 temporary receipt.

### API (localhost development only)

All routes keep R1's loopback peer/Host restrictions, no-store responses, and the real OIDC-verified session requirement.

| Route | Required checks | Outcome |
| --- | --- | --- |
| `GET /auth/ledger` | Verified PhiID session | Returns active review choices and bounded history for this `(iss, sub)` only |
| `POST /auth/ledger` | Verified session, exact same-origin `Origin`, `X-PhiID-Action: ledger-record`, bounded `application/json` | Records only an allowlisted service/scope with both `acknowledged:true` and `persist_acknowledged:true` |
| `DELETE /auth/ledger/{phimail|phicloud}` | Verified session, exact same-origin `Origin`, `X-PhiID-Action: ledger-revoke` | Marks the current local choice revoked, and retains an audit record |

Without `PHIID_LOCAL_LEDGER=1`, `GET` is a verified-session read returning `enabled:false`; mutations return HTTP 404 and do not create the database. No unauthenticated principal can read the enabled ledger.

The R6 return contract is `phiid.local-choice-ledger/0.1`. Every recorded choice explicitly returns `connected:false`, `authority_granted:false`, `service_called:false`, and `external_token_revoked:false`. A revoke response always returns `connection_revoked:false` and `external_token_revoked:false`, because no external grant was ever issued.

### Data minimization and local protection

- Storage is one SQLite database at `dev/identity-lab/.private/local-consent.sqlite`. The entire `.private/` folder is gitignored.
- Files and containing directory are restricted to local owner permissions (`0600` file, `0700` directory) on POSIX runners. Existing unsafe paths, symlinks, or broadly readable database files fail closed.
- The database records **a SHA-256 pseudonymous index of the verified issuer+subject pair**. It never stores email, username, password, browser cookie, ID/access/refresh token, signing key, mailbox data or file content.
- This SHA-256 index is **not** a signing key, password hash, credential, secret, or account authentication method. Protect the local database anyway; metadata and subject linkage can still be sensitive.
- Recorded choices automatically stop appearing as active after **30 days**, even if the user never clicks revoke. History is retained for at most **90 days** when the ledger is opened and queried/updated; old entries are pruned.
- The database stores only the exact allowlisted proposed service and scope, timestamps, locally generated opaque receipt ID and revocation reason (`user_revoked` or `superseded`).
- Replacing a choice transactionally supersedes the earlier record; explicit revoke is idempotent and does not alter other users' rows.
- No background scheduler, cloud export or automated deletion outside this local database process is implemented. Backups of the database, if a user creates them, are outside R6's retention controls.

### Security limitations

SQLite here is provided by Node 22's built-in `node:sqlite` module. It is still an **experimental** Node API in some Node 22 versions, so this R6 local prototype is intentionally not a foundation for internet-facing identity hosting.

**An explicit persisted choice is still NOT authorization.** Real PhiCloud and PhiMail access will need separate HTTPS services, properly issued audience- and scope-restricted access tokens, service-side signature/expiry checks, verified resource ownership, explicit linking, durable auditing, revocation propagation and offline fallback. Do not use these ledger rows alone to permit any resource access.

PhiOS continues to run offline without PhiID. Unlinking or revoking a choice does not delete any local PhiOS data, change device permissions, send email or delete cloud files.

### Test coverage

- `npm test`: checks persisted restart behavior, subject isolation, exact scope/consent fields, replacement, revocation, expiry, private file permissions, symlink rejection and default-disabled HTTP endpoints.
- Real [Keycloak smoke CI](../.github/workflows/keycloak-e2e.yml): starts disposable Keycloak, verifies a signed OIDC login, then records and revokes a durable choice through the HTTP API. The test database is deleted at the end.
- The R5 [dual-app Keycloak test](../.github/workflows/dual-app-e2e.yml) continues unchanged; it validates independent PhiID/PhiMail application logins and isolation, not database-backed service authorization.

For production authorization R7 and beyond, migrate intentionally to a vetted persistent identity/consent data model and review the threat surface before exposing any endpoint outside loopback.
