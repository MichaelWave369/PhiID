# PhiID R6: Verified Local OIDC Session → Explicit Pocket Approval

**Status:** localhost-only development integration. The public GitHub Pages site remains a non-authenticating preview. This is **not** a production action-authority, online account service or audited secret-management system.

## Why this rung exists

PhiID's R4/R5 CI already demonstrates **real Keycloak OIDC authentication** with the audited openid-client flow. NBGPocketMesh's signed executor independently requires an exact Ed25519 permit and a separate Ed25519 approval, but its original approval signer used a synthetic issuer/subject.

R6 adds a local-only, visibly reviewed approval **inside PhiID's verified BFF session**. It keeps the identity boundary distinct from software action authorization:

1. **Identity:** Keycloak verifies an actual disposable local user through OIDC authorization code + PKCE, state/nonce and a validated ID token; PhiID's bridge retains only a short-lived server-side session and (iss,sub).
2. **Planner:** A separate PocketMesh planner and permit signer create a short-lived Ed25519 permit. PhiID cannot manufacture or change its requested task, album, code digest, profile or mode.
3. **Review:** The user pastes the signed permit into a dedicated **localhost-only Pocket Approval Lab** tab. PhiID checks its exact v1 schema, pinned permit public key, audience, expiry, allowed profile and approved issuer/subject before showing album ID/revision, profile, mode, exact permit digest and fixed scope.
4. **Explicit approval:** The authenticated user must click and acknowledge the reviewed action in a separate step. Same-origin action headers are required; a valid cookie without the action confirmation is insufficient.
5. **Signing:** The bridge loads an operator-owned Ed25519 private approval key from a restricted local file and signs the entire permit hash plus its OIDC-session (iss,sub), purpose, audience, scope, policy epoch and short expiry. The private key never reaches the browser or GitHub Pages.
6. **Execution:** PhiID returns a signed approval **envelope for the external PocketMesh executor**. PhiID **does not execute a Pocket Album**, open an executor service, launch a program, call PhiCloud or change the OS.
7. **One use:** The pending approval review is consumed before signing and cannot be confirmed twice. PocketMesh independently enforces its existing single-use signed *execution permit* replay ledger.

**The R2 consent receipt is not an execution grant.** Its existing contract and UI remain untouched.

## Operator setup

R6 is **disabled by default**. Run only on an isolated localhost development environment with a disposable Keycloak realm and disposable user; do not expose ports through tunnels, reverse proxies or the public Internet.

Prepare a reviewed, private Ed25519 approver key using a trusted local tool and store it outside the repository. Store a **different** Ed25519 permit signer key in a separately controlled signer. The approval bridge only needs the permit signer's **public** key.

Provide a restricted (0600 POSIX) JSON config file at an absolute path:

```json
{
  "schema": "phiid.local-pocket-approval-config/0.1",
  "policyEpoch": 1,
  "approvalKeyId": "review-signer",
  "permitKeyId": "permit-signer",
  "permitPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...actual public key...\n-----END PUBLIC KEY-----\n",
  "approvalPrivateKeyFile": "/operator/owned/approver-private.pem",
  "allowedSubjects": ["disposable-keycloak-user-uuid"],
  "allowedProfiles": ["observe", "triage", "health"]
}
```

The private key file must also be owner-restricted (0600 on POSIX). Both the JSON config and key file must be operator-owned **regular files, not symlinks**. In the production threat model, key management should be delegated to a proper external signer/HSM, not handled by a Node process; this local file is solely for the research lab.

On POSIX, start the existing loopback bridge with the operator config path:

```sh
PHIID_POCKET_APPROVAL_CONFIG=/absolute/path/operator-pocket-config.json npm run dev:identity
```

On Windows, set the environment variable in the launching PowerShell process and use Windows ACLs to protect the key and config. The current 0600 POSIX checks are **not a Windows ACL audit**.

Once signed in via the real Keycloak development realm, open `http://127.0.0.1:8786/PhiID/` and select **Pocket Approval Lab**. The tab is not offered on public GitHub Pages. Import a signed, unexpired PocketMesh v1 execution permit, inspect the exact action and check the explicit confirmation box to obtain the signed envelope.

The envelope uses these existing NBGPocketMesh v0 schema identifiers:

- `NBGPocketMesh.PhiIDAuthorizedRequest.v0` with exactly `schema,permit,approval`
- `NBGPocketMesh.PhiIDApproval.v0` Ed25519 approval envelope
- `NBGPocketMesh.PhiIDApprovalStatement.v0` for the fixed `pocket.album.execute` scope and `execute-reviewed-pocket-album` purpose

The signed statement intentionally retains the consumer's existing `subjectAssurance: DECLARED_BY_SIGNER_UNVERIFIED`. **Within this PhiID BFF, the subject originates from a verified local OIDC session**, but a separate PocketMesh process cannot independently validate that statement without the operator-pinned approval key and its own policy. We do not claim that signed strings alone prove a human's identity or comprehension.

## Endpoint policy

- `GET /auth/pocket/status`: limited lab-enabled and session-authorized booleans, no key material or profile attributes.
- `POST /auth/pocket/review`: authenticated, freshly established local OIDC session, same-origin `X-PhiID-Action: pocket-review`, exact JSON `{permit}`. Strict signed-permit verification; stage one short-lived review (maximum 60 seconds or permit/session expiry).
- `POST /auth/pocket/approve`: same verified session and `X-PhiID-Action: pocket-approve`, exact `{reviewId,acknowledged:true}`. Consume the staged review before issuing a second signed approval; cap approval lifetime at 30 seconds, permit expiry and session expiry.
- `POST /auth/pocket/cancel`: authenticated same-origin `X-PhiID-Action: pocket-cancel`; discard any pending review. No approval issued.
- All R6 POST endpoints require fixed loopback Host and TCP peer checks, exact Origin, JSON, bounded request bodies and the existing HttpOnly SameSite session cookie. No remote access, no broad OAuth scope or generic script execution is offered.

## Reproducible verification

```sh
npm install
npm test
npm run build
```

The R6 unit tests cover invalid and expired signed permits, session freshness, issuer/subject changes, operator allowlists, explicit acknowledgment, staged-review replacement, double confirmation, unsafe key paths and independent signer keys.

The existing **PhiID real Keycloak localhost smoke** workflow now adds a disposable test:
- Real Keycloak-verified session obtained using authorization code + PKCE and a disposable non-admin account
- Ephemeral (non-committed) two-key setup, with the approval private key in an owner-only file
- Anonymous and CSRF requests refused; valid session stages one exactly signed synthetic permit
- Missing explicit acknowledgment refused; approved statement independently verified with the approver public key
- Same review cannot be signed twice; R2 profile consent remains non-authoritative
- Disposable user and Keycloak container are cleaned up by the existing workflow

**Important:** the test permit uses deliberately synthetic routing and code digests. It proves PhiID's real OIDC/session-to-approval flow, **not** a live end-to-end PocketMesh execution. Cross-repo acceptance requires pinned compatible issuer/subject and operator public-key policy, plus a separately tested PocketMesh execution.

## Security boundaries

No persistent user consent database, WebAuthn re-authentication per action, device-bound key attestation, production account authority, enterprise policy review, actual user notification, durable cross-service revocation, cross-host replay database, secure remote transport, OS sandbox, or live model/network execution is implemented. A stolen unlocked BFF session or a compromised operator signing key is outside the current defenses; explicit UI review does not eliminate clickjacking or malware concerns beyond the enforced local-only CSP and same-origin checks.

**Next gate:** explicit pinning of PhiID's localhost-dev issuer in NBGPocketMesh's approval verifier under an operator-owned dev-only policy, plus a true cross-repository integration test using a real PocketMesh-generated permit. Never silently relax general HTTPS issuer validation.
