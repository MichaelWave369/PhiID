# Φ PhiID

**One identity. Your authority.**

PhiID is the proposed **sovereign account and identity layer** for PhiOS Desktop, PhiOS WebOS, PhiOS Mobile, PhiMail, PhiCloud and opt-in Phi ecosystem applications.

> **Status: R2 consent contract prototype on top of the R1 local identity lab.** The public GitHub Pages site remains a clearly labeled non-authenticating preview. An optional localhost-only Keycloak + OpenID Connect lab has been added on a development branch; it has no production account registration, PhiOS action authority, hosted PhiMail delivery or PhiCloud permissions. Full end-to-end sign-in has not yet been confirmed on operator hardware.

## Core rules

- **PhiID identifies, PhiOS authorizes local actions.** Login is not a permission to run code, access devices, read files or bypass consent.
- **Accounts are not email addresses.** The durable user key is the OpenID Connect issuer/subject pair (`iss`, `sub`). Addresses and usernames can change.
- **Offline PhiOS works without PhiID.** Linking PhiID is voluntary and reversible.
- **PhiMail is the email experience, not the identity root.** A working mailbox is not necessary for local PhiOS access.
- **PhiCloud hosts optional services, not ownership of the user's computer or data.**
- **No homebrew cryptography or identity server.** Future sign-in must be built on audited OpenID Connect and WebAuthn-capable software, with correct client and backend token validation.
- **Portability over captivity.** User-directed export and eventual recovery/migration mechanisms are first-class requirements.

## R5: Real PhiID ↔ PhiMail app-bridge integration test

The dedicated [R5 dual-app Keycloak CI](.github/workflows/dual-app-e2e.yml) checks out a **pinned PhiMail commit** in an isolated test directory, runs its real Node bridge through its real Vite same-origin proxy, and completes separate signed Keycloak logins with PhiID and PhiMail. It exercises session independence, logout, replay refusal and Gmail-read denial without an independent mailbox token.

**Development testing only.** R5 does not deploy account hosting, grant access to PhiCloud, run Gmail OAuth with real users or authorize PhiOS local actions. See [R5 real dual-app verification](docs/R5_REAL_DUAL_APP_KEYCLOAK.md).

## R4: Real disposable Keycloak integration test

The dedicated [R4 Keycloak smoke workflow](.github/workflows/keycloak-e2e.yml) boots a real localhost-only Keycloak server with an ephemeral admin and test user. It exercises the real PhiID browser authorization-code flow, validates signed OIDC identity through the vetted client, checks a non-authoritative R2 consent receipt, tests logout/replay denial, and separately verifies the second registered PhiMail client can validate a real ID token for the same user.

**Boundary:** This does **not** start PhiMail's own bridge and therefore is not proof of end-to-end two-app login or production account hosting. See [the exact R4 coverage and local setup](docs/R4_REAL_KEYCLOAK_SMOKE.md).

## R0 scope and quick start

This milestone defines account metadata, offers an offline-capable PhiID Account Center preview, and includes deterministic tests and a CI/Pages deployment workflow. It **does not issue tokens, validate real ID tokens, register accounts or authenticate users**.

The browser preview includes a synthetic profile, clearly simulated app linking, proposed passkey/OIDC security screens, and user-directed export of fake metadata. No credentials are requested, and no remote authentication or data-sync operations are performed.

Requirements: Node.js 22+.

~~~sh
npm install
npm test
npm run dev
npm run build
~~~

For a repository configured to deploy GitHub Pages via Actions, the planned static preview address is https://michaelwave369.github.io/PhiID/ after a successful deployment. It is **not** a production identity endpoint. The browser bundle intentionally contains zero signing keys, secrets, tokens or user records.

### R2: Local consent receipts, not live app linking

The R2 branch adds a **Consent Lab** view to the local identity bridge (not GitHub Pages). Only a verified local Keycloak session can record and remove short-lived proposed PhiMail and PhiCloud consent receipts.

These are **explicitly non-authoritative, not OAuth grants and not remote connections**. They have tightly allowlisted proposed scopes, session-limited expiry and clear removal semantics. They never call PhiMail or PhiCloud, send mail, read files or authorize PhiOS actions.

Read [the R2 consent contract](docs/R2_LOCAL_CONSENT_CONTRACT.md), including exactly what is still unverified.

### R1: Optional local identity lab

The R1 development branch adds an actual standards-based **localhost-only** identity flow with Keycloak and `openid-client` on a small Node bridge. It uses authorization code + PKCE S256, random state/nonce, exact local issuer and callback, short-lived HttpOnly session cookies, and discards OAuth tokens without giving them to browser JavaScript.

**This is experimental.** The hosted GitHub Pages UI stays a synthetic preview, and the local identity session cannot authorize PhiOS, PhiCloud or PhiMail actions.

See **[Local Identity Lab setup and verification](docs/R1_LOCAL_IDENTITY_LAB.md)** for private credential setup, local Docker Compose steps, dev-client configuration, known limitations and end-to-end smoke checklist.

PhiMail's R1 Field Connections panel can inspect the synthetic export as **untrusted display-only data**. See [PhiMail consumer compatibility](docs/PHIMAIL_CONSUMER.md). No shared authentication or account connection is implied.

Read the [identity contract](docs/IDENTITY_CONTRACT.md), [threat model](docs/THREAT_MODEL.md), [roadmap](docs/ROADMAP.md) and [agent guardrails](AGENTS.md).

The local Keycloak realm now includes a separate **PhiMail OIDC test client** using the same issuer with independent application sessions. See [PhiMail dev client setup](docs/R3_PHIMAIL_OIDC_CLIENT.md). No mailbox access or service permissions follow.


### R6: Verified local Pocket action review (development only)

The [Pocket Action Approval Lab](docs/R6_POCKET_ACTION_APPROVAL.md) adds an **optional, disabled-by-default** review screen visible only through PhiID's `127.0.0.1:8786` identity bridge. It requires a **real Keycloak-verified OIDC session**, a separate valid signed PocketMesh execution permit, an explicitly acknowledged review of the exact album action, and an operator-owned **independent Ed25519 approval signing key**. The signing key is loaded only by the protected development server, never shipped to GitHub Pages or browser JavaScript.

The second signed statement binds purpose, scope, audience, approval ID, issuer/subject from the verified local session, policy epoch, permit digest and a short expiration. The existing R2 consent receipts **cannot grant execution authority**. The signing session is limited to the operator's allowlisted disposable subjects and expires, and the service does not execute PocketMesh code.

Use `npm test` and review the opt-in [real Keycloak smoke test](docs/R6_POCKET_ACTION_APPROVAL.md). The test verifies sign-in plus user acknowledgment and signature issuance with ephemeral keys; it does **not** demonstrate live PocketMesh execution, production human consent, passkeys, key rotation or OS permissions.

## Ecosystem

- [PhiOS](https://github.com/MichaelWave369/PhiOS)
- [PhiMail](https://github.com/MichaelWave369/PhiMail)
- [PhiCloud](https://github.com/MichaelWave369/PhiCloud)
- [PhiServe](https://github.com/MichaelWave369/PhiServe)

See the [PhiCloud identity boundary proposal](https://github.com/MichaelWave369/PhiCloud/blob/main/docs/PHIID_PHIMAIL_IDENTITY.md).

## Security references

- [OpenID Connect Core, subject stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability)
- [RFC 9700, OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)

**License:** MIT.


### R7: Real Keycloak-to-PocketMesh integration acceptance

PhiID's [R7 real cross-repository smoke test](docs/R7_REAL_POCKETMESH_INTEGRATION.md) now checks out a **pinned, reviewed NBGPocketMesh commit** and uses its actual E0 router, signed-permit generator, independent approval verifier and one-shot executor. A **real disposable Keycloak OIDC session** in PhiID reviews and explicitly approves the exact signed permit. The child worker performs the synthetic network-health album once, then refuses replay. The test also rejects forged approvals, unapproved actions and non-authoritative R2 consent.

This is a **localhost-only development acceptance test**, not production user authorization or permission for real PhiOS effects. The confirmed CI run uses temporary signer keys and a disposable user, never a live network device. Run it through the existing real-Keycloak workflow; its sibling code is intentionally pinned and [the limits are documented](docs/R7_REAL_POCKETMESH_INTEGRATION.md).
