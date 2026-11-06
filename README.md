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

### R3: Independent PhiMail OIDC client

The local Keycloak test realm now includes a second, separately registered `phimail-phiid-dev` client, with an exact `http://localhost:5173/auth/phiid/callback` redirect. It uses the same **development** issuer but not the same application cookie, token or authorization scope. PhiMail's companion R2B feature branch implements its own optional loopback relying party.

The verified issuer/subject pair can be compared after separately signing into both apps with the same disposable Keycloak user. This **does not** grant Gmail/mailbox, PhiCloud or PhiOS access.

Read [the R3 dual-client test plan](docs/R3_PHIMAIL_DUAL_CLIENT.md). End-to-end real Keycloak login remains unverified until manually tested.

### R1: Optional local identity lab

The R1 development branch adds an actual standards-based **localhost-only** identity flow with Keycloak and `openid-client` on a small Node bridge. It uses authorization code + PKCE S256, random state/nonce, exact local issuer and callback, short-lived HttpOnly session cookies, and discards OAuth tokens without giving them to browser JavaScript.

**This is experimental.** The hosted GitHub Pages UI stays a synthetic preview, and the local identity session cannot authorize PhiOS, PhiCloud or PhiMail actions.

See **[Local Identity Lab setup and verification](docs/R1_LOCAL_IDENTITY_LAB.md)** for private credential setup, local Docker Compose steps, dev-client configuration, known limitations and end-to-end smoke checklist.

PhiMail's R1 Field Connections panel can inspect the synthetic export as **untrusted display-only data**. See [PhiMail consumer compatibility](docs/PHIMAIL_CONSUMER.md). No shared authentication or account connection is implied.

Read the [identity contract](docs/IDENTITY_CONTRACT.md), [threat model](docs/THREAT_MODEL.md), [roadmap](docs/ROADMAP.md) and [agent guardrails](AGENTS.md).

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
