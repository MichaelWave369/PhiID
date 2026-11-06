# Φ PhiID

**One identity. Your authority.**

PhiID is the proposed **sovereign account and identity layer** for PhiOS Desktop, PhiOS WebOS, PhiOS Mobile, PhiMail, PhiCloud and opt-in Phi ecosystem applications.

> **Status: R0 foundation. No live authentication exists.** The first pull request provides a browser-based, clearly marked identity-center *preview* and a tested, portable account-metadata contract. This is not an OpenID Provider, password service, account registry, passkey enrollment system, or source of real authorization.

## Core rules

- **PhiID identifies, PhiOS authorizes local actions.** Login is not a permission to run code, access devices, read files or bypass consent.
- **Accounts are not email addresses.** The durable user key is the OpenID Connect issuer/subject pair (`iss`, `sub`). Addresses and usernames can change.
- **Offline PhiOS works without PhiID.** Linking PhiID is voluntary and reversible.
- **PhiMail is the email experience, not the identity root.** A working mailbox is not necessary for local PhiOS access.
- **PhiCloud hosts optional services, not ownership of the user's computer or data.**
- **No homebrew cryptography or identity server.** Future sign-in must be built on audited OpenID Connect and WebAuthn-capable software, with correct client and backend token validation.
- **Portability over captivity.** User-directed export and eventual recovery/migration mechanisms are first-class requirements.

## R0 scope

The forthcoming R0 PR defines account metadata, exposes an offline preview of the PhiID Account Center, and adds deterministic tests/CI. It **does not issue tokens, validate real ID tokens, register accounts or authenticate users**.

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

**License:** MIT (pending R0 scaffold).
