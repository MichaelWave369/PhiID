# PhiID roadmap

All checkboxes are implementation evidence targets, not claims that the service exists.

## R0 — Public foundation and identity center preview

- [x] Canonical identity and ecosystem boundary documentation
- [x] Browser preview with clearly fake persona and in-memory link simulation
- [x] Safe metadata shape validator and sample export (not credential)
- [ ] PR CI green on Node 22
- [ ] GitHub Pages deployment confirmed after merge

## R1 — Audited development identity provider

- [x] Commit a local-only Keycloak Compose profile and restricted dev client realm import (not deployed by CI)
- [x] Document exact registered callback and PKCE S256 requirements
- [x] Implement an opt-in Node loopback OIDC client bridge using vetted `openid-client`; server-side flow state and ephemeral sessions
- [x] Add security-helper and unauthenticated-route tests
- [ ] Run an operator-controlled real Keycloak sign-in smoke test with a test user and verify callback, ID token and nonce validation
- [ ] Add real end-to-end tests for mismatch issuer, audience and expired tokens against a disposable test realm
- [ ] Complete separate threat review and security hardening for any non-loopback deployment
- [x] No admin credentials, live tokens, signing keys or user PII committed

## R2 — Consent and PhiCloud bridge

- [ ] Separate local PhiOS identity from optional PhiID linkage
- [ ] Service-level audience/scope checks and resource ownership
- [ ] PhiCloud authenticated service listing (different from the R0 registry)
- [ ] Explicit consent screen, revocation, logout and offline fallback
- [ ] Account/data export without credential reuse

## R3 — PhiMail, WebOS, Desktop and Mobile

- [ ] PhiMail Relying Party adapter; mailbox remains optional
- [ ] WebOS, desktop and native mobile OIDC clients registered and security-tested
- [ ] Passkey enrollment, device-loss recovery and account-link review
- [ ] Test cross-device sign-in without granting cross-device OS effects

## R4 — Production readiness (separate security gate)

- [ ] External threat-model and implementation review
- [ ] Strong auth and recovery, abuse controls, rate limits, monitoring
- [ ] Secure isolated hosting, DNS, HTTPS, secret rotation, backups
- [ ] Data deletion/export and documented incident response
- [ ] Deployment proof and explicit go/no-go before public sign-ups

**Never claim that a visual identity preview or passing unit test proves a secure identity service.**
