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

## R2 — Explicit consent receipts (local-only)

- [x] Separate local PhiOS authority from optional PhiID sign-in in the documented contract
- [x] Add a bounded proposed PhiMail/PhiCloud consent catalog and scope allowlist
- [x] Require a verified local identity session, explicit acknowledgment and same-origin mutation headers
- [x] Record and remove short-lived session-bound consent receipts with **no external effect**
- [x] Test unauthorized access, scope injection, expiry, and external issuer endpoint rejection
- [ ] Manually verify Keycloak sign-in → consent → local logout on an operator-owned machine
- [ ] Prove durable consent/audit, real service-side audience/scope validation and revocation (not in R2)
- [ ] PhiCloud authenticated service listing and a genuine PhiMail OIDC adapter (not in R2)
- [ ] User-directed account/data export without credential reuse (not in R2)

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

## R4 — Real Keycloak integration evidence (test-only)

- [x] Add a disposable, loopback-bound Keycloak workflow with per-run masked admin credentials
- [x] Add a real OIDC test harness for PhiID browser redirect, Keycloak login, signed ID Token and issuer/subject validation
- [x] Include consent receipt, replay, logout, and independent second-client token validation in integration harness
- [ ] Confirm GitHub Actions live Keycloak smoke passes against the pinned image
- [ ] Run end-to-end PhiMail **application** login in a separate test rig and verify cross-app session isolation
- [ ] Audit and harden any network-facing account provider before production signup
