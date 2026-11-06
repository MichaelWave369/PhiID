# PhiID threat model and R0 exclusions

**Not a security audit.** This is a forward-looking checklist for a future real identity deployment. The R0 website has no real users, authentication or backend.

| Risk | Required future defense |
| --- | --- |
| Forged issuer / subject claim | Vetted OIDC client validates signed ID token, expected issuer/audience and all critical claims |
| Authentication mistaken for action permission | Independent per-service policy plus explicit PhiOS local effect approval |
| Reassigned or changed email address | Key ownership by verified (`iss`, `sub`), never address |
| Authorization code injection / redirect abuse | Strict registered redirect URIs, state/nonce binding, PKCE S256, issuer mix-up defense |
| Credential or session theft | Passkeys, hardened cookies/BFF, TTLs, rotation, revocation, CSP and secret hygiene |
| Lost passkey or locked mailbox | Multiple pre-enrolled recovery factors, rate limits, human-reviewed recovery policies |
| Lateral access across users or tenants | Tenant+subject-based isolation, resource ownership checks, deny-by-default scopes |
| Token scope escalation | Correct audience and scope validation at every resource server |
| Network outage | No dependence of local PhiOS operations on PhiID availability |
| Misleading demo | Prominent non-authentication labels; no bogus 'logged in' or 'security enabled' indicators |
| Third-party ecosystem bridge | Separate opt-in and explicit authorization; no silent activation of PhiServe or PhiCloud services |

## R0 implemented protections

- No password/credential input or client-side token storage.
- No network authentication requests, registration endpoints or API mutations.
- All account data is synthetic and memory-only; JSON export is labeled unusable for authentication.
- Pure metadata validation rejects unexpected fields, including common credential keys.
- Link toggles are in-memory demonstrations and change no remote state.

## R0 not implemented

No account signup, login, hosted IdP, OIDC relying party, MFA/passkeys, session management, email verification, audit log, encryption, private user persistence, API authorization, incident recovery, or production deployment.

## Go/no-go for real accounts

Do not accept real credentials or personal account data until an audited IdP is selected, configured with HTTPS and a reviewed threat model, tested for token validation, recovery, CSRF, browser security, rate limits, data portability and authorization isolation. Run external security review before public production registration.
