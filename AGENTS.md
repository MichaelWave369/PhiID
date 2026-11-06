# PhiID agent guardrails

PhiID is a **security-critical identity project**, but the R0 site is **not a login system**. Preserve those distinctions.

1. Do not invent, simulate as real, or deploy custom password verification, token issuance, JWT signature checking, passkey authentication, OIDC endpoints, user recovery, SSO or account provisioning. Use audited components and a reviewed deployment design in a later milestone.
2. R0 metadata contracts are untrusted, unsigned **display data only**. Export files, the demo issuer, account subject, browser state and link toggles must never be interpreted as identity proof or permission grants.
3. Authentication != authorization != PhiOS effect authority. A valid remote account must never bypass PhiOS local approval or grant broad device access.
4. Email/username are mutable attributes. Stable principal identity is an issuer+subject pair verified by a real OIDC relying party. Do not use an email address as a primary key.
5. PhiOS must remain usable offline and without an account. Disconnecting PhiID must not delete local data or revoke independent OS capability.
6. PhiMail owns mail UI and optional mailbox adapters. PhiCloud owns optional remote services. PhiID owns future identity integration and account lifecycle only.
7. Never commit secrets, password-like input, recovery tokens, client secrets, ID tokens, PII, or signing keys. Do not put them in public GitHub Pages bundles or logs.
8. Separate demos and declared future plans from working integration. Never display invented connected/healthy/secure states.
9. Review every new remote endpoint, write operation, redirect and credential flow against the security threat model. CI green does not constitute a security audit.
10. Prefer accessible, deterministic, well-labeled interfaces and testable pure contract helpers.

## R1 local OIDC bridge constraints

- `dev/keycloak/compose.yaml` and `dev/identity-lab/server.mjs` are **local-only**. Never add `0.0.0.0` bindings, public DNS, tunnels, proxy ingress or GitHub Pages login capability to this development deployment.
- `openid-client` handles token/ID Token validation. Never parse an unverified JWT as an authenticated account. No login button on the static GitHub Pages site.
- Treat `allowInsecureRequests` as an explicit exception for the fixed HTTP `127.0.0.1` realm only. A production project MUST use HTTPS, a separately vetted configuration and reviews.
- PKCE verifier, state and nonce stay server-side and short-lived. No token material in browser JS or storage. Display-only verified profiles never grant PhiCloud access or PhiOS effect authority.
- A valid local session proves only a local development OIDC sign-in at that moment. It does not imply enterprise-grade recovery, production identity, revocation or account lifecycle support.
- All tests in CI are automated contract/route checks; end-to-end Keycloak login remains a separately documented manual test until an isolated integration rig exists.

## R2 consent receipt boundaries

- No receipt issued by `dev/identity-lab/consent.mjs` may authorize any remote or local action, token minting, data access, file access, mailbox access or PhiOS effects.
- Service and proposed scopes must remain fixed allowlists. Do not use wildcard scopes, client-supplied subject IDs, arbitrary service URLs or runtime-discovered permissions.
- Require already-verified local R1 identity to record a receipt; user must explicitly acknowledge the scope and purpose.
- Consent receipts are volatile session state, not durable evidence of consent, account linkage or provider revocation.
- Removal only deletes a local receipt. Clearly report that no external access token was revoked.
- GitHub Pages must remain a non-authenticating preview; never load local consent controls or cookies on public Pages.
- The R1 Identity Lab's pinned discovery endpoint and issuer must not be weakened to allow arbitrary identity provider URLs in development.

## R4 real-provider CI safety

- Keep Keycloak test setup disposable. Generate the bootstrap password in the CI job, mask it, and never commit even throwaway admin credentials.
- R4's admin-cli password grant is **only for ephemeral Keycloak test setup**; do not turn it into a PhiID application login or a user-facing authentication method.
- The smoke script must never log OAuth codes, ID/access tokens, cookies, passwords or full callback URLs.
- Accept redirects only to the hard-coded loopback Keycloak issuer or each exact registered client callback; prevent arbitrary URL/proxy input.
- A green R4 smoke run proves only the test's stated scope. PhiMail's own app bridge, production deployment, passkeys, Gmail authorization and PhiOS local effect enforcement remain separately unverified.
