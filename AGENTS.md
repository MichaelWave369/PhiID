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
