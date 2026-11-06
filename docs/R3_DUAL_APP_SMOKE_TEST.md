# PhiID R3: cross-app sign-in verification checklist

**Scope:** PhiID and PhiMail, separate OIDC clients against a disposable local Keycloak realm. **Not** production SSO, active mail hosting, or proof of account portability.

This checklist augments [the merged PhiMail client configuration](R3_PHIMAIL_OIDC_CLIENT.md). It does not replace or rewrite the existing Keycloak realm import.

## Registered clients on `phiid-dev`

| App | Client ID | Exact registered redirect | App-local session |
| --- | --- | --- | --- |
| PhiID | `phiid-bff-dev` | `http://127.0.0.1:8786/auth/callback` | `phiid_session` |
| PhiMail | `phimail-bff-dev` | `http://127.0.0.1:5173/auth/phiid/callback` | `pm_identity` |

Both clients use the same local issuer, `http://127.0.0.1:8080/realms/phiid-dev`, and authorization code + PKCE S256. The redirect origins and session cookie names are intentionally distinct.

## Preflight

1. Update both repositories from their merged `main` branches after their PRs are reviewed and merged. PhiMail's relevant PR is [#6](https://github.com/MichaelWave369/PhiMail/pull/6).
2. From PhiID, configure a unique, privately stored Keycloak bootstrap administrator password in gitignored `dev/keycloak/.env`.
3. Run the existing [R1 Keycloak lab](R1_LOCAL_IDENTITY_LAB.md) on loopback only.
4. **Existing realm caution:** `start-dev --import-realm` does not overwrite an already-existing realm. In the Keycloak Admin UI, inspect `phiid-dev` and confirm **both** client IDs and their exact callbacks; add the PhiMail client manually if needed. Never delete an existing realm with wanted test data.
5. Create one disposable non-admin test user inside `phiid-dev`. Do not enter a real mailbox password or private personal data.
6. In PhiID, `npm install`, `npm run build`, `npm run dev:identity`. Open `http://127.0.0.1:8786/PhiID/`.
7. In PhiMail, follow its [local PhiID client instructions](https://github.com/MichaelWave369/PhiMail/blob/main/docs/LOCAL_PHIID_R2.md), using the exact `127.0.0.1:5173` origin expected by its current implementation.

## Independent login checks

1. Before login, PhiID `GET /auth/session` returns `authenticated: false` and PhiMail's identity session likewise reports no verified principal.
2. Sign in **only to PhiID** via Keycloak. Confirm a verified issuer/subject in PhiID. PhiMail must remain unauthenticated until it completes its own login flow.
3. Sign in **separately to PhiMail** using its own OIDC start/callback. Confirm the same `iss` and `sub` for the test user.
4. Confirm the browser has *distinct* HttpOnly app-local cookies and the frontend never displays or stores access/refresh/ID tokens.
5. End PhiMail's application session and confirm PhiID remains authenticated. The upstream Keycloak SSO session may still be active.
6. Complete PhiMail login again, then end the PhiID application session; PhiMail's session should remain independently active until its own expiry or logout.
7. Confirm Gmail OAuth, mailbox data, PhiCloud services and PhiOS effect permissions remain unaffected throughout.

## Fail-closed and isolation checks

- Callback without flow cookie, with changed `state`, duplicate `state`, or an expired flow must not create a session.
- Keycloak must reject unregistered redirect origins and invalid client IDs; no wildcard redirect or web origin is registered.
- A synthetic PhiID JSON export must **never** become a sign-in artifact.
- A session valid at one relying party must not be accepted as the other relying party's cookie.
- PhiID consent receipts from R2 are only local display records; they do **not** grant PhiMail or PhiCloud tokens.
- With PhiMail's local PhiID opt-in disabled, no new sign-in route is operational. GitHub Pages remains a static demo.
- Stop the Keycloak process and confirm local PhiOS and the unrelated PhiMail demo continue to work without requiring identity infrastructure.

## Evidence to record

Record the date, git SHAs, Keycloak realm/client configuration, **pass/fail** for each test, and redacted error types without copying usernames, secrets, session cookies, tokens or callback authorization codes.

**Automated CI validates only the checked-in configuration and unit/integration-test contracts. The actual two-application login on a running Keycloak server remains unverified until an operator executes this checklist.**
