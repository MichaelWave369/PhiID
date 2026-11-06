# PhiID R4 — Real Keycloak CI smoke test

This milestone introduces a **real, disposable Keycloak** identity-provider integration test. It is different from the deterministic, mocked R1/R3 unit tests: CI runs Keycloak `26.8.2`, provisions a throwaway user through Keycloak's own Admin API, and completes real authorization-code and token-validation exchanges.

## What the automated test actually proves

1. Keycloak boots from the committed `phiid-dev` realm file and advertises the expected local issuer.
2. An ephemeral, non-admin account can authenticate through the Keycloak-hosted username/password login form.
3. PhiID's `127.0.0.1:8786` bridge creates PKCE/state/nonce values, receives the real callback, uses `openid-client` for a cryptographically verified token exchange, and creates a short-lived display-only local session.
4. A callback without the correct PhiID flow cookie is rejected, and a previously consumed callback cannot be replayed.
5. `/auth/session` contains the verified `(iss,sub)` and does not expose access tokens, refresh tokens or application permissions.
6. Consent recording is denied without a verified session and denied without matching same-origin action headers. With a verified session the API records a non-authoritative local receipt with `connected:false` and `authority_granted:false`, supports its removal, and supports local logout.
7. The *separately registered* `phimail-bff-dev` client can perform **its own real OIDC authorization-code and signed ID Token validation** for the same disposable user. The verified subject matches, while the client `aud` remains distinct.

### Important test coverage limit

The second-client step validates **the provider's PhiMail client registration through a separate `openid-client` instance**. It does **not** start the PhiMail frontend or PhiMail's own relying-party Node bridge, so it does **not** prove PhiMail's complete application sign-in, Gmail session isolation under live Keycloak, or cross-app logout. Those remain on the [dual-app manual test checklist](R3_DUAL_APP_SMOKE_TEST.md).

The test is not a production security audit, account hosting, passkey enrollment, TLS validation, persistent consent audit, email provisioning or an authorization grant to PhiCloud or PhiOS.

## Run on GitHub Actions

The opt-in integration workflow is `.github/workflows/keycloak-e2e.yml`; it runs on relevant PRs and pushes to `main`, and can also be run through **Actions → PhiID real Keycloak localhost smoke → Run workflow**.

- Creates a fresh admin password with `openssl rand`, masks it in CI logs and stores it only as a temporary job environment variable.
- Starts Keycloak through the existing Docker Compose development profile, strictly bound to IPv4 loopback.
- Waits for real OIDC discovery, registers a random non-admin test user with a random throwaway password, executes the sign-in flow and deletes the test user.
- Removes the Keycloak container even if testing fails.
- Does not check credentials, cookies, OAuth tokens, callback codes or user PII into source control; diagnostics avoid logging raw provider errors.
- Has a bounded CI timeout and uses the existing pinned Keycloak image.

## Run locally (operator-controlled development)

Use only a disposable realm and account. Install Node 22+, Docker Engine/Desktop, and verify ports 8080 and 8786 are free. From the PhiID checkout root, supply a strong private admin password via the gitignored `dev/keycloak/.env` described in [R1 setup](R1_LOCAL_IDENTITY_LAB.md), then start the Compose stack.

```sh
npm install
PHIID_E2E_ENABLE=1 KC_BOOTSTRAP_ADMIN_USERNAME=local-admin KC_BOOTSTRAP_ADMIN_PASSWORD='YOUR_PRIVATE_ADMIN_PASSWORD' node dev/keycloak/live-e2e.mjs
```

This example is **POSIX shell syntax**. In PowerShell, set these as process environment variables instead of pasting production secrets into history. For the CI run, no user password is needed because all credentials are generated or supplied ephemerally.

The script intentionally requires explicit `PHIID_E2E_ENABLE=1` and its non-production localhost provider; it does not run under `npm test` or on the hosted GitHub Pages site.

## No authority leakage

PhiID verification remains `(iss,sub)` identity evidence, not generalized resource authorization. The test must not contact Gmail, PhiCloud, PhiServe or the operating system's effect interface. R2 consent receipts remain display-only and have **no access grants or actual revoke events**.

Official reference: https://www.keycloak.org/getting-started/getting-started-docker
