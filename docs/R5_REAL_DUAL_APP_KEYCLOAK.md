# PhiID R5: Real dual-application Keycloak integration

**Test-only and localhost-only.** This R5 rung goes beyond R4's individual PhiMail client token validation: it starts the **real PhiMail Node backend and Vite development proxy**, plus the real PhiID Node identity bridge and Keycloak, and completes independent authorization-code flows with a disposable user.

## Exact tested topology

```text
Keycloak DEV realm  http://127.0.0.1:8080/realms/phiid-dev
    |                         |
    | OIDC code + PKCE S256    | OIDC code + PKCE S256
    v                         v
PhiID Node bridge         PhiMail Vite (same-origin proxy)
127.0.0.1:8786            127.0.0.1:5173
    |                         |
    |                         v
    |                    PhiMail Node bridge
    |                    127.0.0.1:8787
    |
    +-- PhiID session cookie: phiid_session
                           PhiMail session cookie: pm_identity
```

**Real provider:** Keycloak `26.8.2` from PhiID's preexisting committed development Compose profile, with two independent registered clients (`phiid-bff-dev` and `phimail-bff-dev`). OIDC token verification uses each application's existing audited `openid-client` integration. This does not introduce a new credential or token implementation.

**Pinned PhiMail source:** commit `14e86b05bc73ffab68d92ebd1bd722e331879e09`. The workflow checks out that specific known code revision under `integration/phimail/` and installs its dependencies. It never changes PhiMail's live repository and does not run any arbitrary remote workflow. To test a newer PhiMail version, review and deliberately update the pin in `.github/workflows/dual-app-e2e.yml`.

## What R5 must prove

- Neither local app is signed in before the flow.
- A real Keycloak authorization-code exchange through PhiMail's app routes creates a verified `(iss, sub)` and short-lived app-local session.
- PhiID remains unauthenticated after **only** PhiMail logs in.
- A separate real PhiID application login verifies **the same** issuer and subject for the disposable Keycloak test user.
- Reusing the PhiMail app cookie against PhiID, or PhiID's cookie against PhiMail, does not create a session.
- Calling the PhiID consent endpoints with only PhiMail's cookie is rejected.
- A verified PhiMail identity alone does not establish a Gmail provider session or grant inbox read access. The R3 mailbox-review endpoint remains ineligible without its independent Gmail session.
- A callback with no matching in-process flow cookie fails; a consumed PhiMail callback fails on replay.
- A malformed PhiMail logout action is rejected. Logging out of either app does not terminate the other application's own session.
- The disposable test user is deleted, and the Keycloak container is stopped in the cleanup step.

## Running in CI

The workflow `PhiID + PhiMail real dual-app OIDC smoke` runs on relevant pull requests or changes to main, and may be dispatched manually. The existing R4 test continues to run separately.

Each run uses a freshly generated, masked Keycloak administrator password and a randomly named, non-admin temporary user with a random test password. All authentication requests stay within fixed IPv4 loopback endpoints. **Do not print** callback URLs, user credentials, session cookies, access tokens or Keycloak login HTML in build logs.

## Running on your own development machine

Requirements: Node 22+, Docker Compose, open ports 8080, 8786, 8787 and 5173. Use only a disposable local Keycloak realm and never forward these ports. Clone the exact PhiMail fixture to `integration/phimail` and check out the pinned commit listed above. Install PhiID and PhiMail Node dependencies, then start Keycloak through the [R1 Keycloak development setup](R1_LOCAL_IDENTITY_LAB.md).

Set `PHIID_E2E_ENABLE=1`, `PHIID_DUAL_APP_E2E=1`, `NODE_ENV=test`, and the matching private `KC_BOOTSTRAP_ADMIN_USERNAME`/`KC_BOOTSTRAP_ADMIN_PASSWORD`, then run:

```sh
node dev/keycloak/dual-app-e2e.mjs
```

Do not commit or paste administrator credentials into logs, scripts, screenshots or chat. For a disposable CI run, GitHub Actions generates the bootstrap password automatically.

The command will start and stop each local application process, but the **operator** is responsible for starting/stopping the Keycloak development container during a manual run.

## Boundaries of the evidence

A passing R5 workflow demonstrates **real localhost integration** for the tested code snapshots, including PhiMail's real dev proxy and bridge. It is not a public internet deployment, production session security audit, real Gmail OAuth verification, durable account-linking permission, external account provisioning, PhiCloud authorization, passkeys or PhiOS device-effect authorization.

Keycloak SSO login state is separate from both app-local sessions. Application logout is **not** proven to terminate provider-wide SSO.

Existing public GitHub Pages builds remain synthetic/non-authenticating; no real accounts or secrets are deployed.
