# PhiID R1: Local Identity Lab

**Experimental development only. Not a public login service and not production-ready.**

R1 adds an optional, genuine OpenID Connect authorization-code flow using a Keycloak development realm and the audited `openid-client` library. It does **not** issue PhiID accounts for the internet, enable mail hosting, authorize PhiOS effects, or grant PhiCloud resource access.

## Architecture and trust boundary

```text
Browser: http://127.0.0.1:8786/PhiID/
   |
   +-- GET /auth/login (same-origin navigation)
   |    |
   |    +-- Node loopback bridge generates random PKCE verifier,
   |    |   state and nonce; stores them server-side for 5 minutes
   |    +-- Keycloak: http://127.0.0.1:8080/realms/phiid-dev
   |          (dev-only, operator-created demo account)
   |    +-- /auth/callback verifies state, nonce, PKCE and signed
   |        OIDC identity through vetted client library
   |    +-- Tokens discarded, short-lived opaque HttpOnly cookie
   |        set for the local bridge (maximum 15 minutes)
   |
   +-- GET /auth/session shows a minimal validated display profile
   +-- POST /auth/logout ends the bridge session (not Keycloak SSO)
```

The entire browser bundle is a *static* React build. Identity exchange is server-side in `dev/identity-lab/server.mjs`. No ID token, access token, refresh token, password, recovery secret or signing key is written to browser storage. The bridge session grants **no API authority** and its state disappears when the Node process stops.

## Requirements

- Node.js **22+** (the source and tests use ESM and built-in fetch)
- Docker Desktop or Docker Engine with Compose
- Available loopback ports **8080** and **8786**
- A trustworthy locally administered development machine

The image tag is pinned to Keycloak `26.8.2`. The public-client OIDC library is pinned in `package.json` to `openid-client` `6.8.8`. Both are research/development selections, **not production certification**.

## Start the realm

From the PhiID checkout root, make a private admin configuration:

```sh
cp dev/keycloak/.env.example dev/keycloak/.env
```

Edit `dev/keycloak/.env` and replace the placeholder bootstrap password with a strong, unique value. **Do not commit or paste it into chat.** `.gitignore` excludes it.

```sh
docker compose --env-file dev/keycloak/.env -f dev/keycloak/compose.yaml up -d
```

Open `http://127.0.0.1:8080/admin/`. Sign in with your private bootstrap administrator credentials. Switch to the **phiid-dev** realm, add a test user, and set credentials through Keycloak Admin UI. Real personal identities are unnecessary here. Public user self-registration is disabled.

The realm import contains **one public client** `phiid-bff-dev` with the exact callback URI:

```text
http://127.0.0.1:8786/auth/callback
```

The only allowed login mechanism is the authorization-code flow with PKCE S256; implicit flow, direct password grants, and service accounts are disabled in the dev client.

## Start the bridge

In another terminal, from the repository root:

```sh
npm install
npm test
npm run build
npm run dev:identity
```

Open **http://127.0.0.1:8786/PhiID/**, select **Sign in to local Keycloak**, and complete the form *hosted by Keycloak*. Successful verified sign-in returns to the Account Center with a badge marked **VERIFIED LOCAL OIDC** and a short-lived display profile. The synthetic portability export is still only a synthetic preview, never an account backup.

The regular `npm run dev` still launches the **non-authenticating static demo** on Vite's local development port. GitHub Pages also remains **non-authenticating**; it contains no backend and no live PhiID account sign-in.

To shut down Keycloak:

```sh
docker compose --env-file dev/keycloak/.env -f dev/keycloak/compose.yaml down
```

The Node process can be stopped with Ctrl+C. Current in-memory sessions disappear immediately.

## Security limits

- **Never expose ports 8080 or 8786** to your LAN, the public internet, a reverse proxy, Cloudflare Tunnel, Ngrok, or production PhiCloud. The bridge rejects non-loopback Host/peer requests.
- Keycloak `start-dev` intentionally permits insecure HTTP; `allowInsecureRequests` is enabled only to contact the hard-coded loopback issuer. A real deployment requires HTTPS and a new security architecture.
- The bridge discards OAuth tokens and retains only a minimal issuer/subject display profile. **No resource server** may treat a bridge display profile or local cookie as a generalized access token.
- `/auth/logout` removes the local session but does not guarantee Keycloak Single Sign-On logout. The user may immediately be recognized by Keycloak when starting another login.
- The bridge uses **ephemeral in-process maps**; it has no durable sessions, production rate limiting, persistent login audit, refresh token rotation, scalable deployment, account deletion or production incident response.
- A browser-based passkey flow is **not** provided by this PR. Later enrollment uses the audited provider.
- Do not use a real email, live password, sensitive mailbox, production account, or personal data to test this lab.

## Acceptance checklist

Automated CI verifies metadata validation, security helpers, loopback route behavior, and React production build. A **manual Keycloak smoke test remains required** to validate the full real sign-in:

1. Start the Keycloak container and confirm the realm and exact redirect URI.
2. Start the built Node bridge. Test `/auth/session` without a cookie: authenticated false.
3. Sign in with an operator-created test user. Confirm the **verified local** label and that the subject comes from the validated ID Token claims.
4. Attempt callback with missing flow cookie or altered `state`; ensure it fails without signing in.
5. Confirm no tokens are emitted in the browser DOM, URL after return, exported JSON, localStorage or sessionStorage.
6. POST local logout through UI; verify `/auth/session` becomes unauthenticated. Treat provider-wide logout as unimplemented.
7. Reload the GitHub Pages UI independently and confirm no real-sign-in button appears.

**Do not mark a real login deployment as verified based only on a green CI run.**

References: [Keycloak Docker guide](https://www.keycloak.org/getting-started/getting-started-docker), [Keycloak containers/import](https://www.keycloak.org/server/containers), [openid-client v6](https://github.com/panva/openid-client), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).

## Companion PhiMail development client

The development realm now also declares the separate PhiMail OIDC client phimail-bff-dev. It is not shared authentication state or production SSO. Read [the PhiMail dev client guide](R3_PHIMAIL_OIDC_CLIENT.md). Existing imported Keycloak realms must be updated through Admin UI.
