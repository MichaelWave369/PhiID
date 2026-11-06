# PhiID R3 — Two independent localhost OpenID Connect clients

**Development-only registration and test plan, not production federation.**

The `phiid-dev` Keycloak realm now declares **two separate public OIDC clients**, allowing the same disposable test user to sign into PhiID and PhiMail independently. This creates a realistic foundation for future cross-app account recognition **without** forwarding cookies or bearer tokens between apps.

| Client ID | App | Exact callback | Cookie/session |
| --- | --- | --- | --- |
| `phiid-bff-dev` | PhiID Identity Center | `http://127.0.0.1:8786/auth/callback` | PhiID's own in-memory Node session |
| `phimail-phiid-dev` | PhiMail Field Connections | `http://localhost:5173/auth/phiid/callback` | PhiMail's own short-lived OIDC dev session |

Both use the Keycloak issuer `http://127.0.0.1:8080/realms/phiid-dev`, request only `openid profile`, and use authorization code + PKCE S256, distinct state/nonce values and exact redirect allowlists. Implicit flow, resource-owner password grant and service accounts are disabled.

The same verified `(iss, sub)` may be displayed after independently completing sign-in for the same local test user. **Display comparison is not an authorization or account-linking grant.** The PhiMail client is independent of the PhiMail Gmail OAuth read-only pilot and receives zero Gmail scopes.

## Run both clients locally

1. Check out PhiID with the R3 branch (until merged). Copy `dev/keycloak/.env.example` to a gitignored `dev/keycloak/.env`, replace the placeholder admin password with a unique private value.
2. From PhiID, run `docker compose --env-file dev/keycloak/.env -f dev/keycloak/compose.yaml up -d`. Open `http://127.0.0.1:8080/admin/`, switch to `phiid-dev` and create a disposable user using Keycloak Admin (no real personal account data).
3. **Existing realm warning:** Keycloak startup realm imports do not automatically update an already-created realm. If you created `phiid-dev` before R3, manually register the new public client in Keycloak Admin with the exact settings above, or use a fresh disposable Keycloak instance. Do **not** delete a realm containing data you intend to keep.
4. From PhiID: `npm install && npm run build && npm run dev:identity`. Open `http://127.0.0.1:8786/PhiID/`.
5. From the separate PhiMail R2B branch, configure its gitignored `.env.local`: add `PHIMAIL_ENABLE_PHIID_DEV=1` and `BRIDGE_PUBLIC_ORIGIN=http://localhost:5173`. In separate PhiMail terminals run `npm install`, `npm run bridge:dev` and `npm run dev`. Open `http://localhost:5173/`, then **Field Connections**.
6. In each app independently use its Keycloak sign-in and confirm the verified subject matches for the same disposable user. Clear only PhiMail's session and confirm that the PhiID session persists. Clear only PhiID's session and confirm PhiMail remains independently logged in until expiry. Keycloak SSO itself may persist.
7. Confirm neither session creates a real PhiMail email address, Gmail access, PhiCloud data access or PhiOS device permission.

### Negative tests

- Wrong redirect URI is rejected by Keycloak's registered client.
- Incorrect/expired state/nonce/PKCE fails. Do not treat profile-shaped JSON as authentication.
- Signing into the PhiID client does **not** automatically produce the PhiMail client cookie; each client must complete its own flow.
- `GET /api/phiid/session` in PhiMail is a minimal display-only identity check; it has no mailbox scopes or independent service authorization.
- Without the PhiMail local opt-in flag, the new sign-in routes stay disabled.
- GitHub Pages must not contain a live PhiID sign-in endpoint or any credential handling.

## Current verification status

CI covers the realm's separate client IDs, exact redirects, scope/flow restrictions and absence of seeded passwords. **The two-browser end-to-end Keycloak sign-in and cross-app isolation are not tested by that CI suite**; they require an explicit local run and recorded result.

R3 does not implement production identity hosting, passkey registration, persistent audit, upstream logout coordination, token revocation propagation, phi-field.com domain verification, mailbox provisioning, or cross-device synchronization.

See [PhiMail's R2B integration instructions](https://github.com/MichaelWave369/PhiMail/blob/main/docs/PHIID_OIDC_R2B.md) once merged.
