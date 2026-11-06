# PhiID R2 — Local Consent Receipt Contract

**Status:** opt-in localhost-only development feature; no PhiCloud, PhiMail or PhiOS resource access. This is a **consent-to-review prototype**, not implemented OAuth scopes, account linking or federated authorization.

## Purpose

A user who has already completed verified Keycloak authentication in the R1 lab can review an explicit proposed service identity scope and create a short-lived receipt recording their choice. The user can remove that local record. Without a verified session the service returns HTTP 401; without matching same-origin action headers mutation returns HTTP 403.

The "Ecosystem" view on GitHub Pages remains a synthetic simulation. The new "Consent Lab" view exists **only** at `http://127.0.0.1:8786/PhiID/` through the Node localhost identity bridge.

## Data and scope

R2 allowlists two proposed future connections:

| Service | Scope in the receipt | Meaning in R2 | Actual grant |
| --- | --- | --- | --- |
| PhiMail | `profile.basic.read` | User reviewed proposed basic profile sharing | **None** |
| PhiCloud | `profile.basic.read` | User reviewed proposed basic profile sharing | **None** |

The scope name is a **reserved proposal**, not an actual OAuth access token scope, introspection result, or implemented resource-server authorization. It cannot read anybody's data. No e-mail address, mailbox, file, local OS capability, model inference or remote service is accessed by these endpoints.

## R2 receipt contract

```json
{
  "schema": "phiid.local-consent-receipt/0.1",
  "receipt_id": "(cryptographically random opaque ID)",
  "service": "phimail",
  "consent_version": "local-consent/0.1",
  "subject": {
    "issuer": "http://127.0.0.1:8080/realms/phiid-dev",
    "sub": "(validated signed OIDC ID Token subject)"
  },
  "requested_scopes": ["profile.basic.read"],
  "purpose": "Remember that I reviewed the proposed PhiMail identity profile integration.",
  "recorded_at": "(UTC ISO timestamp)",
  "expires_at": "(UTC ISO timestamp at or before the local session expiry)",
  "status": "recorded_not_enforced",
  "connected": false,
  "authority_granted": false,
  "service_called": false,
  "previous_receipt_replaced": false
}
```

The example above documents the JSON shape, **not an actual user's account or a usable credential**.

Receipts live only in the R1 Node process's in-memory map attached to the authenticated session. The bridge discards R1's ID/access/refresh tokens after verification. R2 does **not** restore or reuse them. Session expiration, explicit local logout and restart destroy access to receipts. No durable audit or protected persistent storage has been built; do not claim durable consent evidence.

## Local interface

- `GET /auth/consents` (requires a verified local session) returns fixed declarative catalog, temporary receipts and explicit `service_calls:false` / `permissions_enforced:false`.
- `POST /auth/consents` requires an authenticated session, exact same-origin `Origin`, `X-PhiID-Action: consent`, and `application/json`. It only accepts exact keys `service`, `scopes`, `acknowledged:true`. It rejects any app ID or scope outside the allowlist.
- `DELETE /auth/consents/{phimail|phicloud}` requires a verified session, same-origin `Origin` and `X-PhiID-Action: revoke`. It deletes only that temporary local record and explicitly reports `connection_revoked:false` and `external_token_revoked:false`.

HTTP is permitted only for this fixed loopback lab. The existing Host and remote peer checks remain in force. There is no general-purpose browser-to-Keycloak proxy or arbitrary remote URL input.

## Important security distinctions

1. A **valid PhiID identity** is the verified `iss` + `sub` pair from the audited OIDC client.
2. A **consent receipt** proves only what the local lab recorded as a user choice, while the session existed.
3. An **authorization grant** would require separate user permission, validated provider-issued audience- and scope-restricted tokens, service-side owner checks, expiry/revocation and suitable HTTPS transport.
4. **PhiOS local authority** is independent of all three above. Remote sign-in cannot approve file, tool, package or agent actions.
5. **PhiMail mailbox access** is never implied by PhiID account authentication or this receipt.
6. **PhiCloud storage** is never implicitly connected; the current R0 PhiCloud registry is read-only and does not recognize these receipts.

## Quality gates and unverified items

Automated tests cover accepted/rejected payloads, unknown services, scope injection, local-session binding, expiry, replacement, removal, response restrictions, remote provider metadata pinning and unauthenticated HTTP endpoint denial. The React app builds for static GitHub Pages, where no Consent Lab tab is exposed.

Still **unverified**: an end-to-end login + consent + logout against a running Keycloak container with a disposable real test user. This should be done before calling the entire flow operational. No external PhiCloud or PhiMail resource-server integration exists.

## Next R3 gate

Only after full real OIDC validation and security review:
- deploy a separately secured resource server with strictly validated access tokens
- register PhiMail and PhiCloud clients with correct audience, scope and redirect boundaries
- implement human-readable consent with durable records and revocation propagation
- prove account unlinking, provider outages and offline PhiOS operation do not destroy local ownership
