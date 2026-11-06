# PhiID R3: independent local PhiMail OIDC client

The PhiID Keycloak development realm now declares a SECOND public OAuth client for PhiMail. It uses the same test identity provider but maintains an independent relying-party session.

| App | Client ID | Exact redirect |
| --- | --- | --- |
| PhiID | phiid-bff-dev | http://127.0.0.1:8786/auth/callback |
| PhiMail | phimail-bff-dev | http://127.0.0.1:5173/auth/phiid/callback |

Both enable authorization code + PKCE S256. Implicit flow, direct password grants and service accounts are disabled. No cloud or mailbox permissions follow from logging in.

To test:
1. Start the local PhiID Keycloak development realm on 127.0.0.1:8080 and create a synthetic test user.
2. Open the Keycloak Admin UI and verify the independent PhiMail public client. An EXISTING imported realm is not changed by editing the JSON file. If it existed before this change, create/update the PhiMail client in the Admin UI or carefully reset disposable test state.
3. Follow the PhiMail R2 local sign-in setup at https://github.com/MichaelWave369/PhiMail/blob/main/docs/LOCAL_PHIID_R2.md.
4. Sign in independently from each browser app. They validate the same issuer and signed ID token subject, but do not share app cookies or delegate permissions.
5. Logging out from either app only invalidates that app's own session, not Keycloak's SSO.

This is local development only. Do not port-forward Keycloak or publish either development bridge. No production OIDC, PhiMail-hosted address, Gmail account linking, PhiOS permission or PhiCloud resource authorization is implemented.
