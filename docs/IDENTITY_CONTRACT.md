# PhiID R0 identity contract

**Status: public, non-authenticating metadata demonstration.** This is the shared intent for future PhiOS, PhiCloud and PhiMail integrations. It is not a new identity protocol and does not replace OpenID Connect.

## Canonical identity key

A real PhiID relying party must determine user identity only from a **cryptographically verified** OpenID Connect ID token and its validated issuer and subject:

~~~text
principal-key = (validated iss, validated sub)
~~~

The pair is unique within the relevant relying-party context. Email, preferred username, display name and phone are mutable presentation/contact attributes, not principal keys.

Pairwise subject IDs may differ between relying parties; do not concatenate or correlate them without documented user consent and appropriate issuer configuration.

## R0 preview record

~~~json
{
  "schema_version": "phi-account/0.1",
  "issuer": "https://example.invalid/phiid",
  "sub": "demo-subject-369-not-an-account",
  "preferred_username": "field-explorer",
  "email": null,
  "email_verified": false
}
~~~

**Important:** This is deliberately fake metadata, not an OpenID Connect token or an account database record. The `issuer` property is a display-schema alias for the OIDC `iss` claim; consuming it does not establish a verified issuer. The `sub` string is a synthetic subject. The reserved `example.invalid` hostname is not an online service.

The `validatePreviewAccount` helper checks shapes only; it has **no signature checking, token validation, trusted issuer list, discovery, claim provenance, account persistence or access control**. The `previewIdentityKey` output is a comparison aid, never authentication proof.

The browser exports a wrapped `phiid-preview-export-only` record with `authentic_identity_proof: false`. It is deliberately not valid for account recovery or login.

## Future real OIDC profile

- Select a mature open-source OIDC provider, e.g. Keycloak, and configure an actual HTTPS issuer through operator-controlled deployment.
- Use authorization code with PKCE S256 for public clients. Verify `state`, nonce, redirect URI binding, mix-up defenses and token contents as required for each client type.
- Validate issuer, audience, expiry, signature, algorithm restrictions and keys using a vetted OIDC client library and the provider's pinned configuration. Do not allow client-provided `iss` or `sub` to authorize requests.
- Support passkeys via the provider's audited WebAuthn RP implementation; do not roll custom challenge/signature verification.
- Rotate sessions, support revocation, limit scopes and maintain a separate, independently authorized user-recovery flow.
- Use secure HttpOnly session cookies where applicable or a BFF for web clients. Never store long-lived refresh tokens in the public static site.
- Keep credentials, signing keys, mailbox secrets, sensitive logs and account databases off GitHub Pages.
- Define users' data export, deletion, revocation, device-loss recovery and tenant isolation before production use.

## Ecosystem contract

| Consumer | Identity behavior | Authority boundary |
| --- | --- | --- |
| PhiOS Desktop/Mobile | Optional owner-reviewed account linking | Local effects require independent PhiOS approval |
| PhiOS WebOS | Consent-based sign-in to remote services | Web session grants no native device effect |
| PhiMail | Optional external/provider mailbox, future PhiID account profile | Email ownership never substitutes for principal identity |
| PhiCloud | Remote APIs validate audience, scope and resource owner | No implied access to other services |
| PhiServe | Existing local serving continues independently | Remote inference exposure requires distinct, reviewed approval |

### Portability and offline guarantees

The user may decline PhiID entirely. Removing cloud linkage must not prevent local PhiOS startup, local storage or independently permitted local applications. Exported data must not become a credential or bypass recovery controls.

## References

- OpenID Connect Core, section 5.7: https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700.html
- Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- PhiCloud's earlier PhiID/PhiMail contract: https://github.com/MichaelWave369/PhiCloud/blob/main/docs/PHIID_PHIMAIL_IDENTITY.md
