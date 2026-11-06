# Φ PhiID → PhiMail R1: preview export consumer

The PhiID Account Center is a synthetic **metadata-only** demonstration, not a real identity server. PhiMail's Field Connections panel can now inspect the R0 export format to test interoperability.

## Strict preview contract

- Schema: phi-account/0.1
- Export kind: phiid-preview-export-only
- Authentic identity proof: false, always
- Account fields: schema_version, issuer, sub, preferred_username, email, email_verified
- Stable comparison pair (for future verified identities): issuer + sub. Email and username remain mutable.

For the R1 preview, issuer and subject are **unverified display values only**. Even when the exported email_verified field is true, it never grants identity, access or permission.

## Manual compatibility check

1. Open the PhiID R0 Account Center preview.
2. Export the synthetic metadata JSON file from the portability screen.
3. In PhiMail's Field Connections panel, choose Inspect PhiID preview JSON.
4. Confirm it displays the unverified issuer, subject, and display name while still showing **Not authenticated** and **Permissions: None**.

The PhiMail parser rejects unexpected fields, claimed proof, unsupported versions and malformed values. Nothing is saved to a remote account. PhiMail does not attempt to use the file as a bearer token.

## Real sign-in is a separate milestone

Future authentication must use an audited OIDC provider, Authorization Code + PKCE, a backend-for-frontend where appropriate, strict issuer/audience/nonce/expiry/signature validation, user-directed account linking and independently authorized service access.

**Do not** turn exported JSON or mocked account metadata into an authentication shortcut. PhiID preview linking is not equivalent to real account association.

Reference: [PhiMail Field Connections contract](https://github.com/MichaelWave369/PhiMail/blob/main/docs/INTEGRATION_R1.md). See also [PhiCloud's identity boundary](https://github.com/MichaelWave369/PhiCloud/blob/main/docs/PHIID_PHIMAIL_IDENTITY.md).
