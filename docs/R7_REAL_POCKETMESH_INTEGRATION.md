# R7: Real PhiID → NBGPocketMesh Cross-Repository Execution Smoke

**Status:** disposable, localhost-only integration test; no production authorization or real device actions.

## Why R7 matters

R6 established a real Keycloak OIDC login and a second signed action approval, but its input permit had test-created route/content digests. NBGPocketMesh independently verified a two-signer approval under synthetic identity. **R7 connects the actual code from both repositories.**

The CI workflow pins a reviewed, public NBGPocketMesh checkout to:

```text
MichaelWave369/NBGPocketMesh`50d11cc7f28293c9f6e6333019dcb668fd299225
```

The checkout appears under `integration/pocketmesh`, does not persist GitHub credentials, and its SHA is independently asserted at test startup. Updating this pin requires an explicit source review and workflow update.

## Real integrated sequence

1. Launch disposable Keycloak on loopback; create a random non-admin user with the existing R4 admin helpers.
2. Generate two independent ephemeral Ed25519 key pairs and restricted operator configurations, exact issuer/subject allowlist and a shared local replay ledger.
3. Import actual pinned NBGPocketMesh `createDemoLibrary`, `prepareExecutionRequest`, and `signExecutionRequest`. Produce a genuine, source-verified E0 route and signed, one-use execution permit for `network-health`.
4. Reject a PhiID R2 display-only consent record in the actual PocketMesh worker. This must not spend the permit nonce.
5. Complete **real OIDC code + PKCE + state + nonce** login through the existing PhiID BFF and Keycloak. Require the verified session's `(iss,sub)` to match the actual disposable user; no access or refresh token is exposed to the browser.
6. Refuse anonymous review, missing-origin review and modified-permit review. Stage the real signed PocketMesh permit and verify its album, revision, profile, mode and scope.
7. Refuse an unacknowledged action; explicitly confirm the staged request with a same-origin authenticated session action. PhiID signs the **exact permit** with a separate Ed25519 key. Refuse signing the same review twice.
8. Verify the signed approval with the actual pinned NBGPocketMesh verifier and exact allowed local development issuer/subject and trusted signing keys.
9. Reject a tampered approval in the actual one-shot PocketMesh worker before spending its nonce.
10. Launch the genuine worker as a separate Node process. Require `PERFORM` and metadata-only receipt, with exactly one nonce spent.
11. Launch a second process with the same envelope. Require `REFUSE` and an unchanged spent-nonce count.
12. Log out the temporary BFF session, delete the Keycloak test user, remove the test-only keys and nonce ledger, and tear down the Keycloak container unconditionally.

The test harness programmatically performs the same-origin acknowledgment; that is **not proof that an actual human reviewed or understood the action**.

## Reproduce

The automated test is a step of **GitHub Actions → PhiID real Keycloak localhost smoke**. It runs with Node 22, Docker Compose and explicit two-project integration checkout.

For a local manual run, clone exactly the pinned NBGPocketMesh commit under `integration/pocketmesh/`, start only a disposable localhost Keycloak dev realm with protected bootstrap credentials, and use:

```sh
PHIID_E2E_ENABLE=1 PHIID_POCKET_E2E_ENABLE=1 NODE_ENV=test node dev/keycloak/pocketmesh-e2e.mjs
```

Also supply `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD` as protected environment variables, never in committed files or terminal-history commands. See [R4 real Keycloak setup](R4_REAL_KEYCLOAK_SMOKE.md). PowerShell requires different environment-variable syntax.

## Limits

- **The only executed result is the built-in synthetic network-health fixture.** No device probe, external cloud service, model inference, PhiOS effect or arbitrary OS command is performed.
- **Real OIDC, test approval action:** disposable Keycloak sign-in and signed token validation are real. The second-step approval confirmation is simulated by the CI harness, not a user-presence, MFA or WebAuthn attestation.
- **Ephemeral local keys:** test keys are generated only for the CI run and removed with temporary data. Production signing policy, durable revocation, HSM/isolated key custody and audited approval UX remain unimplemented.
- **No sandbox:** reviewed local JavaScript modules execute with ordinary Node privileges behind a separate permit-only worker.
- **Local replay security only:** a protected nonce file allows one cooperative local process to win. It is not a crash-safe distributed replay ledger or defense against compromised host administration.
- **No secret logging:** private keys, cookie values, user identifiers, Keycloak passwords, signed permits and identity tokens remain in memory or protected temporary files. CI logs only pass/fail summaries.

**The evidence of a green R7 run is narrow but important:** for these pinned snapshots and disposable credentials, one real signed request travels through verified Keycloak/PhiID identity, explicit action review, independent approval signing, the actual NBGPocketMesh Keyhole, and one allowed synthetic execution. It is refused on replay.

**Next:** protected signer isolation, trusted approval policy lifecycle, revocation, step-up auth and OS sandboxing before permitting real PhiOS effects.
