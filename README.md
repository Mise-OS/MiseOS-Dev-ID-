# MiseOS Dev ID

## Security RC2

`1.0.0-security-rc2` is the current release posture: the frozen trust model is substantially implemented, with the authority path consolidated into one fail-closed verifier.

The repository enforces:

- RFC 8785/JCS canonicalization.
- Cryptographic GitHub Actions OIDC verification against JWKS, with issuer, audience, repository, owner/ID, workflow, workflow ref/SHA, ref, ref type, environment, and temporal policy.
- Exact GitHub subject → registered Ed25519 key binding.
- Trusted-registry-only Ed25519 verification using SPKI DER.
- Authorization state, scope, subject, resource, temporal, and revocation enforcement.
- Signed delegation-chain verification with bounded scope/resource/expiration/depth and revocation checks.
- Atomic replay claims at the final security boundary.
- Three-state verification (`ALLOW`, `DENY`, `INDETERMINATE`) with `INDETERMINATE` never converted to authority.
- A 50-case adversarial suite whose release gate explicitly asserts that every unauthorized scenario produces `DENY`.

### Release rule

A release is not security-approved unless the CI `Security Gate` passes. Any unauthorized test reaching `ALLOW` fails the job.

GitHub Actions OIDC uses a dedicated issuer and signed JWT claims; GitHub documents the subject/audience trust conditions and the `id-token: write` requirement for requesting workflow tokens.

## Commands

```bash
npm install
npm run build
npm run test:security
npm run check
```

## Status

**`1.0.0-security-rc2` — security model substantially implemented; production release remains gated on passing repository security CI and deployment-specific registry/JWKS/revocation infrastructure.**
