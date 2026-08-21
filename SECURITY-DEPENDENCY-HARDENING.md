# Dependency hardening

This branch is reserved for dependency hygiene following the RC2 security-gate validation.

## Current remediation

- Vitest is raised from `^3.2.0` to `^3.2.5` to exclude the affected Vitest 3.0.x–3.2.4 range associated with CVE-2026-53633.
- `jose`, `canonicalize`, and `@actions/core` are intentionally unchanged because they participate in the runtime/security boundary and no direct advisory has been established for the currently declared versions from the available evidence.
- A reproducible `package-lock.json` is required before this hardening change can be considered release-ready.

## Required validation

1. Generate and commit `package-lock.json` with Node 20/npm.
2. Run `npm ci` from the committed lockfile.
3. Capture `npm audit --json` and record exact vulnerable dependency paths.
4. Run `npm run build`.
5. Run `npm run test:security`.
6. Confirm all 55 security tests pass and no unauthorized scenario reaches `ALLOW`.
7. Do not use `npm audit fix --force`.

The RC2 trust model is unchanged by this dependency-hardening work.
