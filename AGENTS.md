## Purpose

This repository implements **msecrets v4**: encrypted secrets that live in the repository.

- One committed JSON file (`.env.ms.json`, format version 4)
- Every value is an independent age file, encrypted to the recipients of its environment
- Every value is signed (Ed25519) by a recipient of its environment
- No server, no KMS, no dependencies

---

## Architecture

- `packages/core` (private, never published on its own)
  - `src/crypto`: age v1 (X25519, MLKEM768-X25519, scrypt, ssh-ed25519), bech32, base64, bcrypt_pbkdf, primitives on `node:crypto`
  - `src/keys.ts`: identities and public keys (`msecrets1…`, `age1…`, `age1pq1…`, `ssh-ed25519`)
  - `src/document.ts`: the v4 file format, validation, canonical serialization
  - `src/values.ts`: sealing, signatures, verification
  - `src/status.ts`: completeness, drift, and signature inspection (public data only)
  - `src/operations.ts`: all mutations, as transactions on a document copy
  - `src/store.ts`: file discovery and atomic, conflict-checked writes
  - `src/sources.ts`, `src/keychain.ts`: where private keys come from
- `packages/ts-sdk` (`@msecrets/ts-sdk`): runtime client, `load`, `injectEnv`, `register`
- `packages/ui` (`@msecrets/ui`, bin `msecrets`): CLI commands, terminal UI, `run`, git integration

Packages import core through relative paths; tsdown bundles it. Published packages must have **no dependencies**.

---

## Critical Design Rules

### 1. Core is the source of truth

- All business logic lives in core. The CLI, TUI, and SDK only call core operations and render results.
- Operations mutate a document copy; `updateDocumentFile` validates and writes atomically. Never write the file elsewhere.

### 2. The file is the compatibility contract

- `.env.ms.json` v4 must stay readable by every v4 release. Breaking it requires explicit instruction and a new `version`.
- The file holds no runtime-only or machine-specific data. Keys and identity sources never come from the file.
- Keep `packages/ts-sdk/schema/v4.json` in sync with `document.ts` (a test enforces the name and key patterns).

### 3. Security invariants

- Never decrypt or re-encrypt a value whose signature does not verify; never re-sign without verifying first.
- Revocation must re-encrypt every affected value or fail (unless the caller explicitly allows incomplete).
- Writers must be recipients of the environment with a signing key; machine keys from `--generate` are read-only.
- Never put secrets on command lines; pass them through stdin. Scrub identity variables before running user code.
- Parsers of untrusted input (age headers, keys, files) are strict and reject non-canonical encodings.

### 4. Standards over invention

- Encryption is age, interoperable with the reference implementation. Do not change the age wire format.
- Do not add OpenPGP or GPG dependencies.

---

## Coding Rules

- TypeScript strict, `erasableSyntaxOnly`, `isolatedDeclarations`, exact `.ts` imports. No `any`.
- Minimal code, no duplication, no clever code, no unnecessary abstractions.
- Errors are `MsecretsError` with a `code` and an actionable message. Never swallow errors; expected
  outcomes (authentication failure, not found) are explicit return values.
- Runtime code must work on Node.js 20+ on Linux, macOS, and Windows. ML-KEM is optional (`supportsMlKem()`).

## Tooling

- Node.js 26 via `mise` (`mise exec node@26 -- …`); npm workspaces; tsdown builds; TypeScript 7 typechecks.
- `npm run verify` runs format check, lint, typecheck, build, source tests, dist tests, and the packed install check.
- Do not run lockfile updates or installs unless the task needs them; describe remaining validation steps instead.

## Testing

- Prefer real workflows: real files, real processes, real git; mocks only for I/O streams.
- The C2SP age vectors (`packages/core/test/vectors`) must keep passing.
- Every user-visible behavior has a test; every bug fix gets a regression test.
- Tests must be deterministic and must not depend on the developer's keychain or config (use `MSECRETS_CONFIG_DIR`).
