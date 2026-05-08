# @msecrets/core agent guide

## Purpose

This package is the source of truth for `.env.ms.json` behavior.
Keep business logic here so UI, CLI, and SDK stay thin.

## Commands

```bash
npm --workspace @msecrets/core run typecheck
npm --workspace @msecrets/core run typecheck:test
npm --workspace @msecrets/core run test
npm --workspace @msecrets/core run build
```

## Compatibility Boundary

- Hard boundary: persisted `.env.ms.json` shape.
- Keep package entrypoints from `package.json` working.
- Internal files can move; use compatibility shims only for entrypoints and important aliases.

## Layers And Ownership

- `src/model.ts`: persisted model types.
- `src/validation/`: file validation and compatibility errors.
- `src/file-store.ts`: parse/read/write/modify with validation and atomic rename.
- `src/crypto/`: OpenPGP backend and payload normalization.
- `src/keys/`: key provider contracts and gpg-cli provider.
- `src/domain/`: pure file mutation rules.
- `src/workflows/`: public orchestration APIs.
- `src/adapters/`: runtime decryption adapters.

## Critical Rules

- Never trim decrypted payloads.
- Never return private keys from public workflow results.
- Always validate before writing; writes must stay atomic.
- Do not probe gpg availability at module import time.
- Keep adapters stateless; adapters return plaintext only.
- Keep exact `.ts` imports, Node.js 24+, TypeScript ESM.

## Where To Add Code

- New file-format checks: `src/validation/`.
- New pure business rules: `src/domain/`.
- New user-facing operations: `src/workflows/`.
- New runtime decrypt sources: `src/adapters/`.

## Avoid

- Duplicating core rules in UI/CLI/SDK.
- Tiny one-line wrappers without compatibility value.
- Hidden state and environment-coupled behavior.
