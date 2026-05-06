## Purpose

This repository implements **msecrets**: a repository-native encrypted secrets system.

Core idea:

- One committed JSON file (`.env.ms.json`)
- Per-secret encryption
- Access control via OpenPGP recipients
- No mandatory external KMS
- Runtime decryption via adapters

This file defines how AI agents should understand and modify the codebase after the MVP release path has been established.

---

## High-Level Architecture

Monorepo structure:

- `packages/core`
  - Pure logic
  - File format, validation, workflows
  - OpenPGP-native crypto and shared runtime contracts
- `packages/cli`
  - Interactive CLI (commander + inquirer)
  - Uses core workflows
  - Owns the publishable `msecrets` CLI artifact
- `packages/ts-sdk`
  - Runtime consumption layer
  - Adapter-based decryption client
- `packages/core/src/adapters`
  - Runtime decryption providers (gpg, docker secrets, raw OpenPGP private keys)
- `packages/ui`
  - Dashboard launched through `msecrets ui`

---

## Critical Design Rules

### 1. GPG is convenience-only

- OpenPGP is the real system.
- ASCII-armored OpenPGP keys and messages are the portable artifacts.
- GPG is a convenience bridge for key acquisition only.
- Repository state must not depend conceptually on the local GPG keyring.

Agents MUST:

- Avoid deepening GPG coupling.
- Never make core workflows depend on `gpg --encrypt` or `gpg --decrypt`.
- Prefer provider/adapter abstractions over direct `gpg` usage.
- Base portability guarantees on armored OpenPGP keys/messages, not local GPG state.

### 2. Core is the source of truth

- All business logic belongs in `@msecrets/core`.
- CLI and UI must stay thin.

Agents MUST:

- Never duplicate core logic in CLI/UI/SDK layers.
- Extend core workflows instead of reimplementing behavior elsewhere.
- Keep validation close to the file format and workflow boundaries.

### 3. SDK and adapters are the runtime path

- The CLI is the authoring interface.
- The SDK is the primary runtime interface.
- Adapters provide runtime key access.

Adapter rules:

- Adapters MUST be stateless.
- Adapters MUST NOT mutate global state.
- Adapters MUST return plaintext only.

### 4. Secrets file is the compatibility contract

File:

```text
.env.ms.json
```

Rules:

- Must remain portable.
- Must remain tool-independent.
- Must not depend on local environment state.
- Must not include runtime-only data.
- Must preserve v1 compatibility unless the user explicitly asks for a breaking format change.

### 5. Encryption model

- Each secret is encrypted independently.
- Recipients define access.
- There is no central authority.

Implications:

- No retroactive revocation.
- No hidden access control.
- Everything must be explicit.

---

## Coding Rules

### TypeScript

- Strict typing REQUIRED.
- No `any`.
- Prefer inference but keep clarity.
- Validate all external input.

### Tooling

- Use `mise` only as the optional Node.js 24 shim provider in this repository.
- Prefer commands like `mise exec node@24 -- ...` over assuming globally installed Node.js.
- Use npm workspaces for install, script, test, and verification workflows.
- Bun is not a repo orchestration tool; only the deferred CLI package bundling script still depends on Bun until that packaging path is redesigned.
- If Node.js 24 is not available through `mise`, report that clearly before making assumptions about local availability.
- When finishing implementation work, do not automatically run tests, smoke tests, lockfile generation, `npm install`, or similar validation chores unless they are explicitly part of the task or clearly necessary to complete it. Instead, describe the remaining developer-owned validation steps in the final response.

### Style

- Minimal code.
- No duplication.
- No unnecessary abstractions.
- No clever code.

### Errors

- Always explicit and descriptive.
- Never swallow errors.
- Prefer early throws.

---

## What Agents SHOULD do

- Preserve v1 file-format compatibility.
- Extend core workflows.
- Improve validation and safety.
- Move logic toward OpenPGP and away from GPG assumptions.
- Strengthen the SDK/adapters runtime path.
- Improve type safety.
- Keep release validation current when behavior changes.
- Update docs and tests with user-visible changes.

---

## What Agents MUST NOT do

- Add business logic to CLI/UI.
- Modify anything under `packages/ui` unless the user explicitly asks for UI work.
- Hardcode environment-specific behavior.
- Introduce hidden state.
- Depend on local machine configuration.
- Deepen GPG dependency.
- Break file format compatibility without explicit instruction.
- Weaken generated-package or release verification.

---

## Known Technical Debt

- GPG shell dependency remains for local key discovery.
- `owners` duplicates actual OpenPGP recipients.
- SDK/adapters contract is still settling.
- SDK is not fully independent.
- Adapter system is still minimal.

Agents MAY improve these incrementally when the change preserves compatibility and keeps boundaries clean.

---

## Preferred Future Direction

1. OpenPGP remains the core crypto implementation.
2. Stored public keys remain the encryption source of truth.
3. SDK handles runtime decryption.
4. Adapters provide private keys only.
5. CLI remains focused on authoring and local inspection.

---

## Mental Model

Think of msecrets as:

> "Git for encrypted configuration"

NOT:

- a KMS
- a secrets server
- a policy engine

---

## Testing Philosophy

- Prefer real workflows over mocks.
- Validate file transformations.
- Ensure deterministic outputs.
- Avoid environment-dependent tests.
- Keep generated-package validation aligned with the public install path.

---

## Final Rule

If a change makes the system more deterministic, more portable, less dependent on GPG, more SDK-first, and still compatible with the v1 file contract, it is in scope.

If not, reconsider.
