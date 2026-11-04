## Purpose

This repository implements **msecrets v4**: encrypted secrets that live in the repository.

- One committed JSON file (`msecrets.json`, format version 4)
- Every value is an independent age file, encrypted to the recipients of its environment
- Every value is signed (Ed25519) by a recipient of its environment
- No server, no KMS; the published packages have no npm dependencies

---

## Architecture

Go module `github.com/k18k/msecrets`. Go dependencies are allowed (prefer well-known ones: age, x/crypto, cobra,
Charm); the published npm packages must have **no npm dependencies**.

- `internal/core`: all logic, on `filippo.io/age` and `golang.org/x/crypto`
  - `keys.go`, `age.go`, `ssh.go`, `bech32.go`: identities and public keys (`msecrets1…`, `age1…`, `age1pq1…`, `ssh-ed25519`)
  - `document.go`, `json.go`, `map.go`: the v4 file format, validation, byte-identical canonical serialization
  - `values.go`: sealing, signatures, verification
  - `status.go`: completeness, drift, and signature inspection (public data only)
  - `operations.go`: all mutations, as transactions on a document copy
  - `store.go`: file discovery and atomic, conflict-checked writes
  - `sources.go`, `keychain.go`: where private keys come from
  - `host.go`: all I/O goes through `Host`, so the same core runs natively and under js/wasm
- `cmd/msecrets`, `internal/cli`, `internal/tui`: the CLI (cobra), the terminal UI (bubbletea), `run`, git integration
- `sdk/wasm`: the core compiled to WebAssembly, with a `Host` on Node.js synchronous APIs
- `sdk/js`: `@msecrets/ts-sdk`: `createClient(file)` (typed secrets from an imported file), `injectEnv`
- `npm/cli`: `@msecrets/cli`, a Node.js shim that runs the binary from `@msecrets/cli-<os>-<arch>`
- `skills/msecrets/SKILL.md`: the agent skill, embedded in the binary, installed by `msecrets skill`, and served
  as a Claude Code plugin (`.claude-plugin/`). Keep it in sync with the CLI and SDK (a test checks commands,
  imports, error codes, and the plugin version).

### Release

`VERSION` is the version. `scripts/build-dist.sh` builds `dist/` (six platform binaries, the shim, the SDK);
`scripts/publish-branches.sh` commits each package to its own git branch (`cli`, `cli-<os>-<arch>`, `ts-sdk`),
tagged `<branch>-v<version>`. A push to `master` with a new `VERSION` does both (`.github/workflows/release.yml`).
npm installs from git: `npm install -g --allow-git=all github:k18k/msecrets#cli`,
`npm install --allow-git=root github:k18k/msecrets#ts-sdk`.

---

## Critical Design Rules

### 1. Core is the source of truth

- All business logic lives in core. The CLI, TUI, and SDK only call core operations and render results.
- Operations mutate a document copy; `updateDocumentFile` validates and writes atomically. Never write the file elsewhere.

### 2. The file is the compatibility contract

- `msecrets.json` v4 must stay readable by every v4 release. Breaking it requires explicit instruction and a new `version`.
- The file holds no runtime-only or machine-specific data. Keys and identity sources never come from the file.
- The SDK takes the imported file (`createClient(file)`) and never searches for or reads it; its secret names
  type the result.
- Keep `schema/v4.json` in sync with `document.go` (a test enforces the name and key patterns).

### 3. Security invariants

- Never decrypt or re-encrypt a value whose signature does not verify; never re-sign without verifying first.
- Revocation must re-encrypt every affected value or fail (unless the caller explicitly allows incomplete).
- Writers must be recipients of the environment with a signing key; machine keys from `--generate` are read-only.
- Never put secrets on command lines; pass them through stdin. Scrub identity variables before running user code.
- Parsers of untrusted input (age headers, keys, files) are strict and reject non-canonical encodings.
- Never print untrusted text with control characters (terminal escape injection): validate or sanitize it.

### 4. Standards over invention

- Encryption is age, interoperable with the reference implementation. Do not change the age wire format.
- Do not add OpenPGP or GPG dependencies.

---

## Coding Rules

- Idiomatic Go, `gofmt`, `go vet` clean. Minimal code, no duplication, no clever code, no unnecessary abstractions.
- Use well-known libraries instead of hand-written code; hand-written code only where a format requires it.
- Errors are `*core.Error` with a `Code` and an actionable message. Never swallow errors; expected
  outcomes (authentication failure, not found) are explicit return values.
- Binaries run on Linux, macOS, and Windows (amd64, arm64); the SDK runs on Node.js 20+.

## Tooling

- Go (version in `go.mod`), Node.js 26 for the SDK tests and the install check.
- `go test ./...`, `go vet ./...`, `gofmt -l .`
- SDK: `MSECRETS_PLATFORMS= scripts/build-dist.sh && node --test sdk/test/`
- Install check: `scripts/build-dist.sh && scripts/test-install.sh` (publishes to a local bare repo, installs with npm)

## Testing

- Prefer real workflows: real files, real processes, real git; mocks only for I/O streams.
- The C2SP age vectors (`internal/core/testdata/vectors`) must keep passing.
- `internal/core/testdata/typescript` is a file written by the TypeScript implementation (4.0); it must stay readable
  and re-serialize byte-identically.
- Hostile input is tested by seeded mutation tests (`MSECRETS_FUZZ_CASES` for more cases) and Go fuzz targets
  (`go test -fuzz=FuzzDecryptAge ./internal/core`).
- Every user-visible behavior has a test; every bug fix gets a regression test.
- Tests must be deterministic and must not depend on the developer's keychain or config (use `MSECRETS_CONFIG_DIR`).
