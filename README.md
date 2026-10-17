# msecrets

[![CI](https://github.com/k18k/msecrets/actions/workflows/ci.yml/badge.svg)](https://github.com/k18k/msecrets/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/k18k/msecrets/master/.github/badges/coverage.json)](https://github.com/k18k/msecrets/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@msecrets/ui?label=%40msecrets%2Fui)](https://www.npmjs.com/package/@msecrets/ui)
[![npm](https://img.shields.io/npm/v/@msecrets/ts-sdk?label=%40msecrets%2Fts-sdk)](https://www.npmjs.com/package/@msecrets/ts-sdk)

Encrypted secrets that live in your repository.

Commit one file, `.env.ms.json`. Every value is encrypted with [age](https://age-encryption.org) to the people and
machines of its environment and signed by whoever wrote it. There is no server, no account, nothing to provision,
and no dependencies.

```bash
npm install --save-dev @msecrets/ui
npx msecrets init                      # .env.ms.json + your key (OS keychain when available)
npx msecrets set DATABASE_URL          # prompts for the value
npx msecrets                           # terminal UI: every secret in every environment
npx msecrets run -- npm start          # secrets as environment variables, for any language
node --import @msecrets/ts-sdk/register server.js   # or the Node.js preload
```

**Documentation: https://k18k.github.io/msecrets/**

## Why

- **Complete:** every environment has every secret, or `msecrets check` fails CI and apps refuse to start.
- **In sync:** when access changes, outdated values are flagged until `msecrets sync` re-encrypts them.
- **Tamper-evident:** every value is signed by a member of its environment and bound to its slot.
- **Reviewable:** `git diff` shows who changed which value; independent changes merge without conflicts.
- **Your keys, your vault:** OS keychain, 1Password, Bitwarden, pass, any command, or SSH keys you already have.
- **Ephemeral runtimes:** read-only machine keys through `MSECRETS_IDENTITY` or `/run/secrets`, scrubbed before your
  code runs.
- **Post-quantum ready:** optional ML-KEM-768 + X25519 keys for secrets that stay in git history forever.
- **Standard and portable:** values are age files; `base64 -d | age -d` decrypts them without msecrets.

## Packages

| Package                               |                                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------------- |
| [`@msecrets/ui`](packages/ui)         | The `msecrets` CLI and terminal UI.                                                   |
| [`@msecrets/ts-sdk`](packages/ts-sdk) | Runtime SDK: `load()`, typed `createClient()`, and the `register` preload.            |
| `packages/core`                       | Private: age, keys, the file format, operations, identity sources. Bundled into both. |

Both packages have no dependencies and run on Node.js 20 or newer on Linux, macOS, and Windows.

## Development

Node.js 26 through [mise](https://mise.jdx.dev) (`mise install`), npm workspaces.

```bash
npm install
npm run build          # tsdown: ESM + CJS + types for the SDK, a single-file CLI
npm test               # TypeScript tests from source (node:test)
npm run test:dist      # the built packages, also run on Node.js 20 in CI
npm run verify         # format, lint, typecheck, build, all tests, and the packed install path
```

The [age interoperability tests](packages/core/test/age-interop.test.ts) run when `age` is on `PATH`
(`MSECRETS_AGE_BIN`). OS keychain round-trips run with `MSECRETS_TEST_KEYCHAIN=1`.

## Releases

Merging to `master` runs CI on Linux, macOS, and Windows with every supported Node.js version, then publishes each
package whose version is not on npm yet (with provenance) and tags the release.

## License

MIT
