# msecrets

[![CI and release](https://github.com/k18k/msecrets/actions/workflows/release.yml/badge.svg?branch=master)](https://github.com/k18k/msecrets/actions/workflows/release.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/k18k/msecrets/master/.github/badges/coverage.json)](https://github.com/k18k/msecrets/actions/workflows/release.yml)

Encrypted secrets that live in your repository.

Commit one file, `msecrets.json`. Every value is encrypted with [age](https://age-encryption.org) to the people and
machines of its environment and signed by whoever wrote it. There is no server, no account, nothing to provision,
and no dependencies.

```bash
npm install -g --allow-git=all github:k18k/msecrets#cli
msecrets init                      # msecrets.json + your key (OS keychain when available)
msecrets set DATABASE_URL          # prompts for the value
msecrets                           # terminal UI: every secret in every environment
msecrets run -- npm start          # secrets as environment variables, for any language
```

In TypeScript or JavaScript, import the file and get your secrets as a typed object:

```bash
npm install --allow-git=root github:k18k/msecrets#ts-sdk
```

```ts
import { createClient } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

const secrets = createClient(file); // verifies and decrypts the environment, or throws
secrets.DATABASE_URL; // string, names come from your msecrets.json
secrets.DATABSE_URL; // type error
```

The environment is `MSECRETS_ENV` (or `{ env: "production" }`), and the private key comes from your keychain on a
developer machine or from `MSECRETS_IDENTITY` in CI and containers. Libraries that read `process.env` get the values
through `injectEnv(file)`. See the [runtime docs](https://k18k.github.io/msecrets/runtime/).

**Documentation: https://k18k.github.io/msecrets/**

### CI and deployment

```bash
msecrets recipient add github-actions --generate --env production | gh secret set MSECRETS_IDENTITY
```

A read-only key for the workflow goes straight into a GitHub secret. The job sets `MSECRETS_IDENTITY` from it and
`MSECRETS_ENV: production`, then runs `node deploy.ts` as usual. Docker, systemd, and other platforms work the same
way: [CI and containers](https://k18k.github.io/msecrets/runtime/#containers-and-ci).

### AI coding agents

```bash
msecrets skill    # teaches Claude Code, Codex, Cursor, Copilot, Gemini CLI, … to use msecrets
```

Agents learn to use the typed SDK and to manage secrets without ever seeing a value: they ask you to run
`msecrets set` instead. Commit the generated `.claude/skills` and `.agents/skills`. Also available through
`npx skills add k18k/msecrets` and in Claude Code with `/plugin install msecrets --marketplace k18k/msecrets`.
See [AI agents](https://k18k.github.io/msecrets/ai/).

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

## Install

msecrets is installed from this repository only. It is not published to the npm registry; the `@msecrets/*`
packages there are the abandoned 4.0 and get no updates.

npm 12 installs git dependencies only when allowed, hence `--allow-git`. The CLI needs `all`: `cli` pulls the
prebuilt binary for your platform from the `cli-<os>-<arch>` branch (Linux, macOS, Windows; x64 and arm64). Pin a
version with the tag, e.g. `github:k18k/msecrets#cli-v5.0.0`.

| Branch                                       |                                                                                  |
| -------------------------------------------- | -------------------------------------------------------------------------------- |
| `cli` (`@msecrets/cli`)                      | The `msecrets` CLI and terminal UI: a Go binary, behind a small Node.js shim.    |
| `ts-sdk` (`@msecrets/ts-sdk`)                | Runtime SDK: `createClient(file)` returns your typed secrets; `injectEnv(file)`. |

Both have no npm dependencies. The SDK is the Go core compiled to WebAssembly and runs on Node.js 20 or newer.

## Development

Go (version in `go.mod`) and Node.js 26, e.g. through [mise](https://mise.jdx.dev) (`mise install`).

```bash
go test ./...                                              # core, CLI, terminal UI
MSECRETS_PLATFORMS= scripts/build-dist.sh && node --test sdk/test/   # the WebAssembly SDK
scripts/build-dist.sh && scripts/test-install.sh           # every platform; npm install from git branches
(cd docs && bundle install && bundle exec jekyll serve --destination ../.docs-site)   # preview the docs site
```

OS keychain round-trips run with `MSECRETS_TEST_KEYCHAIN=1`.

## Releases

A push to `master` runs CI on Linux, macOS, and Windows with Node.js 20 and 26. When `VERSION` is new, it builds
every platform, commits the packages to the `cli`, `cli-<os>-<arch>`, and `ts-sdk` branches, and tags the release.

## License

MIT
