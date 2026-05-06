# msecrets Monorepo

msecrets is a repository-native encrypted secrets system.

Documentation: https://k18k.github.io/msecrets/

This monorepo ships publishable npm packages for:

- authoring via CLI
- runtime decryption via SDK + adapters
- local UI editing/inspection
- shared OpenPGP-native core workflows

## Packages

- `@msecrets/cli` (CLI): interactive authoring and UI launcher
- `@msecrets/core`: file contract, validation, workflows, crypto
- `@msecrets/ts-sdk`: runtime secret reader/decryptor
- `@msecrets/adapters`: runtime decryption adapters
- `@msecrets/ui`: local UI runtime binary

## File Contract

Default secrets file:

```text
.env.ms.json
```

Current format major:

```text
2.x.x
```

Core validates semver and hard-fails on incompatible major versions.

## Local Development

Node.js 24+ is required.

```bash
npm install
npm run build
npm run test
npm run test:e2e
```

Preview the GitHub Pages docs locally:

```bash
npm --workspace @msecrets/docs run preview
```

## Publish Readiness

Run the full release check (without publishing):

```bash
npm run verify:release
```

This includes:

- workspace build
- tests + e2e smoke
- `npm pack --dry-run` for all publishable packages

## UI Binary Usage

The UI no longer relies on `SECRETS_FILE` env.

Use positional config path:

```bash
npx @msecrets/ui secrets.ms.json
```

It binds to `127.0.0.1` and accepts `--port`.
