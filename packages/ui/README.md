# @msecrets/ui

Local web UI for managing msecrets encrypted environment files.

`@msecrets/ui` starts a small local HTTPS server bound to `127.0.0.1`, serves the bundled msecrets UI, and connects it to a selected `.env.ms.json` / `secrets.ms.json` workspace file.

## Install

```bash
npm install -g @msecrets/ui
````

Or run without installing:

```bash
npx @msecrets/ui .env.ms.json
```

## Usage

Pass the msecrets workspace file as the first positional argument:

```bash
npx @msecrets/ui .env.ms.json
```

Use a custom port:

```bash
npx @msecrets/ui .env.ms.json --port 9842
```

Short form:

```bash
npx @msecrets/ui .env.ms.json -p 9842
```

If no file path is provided, the UI defaults to:

```txt
.env.ms.json
```

## What it does

`@msecrets/ui` provides a local browser interface for:

* initializing a msecrets workspace file
* managing environments
* importing recipient public keys
* importing temporary runtime private keys
* creating, renaming, and deleting secrets
* setting encrypted values per environment
* peeking/decrypting values when a matching runtime private key is loaded
* sharing and revoking encrypted values for configured recipient keys

## Security defaults

The UI is intentionally local-first:

* binds only to `127.0.0.1`
* serves over local HTTPS with a throwaway certificate
* does not expose the server on your LAN
* keeps imported runtime private keys in process memory only
* exits automatically after a period of inactivity
* reads and writes the workspace file directly on your machine

The local HTTPS certificate is generated at startup and is not intended to establish public trust. Your browser may show a certificate warning.

## GPG key support

If a supported local GPG provider is available, the UI can list available keys and import matching public or private key material.

Private keys imported into the UI are runtime-only. They are used for local decrypt/peek operations and are not written into the msecrets workspace file.

## Package

```txt
@msecrets/ui
```

Binary:

```txt
@msecrets/ui
```

Published files:

```txt
dist/
```

## Development

From the repository root:

```bash
npm --workspace @msecrets/ui run build
```

Run the e2e test:

```bash
npm --workspace @msecrets/ui run test:e2e
```

Run the development server:

```bash
npm --workspace @msecrets/ui run dev
```

Run the production server locally:

```bash
npm --workspace @msecrets/ui run start
```

## Build layout

The package builds two parts:

* server runtime with `tsdown`
* client SPA with Vite

```bash
npm --workspace @msecrets/ui run server:build
npm --workspace @msecrets/ui run client:build
```

The production server serves the built client from:

```txt
dist/client
```

## License

See the repository license.