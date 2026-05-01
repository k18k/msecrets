# @msecrets/ts-sdk

Runtime TypeScript client for reading and decrypting values from a committed
`.env.ms.json` file.

The SDK is the runtime entry point for msecrets applications. It validates the
secrets file, selects values for the requested mode, and asks one or more
stateless adapters to decrypt each value.

## Install

```bash
npm install @msecrets/ts-sdk @msecrets/adapters
```

The SDK bundles the small core runtime code it needs. Install
`@msecrets/adapters` when you want the official adapters for raw OpenPGP private
keys, Docker secrets, or local GPG-backed decryption.

## Quick Start

```ts
import { rawPKs } from "@msecrets/adapters/raw-pks";
import { MSecrets } from "@msecrets/ts-sdk";
import secrets from "./.env.ms.json" with { type: "json" };

const privateKey = process.env["MSECRETS_PRIVATE_KEY"];
if (!privateKey) {
  throw new Error("MSECRETS_PRIVATE_KEY is required");
}

const adapter = await rawPKs({
  keys: [privateKey],
});

const client = new MSecrets({
  mode: "production",
  adapters: [adapter],
  secrets,
});

const password = await client.get("DB_PASSWORD");
```

CommonJS applications can load the same committed file with `require`:

```js
const { rawPKs } = require("@msecrets/adapters/raw-pks");
const { MSecrets } = require("@msecrets/ts-sdk");
const secrets = require("./.env.ms.json");
```

## API

### `new MSecrets(config)`

Creates a client for one secrets file and one runtime mode.

```ts
type MSecretsConfig = {
  secrets: SecretsFile;
  mode: string;
  adapters: MSecretsAdapter[];
};
```

- `secrets` is the parsed `.env.ms.json` content.
- `mode` must exist in `secrets.environments`.
- `adapters` must contain at least one runtime adapter.

The constructor validates the secrets file before any decryption attempt.

### `client.listKeys()`

Returns secret names that have a value for the configured mode.

### `client.has(key)`

Returns whether a secret has a value for the configured mode.

### `client.get(key)`

Decrypts and returns one secret value. Results are cached in memory for the
life of the client instance. If an adapter cannot decrypt the value, the SDK
tries the next adapter and reports all adapter errors if none succeed.

## Publish Readiness

```bash
npm --workspace @msecrets/ts-sdk run build
npm --workspace @msecrets/ts-sdk run test
npm --workspace @msecrets/ts-sdk run test:e2e
npm pack --dry-run --workspace @msecrets/ts-sdk
```
