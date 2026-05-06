# @msecrets/adapters

Runtime decryption adapters for msecrets.

Adapters are the bridge between `@msecrets/ts-sdk` and private key material.
They receive one encrypted value at a time and return plaintext when they can
decrypt it.

## Install

```bash
npm install @msecrets/adapters
```

## Usage

```ts
import { rawPKs } from "@msecrets/adapters/raw-pks";
import { MSecrets } from "@msecrets/ts-sdk";
import secrets from "./.env.ms.json" with { type: "json" };

const privateKey = process.env["MSECRETS_PRIVATE_KEY"];
if (!privateKey) {
  throw new Error("MSECRETS_PRIVATE_KEY is required");
}

const client = new MSecrets({
  mode: "production",
  secrets,
  adapters: [
    await rawPKs({
      keys: [privateKey],
    }),
  ],
});

const value = await client.get("DB_PASSWORD");
```

CommonJS applications can load the same committed secrets file with `require`:

```js
const { rawPKs } = require("@msecrets/adapters/raw-pks");
const { MSecrets } = require("@msecrets/ts-sdk");
const secrets = require("./.env.ms.json");
```

## Adapters

### `@msecrets/adapters/raw-pks`

OpenPGP-native adapter for ASCII-armored private keys.

```ts
import { rawPKs } from "@msecrets/adapters/raw-pks";

const adapter = await rawPKs({
  keys: [process.env["MSECRETS_PRIVATE_KEY"] ?? ""],
});
```

Prefer this adapter for portable runtime decryption. It does not use the local
GPG keyring.

### `@msecrets/adapters/gpg`

Convenience adapter that shells out to local `gpg --decrypt`.

```ts
import { gpg } from "@msecrets/adapters/gpg";

const adapter = gpg();
```

Use this for local development when relying on an existing GPG keyring is
acceptable. It is not the portable runtime path.

### `@msecrets/adapters/docker-secrets`

Adapter for container runtimes that mount private key material as Docker secret
files.

```ts
import { dockerSecrets } from "@msecrets/adapters/docker-secrets";

const adapter = dockerSecrets();
```

By default it looks in `/run/secrets` for one of:

- `msecrets-private-key.asc`
- `msecrets-private-key.gpg`
- `msecrets-private-key`

You can override both the directory and accepted filenames:

```ts
const adapter = dockerSecrets({
  directory: "/run/secrets",
  keyFilenames: ["msecrets-private-key.asc"],
});
```

## Publish Readiness

```bash
npm --workspace @msecrets/adapters run build
npm pack --dry-run --workspace @msecrets/adapters
```
