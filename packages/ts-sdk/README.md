# @msecrets/ts-sdk

TypeScript runtime client for reading and decrypting msecrets values.

## Install

```bash
npm install @msecrets/ts-sdk @msecrets/adapters
```

## Quick Start

```ts
import { readFileSync } from "node:fs";
import { rawPKs } from "@msecrets/adapters/raw-pks";
import { MSecrets } from "@msecrets/ts-sdk";

const secrets = JSON.parse(readFileSync(".env.ms.json", "utf8"));

const adapter = await rawPKs({
  keys: [process.env["MSECRETS_PRIVATE_KEY"] ?? ""],
});

const client = new MSecrets({
  mode: "production",
  adapters: [adapter],
  secrets,
});

const password = await client.get("DB_PASSWORD");
```

## Build / Test

```bash
npm --workspace @msecrets/ts-sdk run build
npm --workspace @msecrets/ts-sdk run test
npm --workspace @msecrets/ts-sdk run test:e2e
```
