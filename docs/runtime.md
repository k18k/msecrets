---
layout: default
title: Runtime SDK
description: Runtime SDK and adapter usage for msecrets.
eyebrow: Application interface
lead: Applications read the committed secrets file with @msecrets/ts-sdk and decrypt values through stateless adapters.
permalink: /runtime/
hero_shell: |-
  import { MSecrets } from "@msecrets/ts-sdk";
  import { rawPKs } from "@msecrets/ts-sdk/adapters/raw-pks";

  const client = new MSecrets({ mode, secrets, adapters });
  const password = await client.get("DB_PASSWORD");
---

## Install

```bash
npm install @msecrets/ts-sdk
```

## Recommended path

Prefer `@msecrets/ts-sdk/adapters/raw-pks` for OpenPGP-native runtime decryption without coupling the application to a local GPG keyring.

```ts
import { rawPKs } from "@msecrets/ts-sdk/adapters/raw-pks";
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

<div class="cards three">
  <article class="card accent">
    <span class="kicker">Validate first</span>
    <h3>Bad files fail early</h3>
    <p>The SDK validates the secrets file before decrypting values, including format compatibility and selected mode.</p>
  </article>
  <article class="card blue">
    <span class="kicker">Adapter chain</span>
    <h3>Try multiple providers</h3>
    <p>Applications can provide more than one stateless adapter. The SDK reports all adapter failures if none can decrypt.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Process cache</span>
    <h3>Decrypt once per client</h3>
    <p>Decrypted values are cached for the lifetime of the client instance to avoid repeated private key work.</p>
  </article>
</div>

## Client API

<div class="cards">
  <article class="card">
    <h3><code>listKeys()</code></h3>
    <p>Returns secret names that have a value for the configured mode.</p>
  </article>
  <article class="card">
    <h3><code>has(key)</code></h3>
    <p>Checks whether a secret has a value for the configured mode.</p>
  </article>
  <article class="card">
    <h3><code>get(key)</code></h3>
    <p>Decrypts and returns one secret value, cached for the client lifetime.</p>
  </article>
</div>

## Adapters

- `@msecrets/ts-sdk/adapters/raw-pks`: raw armored private keys.
- `@msecrets/ts-sdk/adapters/docker-secrets`: private key material from Docker secrets.
- `@msecrets/ts-sdk/adapters/gpg`: local GPG-backed decryption when that is appropriate.

> Adapters are stateless, do not mutate global state, and return plaintext only. The SDK owns runtime selection and validation.
