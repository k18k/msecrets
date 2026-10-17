---
layout: default
title: Runtime SDK
description: Read msecrets values at runtime with @msecrets/ts-sdk.
eyebrow: "@msecrets/ts-sdk"
lead: Applications read the committed file and decrypt their environment with a synchronous, dependency-free SDK, or without any code through a preload.
permalink: /runtime/
hero_shell: |-
  npm install @msecrets/ts-sdk
  node --import @msecrets/ts-sdk/register server.js
---

## Three ways in

<div class="cards three">
  <article class="card accent">
    <span class="kicker">No code</span>
    <h3>Preload</h3>
    <p><code>node --import @msecrets/ts-sdk/register app.js</code> (or <code>--require</code>) fills <code>process.env</code> before your app starts.</p>
  </article>
  <article class="card blue">
    <span class="kicker">One call</span>
    <h3>load()</h3>
    <p>Returns the complete, frozen environment or throws. A running app never sees half of its secrets.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Typed</span>
    <h3>createClient()</h3>
    <p>With a JSON import, secret names are checked by TypeScript. Values are decrypted on demand.</p>
  </article>
</div>

```ts
import { createClient, load } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

const all = load({ env: "production" });

const secrets = createClient({ file, env: "production" });
secrets.get("DATABASE_URL"); // typed from the file
secrets.has("SENTRY_DSN"); // no key needed
```

Not using Node.js directly? `msecrets run -- <command>` does the same for any language.

## Choosing the environment

`env` option, else `MSECRETS_ENV`, else `development` when the file has it, else the only environment. Set
`MSECRETS_ENV` in every deployed environment.

## Where keys come from

The SDK loads the private key on the first decryption, from the first of these that is set:

1. `MSECRETS_IDENTITY`: the key itself. Read once, then deleted from `process.env`.
2. `MSECRETS_IDENTITY_FILE`: a key file; `MSECRETS_PASSPHRASE` unlocks passphrase-protected files.
3. `MSECRETS_IDENTITY_SOURCE`: one [source]({{ '/identities/' | relative_url }}), e.g. `op://Prod/app/msecrets`.
4. `/run/secrets/msecrets_identity` (Docker, Swarm, Compose) and `$CREDENTIALS_DIRECTORY/msecrets_identity` (systemd).
5. Only if none of those is set: the developer's msecrets config, so local development needs no setup.

To be explicit, pass `identities`:

```ts
createClient({ identities: ["file:/etc/app/msecrets.key"] });
createClient({ identities: [fromEnv("APP_MSECRETS_KEY")] });
```

## Containers and CI

```bash
# Once, by a member with access to production:
msecrets recipient add api-production --generate --env production
```

The printed identity is shown once and stored nowhere. Put it in your platform's secret store and expose it to the
container as `MSECRETS_IDENTITY` or as a file at `/run/secrets/msecrets_identity`:

```yaml
# docker-compose.yml
services:
  api:
    image: my-api
    environment:
      MSECRETS_ENV: production
    command: node --import @msecrets/ts-sdk/register server.js
    secrets: [msecrets_identity]
secrets:
  msecrets_identity:
    environment: MSECRETS_IDENTITY
```

{% raw %}
```yaml
# GitHub Actions
- run: npx msecrets run --env production -- ./deploy.sh
  env:
    MSECRETS_IDENTITY: ${{ secrets.MSECRETS_IDENTITY }}
```
{% endraw %}

Machine keys made with `--generate` can read their environments but never write: their public key has no signing
key. Give each deployment target its own key so you can revoke one without touching the others.

## API

|                                                                                                     |                                                                                                                                |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `createClient(options?)`                                                                            | Client for one environment: `environment`, `get`, `has`, `keys`, `all`, `identities`.                                          |
| `load(options?)`                                                                                    | Every value of the environment, frozen; throws if incomplete.                                                                  |
| `injectEnv(options?)`                                                                               | Writes the environment into `process.env`; set variables win unless `override: true`.                                          |
| `fromEnv`, `fromFile`, `fromCommand`, `fromKeychain`, `fromString`, `parseSourceSpec`, `autoSource` | Identity sources.                                                                                                              |
| `MsecretsError`, `isMsecretsError(error, code?)`                                                    | Errors carry a `code`: `NOT_FOUND`, `ACCESS_DENIED`, `SIGNATURE`, `INVALID_FILE`, `IDENTITY_SOURCE`, `UNSUPPORTED`, `USAGE`, … |

Options: `file` (parsed file or path), `env`, `identities`, `cwd`.

Everything is synchronous, so it also works in CommonJS preloads, configuration files, and module initialization.
