---
layout: default
title: Runtime SDK
description: Read msecrets values at runtime with @msecrets/ts-sdk.
eyebrow: "@msecrets/ts-sdk"
lead: Applications import the committed file and get their environment back as a typed object, from a synchronous, dependency-free SDK.
permalink: /runtime/
hero_shell: |-
  npm install @msecrets/ts-sdk
---

## Import the file, get typed secrets

```ts
import { createClient } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

const secrets = createClient(file);

secrets.DATABASE_URL; // string
secrets.SENTRY_DSN; // string | undefined: limited to some environments in the file
secrets.DATABSE_URL; // type error: names come from your msecrets.json
```

<div class="cards three">
  <article class="card accent">
    <span class="kicker">Complete</span>
    <h3>All or nothing</h3>
    <p>Every secret of the environment is verified and decrypted up front. If one is missing, tampered with, or unreadable, <code>createClient</code> throws: a running app never sees half of its secrets.</p>
  </article>
  <article class="card blue">
    <span class="kicker">Typed</span>
    <h3>From your file</h3>
    <p>Names and types come from the imported JSON, so renaming or deleting a secret is a compile error wherever it is used.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Quiet</span>
    <h3>Safe to log</h3>
    <p>The result is frozen, and <code>console.log(secrets)</code> prints only the names, never the values.</p>
  </article>
</div>

TypeScript needs `"resolveJsonModule": true`. With `"module": "nodenext"`, import with `with { type: "json" }`;
with a bundler, `import file from "./msecrets.json"` is enough. In CommonJS: `createClient(require("./msecrets.json"))`.

Libraries that read `process.env` (ORMs, frameworks) get the values through `injectEnv(file)`, called before them;
variables that are already set win. Not using Node.js? `msecrets run -- <command>` does the same for any language.

## Choosing the environment

`env` option, else `MSECRETS_ENV`, else `development` when the file has it, else the only environment. Set
`MSECRETS_ENV` in every deployed environment.

## Where keys come from

The SDK loads the private key from the first of these that is set:

1. `MSECRETS_IDENTITY`: the key itself. Read once, then deleted from `process.env`.
2. `MSECRETS_IDENTITY_FILE`: a key file; `MSECRETS_PASSPHRASE` unlocks passphrase-protected files.
3. `MSECRETS_IDENTITY_SOURCE`: one [source]({{ '/identities/' | relative_url }}), e.g. `op://Prod/app/msecrets`.
4. `/run/secrets/msecrets_identity` (Docker, Swarm, Compose) and `$CREDENTIALS_DIRECTORY/msecrets_identity` (systemd).
5. Only if none of those is set: the developer's msecrets config, so local development needs no setup.

To be explicit, pass `identities`:

```ts
createClient(file, { identities: ["file:/etc/app/msecrets.key"] });
createClient(file, { identities: [fromEnv("APP_MSECRETS_KEY")] });
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
    command: node server.js
    secrets: [msecrets_identity]
secrets:
  msecrets_identity:
    environment: MSECRETS_IDENTITY
```

Machine keys made with `--generate` can read their environments but never write: their public key has no signing
key. Give each deployment target its own key so you can revoke one without touching the others.

## GitHub Actions

Create a key for the workflow and send it straight to a GitHub secret, so it never appears on screen, in your shell
history, or on disk:

```bash
npx msecrets recipient add github-actions --generate --env production | gh secret set MSECRETS_IDENTITY
git add msecrets.json && git commit -m "GitHub Actions can read production secrets" && git push
```

This adds the read-only recipient `github-actions` to `production`, re-encrypts the production values for it with
your key, and stores its private key as the repository secret `MSECRETS_IDENTITY`. If `gh` fails (not logged in),
replace the key with `npx msecrets recipient rotate github-actions --generate | gh secret set MSECRETS_IDENTITY`.

{% raw %}
```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production # optional: GitHub Environments add approvals and branch rules
    env:
      MSECRETS_IDENTITY: ${{ secrets.MSECRETS_IDENTITY }}
      MSECRETS_ENV: production
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 24
      - run: npm ci
      - run: node deploy.ts # createClient(file) reads MSECRETS_IDENTITY and MSECRETS_ENV
```
{% endraw %}

- **One key per target.** `github-actions-staging` with `--env staging`, and so on: a leaked key opens only its
  environment.
- **Protect production with GitHub Environments.** `gh secret set MSECRETS_IDENTITY --env production` stores the
  secret in the `production` environment instead of the repository; only jobs with `environment: production` get
  it, after the approvals you configure.
- **Check every pull request.** `npx msecrets check` needs no key, so it also runs for pull requests from forks,
  which never receive secrets.
- **Revoke.** `npx msecrets recipient rm github-actions` re-encrypts everything without the key; then delete the
  GitHub secret and rotate the values msecrets lists.

## API

|                                                                                                     |                                                                                                                                |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `createClient(file, options?)`                                                                      | Every secret of the environment as a frozen object typed by the file; throws if anything is wrong.                            |
| `injectEnv(file, options?)`                                                                         | Writes the environment into `process.env`; set variables win unless `override: true`.                                          |
| `Secrets<typeof file>`                                                                              | The type of the result.                                                                                                        |
| `fromEnv`, `fromFile`, `fromCommand`, `fromKeychain`, `fromString`, `parseSourceSpec`, `autoSource` | Identity sources.                                                                                                              |
| `MsecretsError`, `isMsecretsError(error, code?)`                                                    | Errors carry a `code`: `NOT_FOUND`, `ACCESS_DENIED`, `SIGNATURE`, `INVALID_FILE`, `IDENTITY_SOURCE`, `UNSUPPORTED`, `USAGE`, … |

Options: `env`, `identities`.

Everything is synchronous, so it also works in CommonJS, configuration files, and module initialization.
