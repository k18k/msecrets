---
name: msecrets
description: Work with msecrets, encrypted secrets committed as msecrets.json. Use when code needs a secret, API key, token, password, connection string, or environment variable in a project that has msecrets.json or depends on @msecrets/ts-sdk; when adding, renaming, scoping, or removing a secret; when wiring secrets into an app, tests, Docker, CI, or a deployment; or when someone asks how to use msecrets.
---

# msecrets

msecrets keeps a project's secrets in one committed file, `msecrets.json`. Every value is encrypted with age to the
people and machines of its environment (for example `development`, `production`) and signed by whoever set it.
Code reads the values with `@msecrets/ts-sdk`; people manage them with the `msecrets` CLI and terminal UI. Docs:
https://k18k.github.io/msecrets/

If `msecrets` is not installed, a person installs the CLI (a native binary, through npm) with:

```bash
npm install -g --allow-git=all github:k18k/msecrets#cli
```

## Rules

Secret values belong to the people who own them. Never let one pass through you.

- **Never reveal values.** Do not run `msecrets get`, `msecrets export`, `msecrets run -- env` (or anything else that
  prints the environment), or the terminal UI. Do not read key files, keychains, `~/.config/msecrets`, or
  `MSECRETS_IDENTITY`.
- **Never handle values.** Do not ask anyone to paste a secret into the conversation, and never write one into code,
  tests, fixtures, `.env` files, command lines, or logs. People set values themselves (see "Add or change a secret").
- **Never edit `msecrets.json` by hand.** Values are ciphertext with signatures, and the file is validated strictly;
  change it only through `msecrets` commands. Never commit a broken file: `msecrets check` must pass.
- **Safe to run any time** (public data only, no key needed): `msecrets ls`, `msecrets ls --json`,
  `msecrets check`, `msecrets env ls`, `msecrets recipient ls`. Reading `msecrets.json` is also fine for
  secret names, descriptions, environments, and who has access.

## Read secrets in TypeScript or JavaScript

Install the runtime SDK as a regular dependency (it has no dependencies of its own, Node.js 20+). It is installed from
git and imported as `@msecrets/ts-sdk`:

```bash
npm install --allow-git=root github:k18k/msecrets#ts-sdk
```

Create the secrets once, in one module, at startup:

```ts
// src/secrets.ts
import { createClient } from "@msecrets/ts-sdk";
import file from "../msecrets.json" with { type: "json" };

export const secrets = createClient(file);
export type AppSecrets = typeof secrets;
```

Use them anywhere:

```ts
import { secrets } from "./secrets.ts";

const db = connect(secrets.DATABASE_URL); // string
if (secrets.SENTRY_DSN) initSentry(secrets.SENTRY_DSN); // string | undefined
```

How it behaves:

- `createClient(file)` verifies and decrypts every secret of the environment synchronously and returns a frozen object
  shaped like the file. It throws if anything is missing, tampered with, or unreadable, so the app fails at startup
  instead of later. Create it once (module level), not per request.
- **Types come from `msecrets.json`.** A secret that applies to every environment is `string`. A secret limited to
  some environments (it has `"environments": [...]` in the file) is `string | undefined`: handle `undefined`, do not
  silence it with `!` or a cast.
- `Property 'X' does not exist` means `X` is not in `msecrets.json`. Do not cast it away: the secret has to be added
  (see below), or the name is a typo.
- The environment is `MSECRETS_ENV`, else `development` when the file has it, else its only environment. Pass
  `createClient(file, { env: "production" })` only when the code must pin one.
- `console.log(secrets)` prints only names. Still never log individual values.
- TypeScript needs `"resolveJsonModule": true`. With `"module": "nodenext"` use `with { type: "json" }` as above; with
  a bundler (Vite, webpack, esbuild, Next.js) a plain `import file from "../msecrets.json"` works; in CommonJS use
  `createClient(require("../msecrets.json"))`. Make sure `msecrets.json` ships with the app (bundlers inline it; for
  `tsc` builds and Docker images, copy it).
- Server-side only: the SDK reads keys through Node.js (`node:fs`, `node:child_process`). Never import it into browser or client components.

Do not:

- read or parse `msecrets.json` yourself, or add `dotenv` for these secrets;
- use `process.env.X` for values that live in msecrets, unless a library requires `process.env`.

### Libraries that read `process.env`

Some libraries (ORMs, frameworks) read `process.env` themselves. Fill it before they load:

```ts
// src/env.ts: import this first, before anything that reads process.env
import { injectEnv } from "@msecrets/ts-sdk";
import file from "../msecrets.json" with { type: "json" };

injectEnv(file); // variables that are already set win; { override: true } replaces them
```

ES module imports run before the importing module's body, so `injectEnv` must sit in its own module imported first,
not below other imports in the same file. Alternatively, start the process with
`msecrets run -- <command>`, e.g. `"dev": "msecrets run -- next dev"` in `package.json`. `msecrets run` is also the
way for non-Node.js languages (Python, Go, Ruby, shell scripts): `msecrets run -- python app.py`.

### Errors

The SDK throws `MsecretsError`; `isMsecretsError(error, code)` checks the `code`:

| Code              | Meaning                                                  | What to do                                                                                                    |
| ----------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `NOT_FOUND`       | The environment is incomplete, or does not exist         | Run `msecrets ls` to see what is missing; ask a person to set it                                          |
| `IDENTITY_SOURCE` | No private key found                                     | Developer machine: `msecrets init` (new file) or `msecrets join`. Deployment: set `MSECRETS_IDENTITY` |
| `ACCESS_DENIED`   | This key is not a recipient of the environment           | A member grants access: `msecrets grant NAME ENV` (or `msecrets sync` after a `join`)                 |
| `SIGNATURE`       | A value was changed or written by someone without access | Stop. Do not work around it; tell a person, and review the history of `msecrets.json`                         |
| `INVALID_FILE`    | `msecrets.json` is malformed, often after a bad merge    | Restore it from git; `msecrets git setup` prevents merge conflicts                                        |

## Tests

Do not decrypt real secrets in unit tests. Pass values in, and build fakes from the type:

```ts
import type { AppSecrets } from "./secrets.ts";

export function createApp(secrets: AppSecrets) {
  /* … */
}

// test
const fake: AppSecrets = { DATABASE_URL: "postgres://localhost/test", SENTRY_DSN: undefined };
createApp(fake);
```

Tests that need real values (integration tests in CI) use a machine key for a dedicated environment, set as
`MSECRETS_IDENTITY` with `MSECRETS_ENV` in the CI secret store.

## Add or change a secret

1. Check what exists: `msecrets ls`.
2. A person sets the value in their own terminal; the prompt hides it:
   - `msecrets set NAME` (default environment), `msecrets set NAME --env production`, or
     `msecrets set NAME --all` for the same value everywhere
   - `-d "What it is for"` adds a description that teammates and agents see
3. Every environment the secret applies to needs a value, or `msecrets check` fails and apps refuse to start. A
   secret that only some environments use: `msecrets scope NAME staging production`.
4. Commit `msecrets.json`.

Give the person the exact commands and wait for them; do not invent placeholder values. One exception: a value that
no person has to know, like a random session key, can be generated and piped straight in so it is never printed:

```bash
node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))" \
  | msecrets set SESSION_SECRET --env development
```

Use a separate value per environment. Structural changes do not reveal values and are fine when the user asks for
them: `msecrets mv OLD NEW` (then update the code; the types point at every use), `msecrets rm NAME`,
`msecrets describe NAME "text"`, `msecrets scope NAME ENV…`.

## Deploy

1. Once, a person with access creates a read-only machine key:
   `msecrets recipient add api-production --generate --env production`. It is printed once.
2. They store it in the platform's secret store and expose it as `MSECRETS_IDENTITY` (or a file at
   `/run/secrets/msecrets_identity`), with `MSECRETS_ENV=production`.
3. The app runs unchanged; `createClient(file)` picks both up. The key is removed from `process.env` after loading.
4. CI runs `msecrets check` (no key needed) so incomplete environments never merge.

Never create machine keys yourself or pass them through the conversation: give the person the commands.

### GitHub Actions

The person creates the key and pipes it straight into a GitHub secret, so it is never printed:

```bash
msecrets recipient add github-actions --generate --env production | gh secret set MSECRETS_IDENTITY
git add msecrets.json && git commit -m "GitHub Actions can read production secrets"
```

You may write the workflow:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    env:
      MSECRETS_IDENTITY: ${{ secrets.MSECRETS_IDENTITY }}
      MSECRETS_ENV: production
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 24
      - run: npm ci
      - run: node deploy.ts # createClient(file) reads both variables
```

- One key per target and environment (`github-actions-staging` with `--env staging`, …).
- With GitHub Environments, `gh secret set MSECRETS_IDENTITY --env production` limits the key to jobs with
  `environment: production`, behind its approval rules.
- Pull request workflows run `msecrets check` without any key.
- Never print the secrets in a workflow (`msecrets export`, `env`, `echo`); logs are readable by everyone with access
  to the repository.
- If `gh secret set` failed, replace the key: `msecrets recipient rotate github-actions --generate | gh secret set MSECRETS_IDENTITY`.
- Revoke with `msecrets recipient rm github-actions`, delete the GitHub secret, and rotate the values it lists.

## Explaining msecrets to a person

When someone asks how to use it, point them to the step they need:

- **Start a project:** `msecrets init`. Creates `msecrets.json` and their key, stored in the OS keychain.
- **Join a project:** `msecrets join`, commit and push; a member then runs `msecrets sync` and pushes.
- **See and edit everything:** `msecrets` opens the terminal UI (secrets × environments; `?` shows the keys).
- **Set a value:** `msecrets set NAME`. **Run the app with secrets:** `msecrets run -- npm run dev`.
- **Their keys:** `msecrets whoami`. Keys can live in the OS keychain, 1Password, Bitwarden, pass, or a file:
  https://k18k.github.io/msecrets/identities/
- **Access:** `msecrets grant NAME ENV`, `msecrets revoke NAME ENV`. After a revoke, rotate the values it lists:
  the person may have kept copies.
- **Readable diffs and merges:** `msecrets git setup` once per clone.
