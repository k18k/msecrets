# @msecrets/ts-sdk

Runtime SDK for [msecrets](https://k18k.github.io/msecrets/): verify and decrypt the secrets committed in
`msecrets.json`. **Zero dependencies**, synchronous, ESM and CommonJS, Node.js 20 or newer on every platform.

```bash
npm install @msecrets/ts-sdk
```

Create and edit the secrets file with the [`msecrets` CLI](https://www.npmjs.com/package/@msecrets/ui).

## Use it

Import your secrets file and pass it to `createClient`. You get back an object shaped like your secrets:

```ts
import { createClient } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

const secrets = createClient(file);

secrets.DATABASE_URL; // string
secrets.SENTRY_DSN; // string | undefined: limited to some environments in the file
secrets.DATABSE_URL; // type error: names come from your msecrets.json
```

- **Complete or nothing:** `createClient` verifies and decrypts every secret of the environment up front, and throws
  if one is missing, tampered with, or unreadable. A running app never sees half of its secrets.
- **Typed:** secret names and types come from the imported JSON, so a renamed or deleted secret is a compile error.
- **Safe to log by accident:** the result is frozen, and `console.log(secrets)` prints only the names.

TypeScript needs `"resolveJsonModule": true`. With `"module": "nodenext"`, import with `with { type: "json" }` as
above; with a bundler, `import file from "./msecrets.json"` is enough. In CommonJS:
`createClient(require("./msecrets.json"))`.

### Libraries that read `process.env`

```ts
import { injectEnv } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

injectEnv(file); // before the code that reads process.env; variables that are already set win
```

Not in Node.js, or no code changes at all? `msecrets run -- <command>` from
[`@msecrets/ui`](https://www.npmjs.com/package/@msecrets/ui) passes the secrets as environment variables.

## Environment

`env` option, else `MSECRETS_ENV`, else `development` when it exists, else the only environment of the file:

```ts
const secrets = createClient(file, { env: "production" });
```

## Where the private key comes from

By default the SDK looks, in this order, at:

1. `MSECRETS_IDENTITY`: the key itself (read once, then removed from `process.env`)
2. `MSECRETS_IDENTITY_FILE`: a path to a key file (`MSECRETS_PASSPHRASE` for passphrase-protected files)
3. `MSECRETS_IDENTITY_SOURCE`: a source such as `op://vault/item/field`, `bw:item`, `pass:name`, `keychain:account`
4. `/run/secrets/msecrets_identity` (Docker, Swarm, Compose) and `$CREDENTIALS_DIRECTORY/msecrets_identity` (systemd)
5. Only when none of those is set: the developer's own msecrets config (OS keychain, password manager, key file)

Pass `identities` to choose explicitly. Strings are keys or source specs:

```ts
createClient(file, { identities: ["env:PROD_KEY", "file:/etc/app/msecrets.key"] });
```

## API

|                                                                                       |                                                                                                  |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `createClient(file, options?)`                                                        | Every secret of the environment as a frozen, typed object; throws if anything is wrong.          |
| `injectEnv(file, options?)`                                                           | Writes the environment into `process.env` (`override: true` to replace set variables, `target`). |
| `Secrets<typeof file>`                                                                | The type of the result, e.g. to pass the secrets around.                                         |
| `fromEnv`, `fromFile`, `fromCommand`, `fromKeychain`, `fromString`, `parseSourceSpec` | Identity sources.                                                                                |

Options: `env`, `identities`.

Errors are `MsecretsError` instances with a `code`: `NOT_FOUND`, `ACCESS_DENIED`, `SIGNATURE`, `INVALID_FILE`,
`IDENTITY_SOURCE`, `UNSUPPORTED`, …

## Security

Values are encrypted with age (X25519, or ML-KEM-768 + X25519 for post-quantum keys) and every value is signed with
Ed25519 by a member of its environment. Before decrypting, the SDK verifies that the signature binds the ciphertext
to this file, secret, environment, and recipient set, and that the signer may write there.

## License

MIT
