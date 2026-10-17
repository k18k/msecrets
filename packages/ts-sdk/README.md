# @msecrets/ts-sdk

Runtime SDK for [msecrets](https://k18k.github.io/msecrets/): verify and decrypt the secrets committed in
`msecrets.json`. **Zero dependencies**, synchronous, ESM and CommonJS, Node.js 20 or newer on every platform.

```bash
npm install @msecrets/ts-sdk
```

Create and edit the secrets file with the [`msecrets` CLI](https://www.npmjs.com/package/@msecrets/ui).

## Use it

### No code changes: preload

```bash
node --import @msecrets/ts-sdk/register server.js     # ESM
node --require @msecrets/ts-sdk/register server.js    # CommonJS
```

Every secret of the selected environment becomes an environment variable before your app starts. Variables that
are already set win. If anything is missing, tampered with, or unreadable, the process stops with a clear error.

### Load everything

```ts
import { load } from "@msecrets/ts-sdk";

const secrets = load(); // { DATABASE_URL: "…", STRIPE_KEY: "…" }, frozen
```

`load()` returns the complete environment or throws: a running app never sees half of its secrets.

### Typed access

```ts
import { createClient } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

const secrets = createClient({ file, env: "production" });
secrets.get("DATABASE_URL"); // string
secrets.get("DATABSE_URL"); // type error: names come from your secrets file
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
createClient({ identities: ["env:PROD_KEY", "file:/etc/app/msecrets.key"] });
```

The key is only loaded when the first value is decrypted.

## Environment

`env` option, else `MSECRETS_ENV`, else `development` when it exists, else the only environment of the file.

## API

|                                                                                       |                                                                                        |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `createClient(options?)`                                                              | A client for one environment.                                                          |
| `client.get(name)`                                                                    | Verifies and decrypts one value.                                                       |
| `client.has(name)` / `client.keys()`                                                  | What has a value in this environment (no key needed).                                  |
| `client.all()`                                                                        | Every value of the environment; throws if the environment is incomplete.               |
| `load(options?)`                                                                      | `createClient(options).all()`.                                                         |
| `injectEnv(options?)`                                                                 | Writes the environment into `process.env` (`override: true` to replace set variables). |
| `fromEnv`, `fromFile`, `fromCommand`, `fromKeychain`, `fromString`, `parseSourceSpec` | Identity sources.                                                                      |

Options: `file` (parsed file or path; default: `MSECRETS_FILE`, else `msecrets.json` in the working directory or a
parent), `env`, `identities`, `cwd`.

Errors are `MsecretsError` instances with a `code`: `NOT_FOUND`, `ACCESS_DENIED`, `SIGNATURE`, `INVALID_FILE`,
`IDENTITY_SOURCE`, `UNSUPPORTED`, …

## Security

Values are encrypted with age (X25519, or ML-KEM-768 + X25519 for post-quantum keys) and every value is signed with
Ed25519 by a member of its environment. Before decrypting, the SDK verifies that the signature binds the ciphertext
to this file, secret, environment, and recipient set, and that the signer may write there.

## License

MIT
