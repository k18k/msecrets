# @msecrets/ui

The msecrets command line and terminal UI: encrypted secrets that live in your repository.

You commit one file, `msecrets.json`. Every value in it is encrypted with [age](https://age-encryption.org) to the
people and machines that may read its environment, and signed by whoever wrote it. There is no server, no account,
and nothing to provision. **Zero dependencies.**

```bash
npm install --save-dev @msecrets/ui   # or: npm install --global @msecrets/ui
npx msecrets                          # open the terminal UI
```

Requires Node.js 20 or newer on Linux, macOS, or Windows. Post-quantum keys need Node.js 24.7 or newer.

## Start in a minute

```bash
msecrets init                          # creates msecrets.json and your key (OS keychain when available)
msecrets set DATABASE_URL              # prompts for the value; nothing lands in your shell history
msecrets set STRIPE_KEY --all          # same value for every environment
msecrets run -- npm start              # your app gets the secrets as environment variables
msecrets git setup                     # readable `git diff` and conflict-free merges
git add msecrets.json .gitattributes && git commit -m "Add secrets"
```

`msecrets` without arguments opens the terminal UI: a matrix of every secret in every environment, where you can add,
edit, reveal, rename, and delete secrets, and manage environments and access.

```
 msecrets  msecrets.json  you: alice
 1 Secrets   2 Environments   3 Recipients   4 Checks
──────────────────────────────────────────────────────────────────
  SECRET        development  staging  production  DESCRIPTION
› DATABASE_URL  [●]           ●        ●          Primary database
  SENTRY_DSN     ·            ●        ●          Error reporting
  STRIPE_KEY     ●            ●        ◐          Payments
──────────────────────────────────────────────────────────────────
● set  ◐ needs sync  ○ missing  ✗ bad signature   1 error(s)
enter edit · v reveal · a add · r rename · d delete · s sync · ? help
```

## Never worry about secrets being out of sync

- **Completeness:** every secret must have a value in every environment it applies to. `msecrets check` fails CI
  when one is missing, and `msecrets run` refuses to start an incomplete environment.
- **Access drift:** when someone gains or loses access, values encrypted for the old set of people show up as
  _needs sync_. `msecrets sync` fixes them; `check` fails until then.
- **Integrity:** every value is signed by a member of its environment. A value that was tampered with, copied from
  another secret or environment, or written by someone without access is rejected.
- **Reviewable:** after `msecrets git setup`, `git diff` shows which values changed and who signed them, and
  independent changes on two branches merge without conflicts.

## Commands

| Task                           | Command                                                                            |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| Show everything                | `msecrets ls` (`--json` for scripts)                                               |
| Read / write a value           | `msecrets get NAME`, `msecrets set NAME [VALUE] [--env NAME \| --all]`             |
| Remove / rename / document     | `msecrets unset`, `msecrets rm`, `msecrets mv`, `msecrets describe`                |
| Limit a secret to environments | `msecrets scope SENTRY_DSN staging production`                                     |
| Environments                   | `msecrets env ls \| add \| rm \| mv`                                               |
| People and machines            | `msecrets recipient ls \| add \| rm \| mv \| rotate`                               |
| Access                         | `msecrets grant bob production`, `msecrets revoke bob production`, `msecrets sync` |
| Run your app                   | `msecrets run [--env NAME] -- <command>`                                           |
| Export / import                | `msecrets export --format dotenv\|json\|shell\|powershell`, `msecrets import .env` |
| CI                             | `msecrets check`                                                                   |
| Your keys                      | `msecrets whoami`, `msecrets identity new \| show \| use \| export`                |
| AI coding agents               | `msecrets skill` (`--global` for all your projects)                                |

The environment is `--env`, else `MSECRETS_ENV`, else `development` when it exists, else the only environment.
Run `msecrets <command> --help` for details.

## Working in a team

```bash
# Bob, in a fresh clone:
msecrets join --env development        # adds his public key; commit and open a pull request
# Alice, after reviewing it:
msecrets sync                          # re-encrypts the values for Bob
```

Revoking re-encrypts every affected value without the person and lists the secrets they could read, so you know
what to rotate. Encryption cannot take back what someone already copied.

## Keys in your password manager

Your key is one line (`AGE-SECRET-KEY-1…`). Keep it wherever you like:

```bash
msecrets identity new --store print    # print a new key to paste into your password manager
msecrets identity use op://Private/msecrets/identity   # 1Password
msecrets identity use bw:msecrets                      # Bitwarden
msecrets identity use pass:dev/msecrets                # pass
msecrets identity use keychain:default                 # macOS Keychain, Windows Credential Manager, Secret Service
msecrets identity use "cmd:gopass show -o msecrets"    # anything that prints the key
```

Sources live in your own config file (`~/.config/msecrets/config.json`, `%APPDATA%\msecrets` on Windows), never
in the repository. Existing age keys and `ssh-ed25519` keys (including passphrase-protected ones) work too.

## CI and containers

```bash
msecrets recipient add deploy --generate --env production | gh secret set MSECRETS_IDENTITY
```

The machine key is printed once, never stored. At runtime, provide it as `MSECRETS_IDENTITY`, or mount it at
`/run/secrets/msecrets_identity` (Docker, Swarm, Compose) or as the systemd credential `msecrets_identity`.
`msecrets run` and the SDK remove it from the environment before your app starts. Machine keys created this way can
read but never write. Set `MSECRETS_ENV` (for example `production`) next to it. A complete GitHub Actions setup:
https://k18k.github.io/msecrets/runtime/#github-actions

## AI coding agents

```bash
msecrets skill    # writes .claude/skills/msecrets and .agents/skills/msecrets; commit them
```

The skill teaches Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and other agents to read secrets with the
typed SDK and to manage them without ever seeing a value. In Claude Code it is also a plugin:

```
/plugin install msecrets --marketplace k18k/msecrets
```

## Documentation

https://k18k.github.io/msecrets/ · the runtime SDK is [`@msecrets/ts-sdk`](https://www.npmjs.com/package/@msecrets/ts-sdk).

## License

MIT
