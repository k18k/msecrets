---
layout: default
title: CLI & terminal UI
description: The msecrets command line and terminal UI.
eyebrow: "@msecrets/ui"
lead: One binary, msecrets, to create the secrets file, set values, run your app, and manage access. Without arguments it opens a full-screen terminal UI.
permalink: /cli/
hero_shell: |-
  npm install --save-dev @msecrets/ui
  npx msecrets --help
---

## Install

```bash
npm install --save-dev @msecrets/ui     # per project: npx msecrets …
npm install --global @msecrets/ui       # everywhere: msecrets …
```

Node.js 20 or newer on Linux, macOS, or Windows. The package has no dependencies.

## The terminal UI

Run `msecrets` (or `msecrets tui`) in a terminal.

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

| Keys                                | Action                                                             |
| ----------------------------------- | ------------------------------------------------------------------ |
| `1`–`4`, `tab`                      | Secrets, Environments, Recipients, Checks                          |
| arrows, `hjkl`, Home/End, PgUp/PgDn | Move                                                               |
| `enter` / `e`                       | Edit the selected value (hidden while typing; `tab` shows it)      |
| `v`                                 | Reveal the selected value; `c` copies it to the clipboard (OSC 52) |
| `a` / `r` / `d`                     | Add, rename, delete (a secret, an environment, or a recipient)     |
| `u` / `D`                           | Unset a value / describe                                           |
| `g` / `x`                           | Grant / revoke access                                              |
| `s`                                 | Sync: re-encrypt values for the current recipients                 |
| `/`                                 | Filter secrets (`esc` clears)                                      |
| `?` / `q`                           | Help / quit                                                        |

In the Checks view, `enter` jumps to the problem.

## Commands

### Get started

| Command                                                                          |                                                                                                       |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `msecrets init [--env a,b] [--name NAME] [--store WHERE] [--pq]` | Create `msecrets.json` with you as the first recipient. Default environments: development, production. `--store`: `keychain` (default), `file`, or `print`. |
| `msecrets join [--env NAME]`                                                     | Add yourself to an existing file. Commit it; a member then runs `msecrets sync`.                      |
| `msecrets whoami`                                                                | Your keys, where they come from, and what they can access.                                            |
| `msecrets identity new`, `show`, `use SOURCE`, `export` | Create, show, configure, or export your keys. See [Keys](../identities/). |

### Secrets

| Command                                                     |                                                                                        |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `msecrets ls [--json]`                                      | Every secret in every environment, with problems.                                      |
| `msecrets get NAME`                                         | Print a value.                                                                         |
| `msecrets set NAME [VALUE] [--env NAME]… [--all] [-d TEXT]` | Encrypt and store a value. Without VALUE it prompts (hidden) or reads stdin.           |
| `msecrets unset NAME [--env NAME]`                          | Remove a value from an environment.                                                    |
| `msecrets rm NAME`, `msecrets mv NAME NEW`                  | Delete or rename a secret.                                                             |
| `msecrets describe NAME [TEXT]`                             | Document a secret.                                                                     |
| `msecrets scope NAME ENV…` or `--all`                         | Limit a secret to some environments, e.g. `SENTRY_DSN` only in staging and production. |

Secret names are environment variable names (`[A-Za-z_][A-Za-z0-9_]*`), so every secret can be injected as-is.

### Environments and access

| Command                                                                                  |                                                                                                         |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `msecrets env ls`, `add NAME [--from ENV] [--recipients a,b]`, `rm NAME`, `mv NAME NEW` | Manage environments. A new environment makes every unscoped secret _missing_ there until it is set.     |
| `msecrets recipient add NAME KEY` (or `github:USER`, or `--generate`) `[--env NAME]…`             | Add a person (their `msecrets1…` key) or a machine (`--generate` prints a new read-only identity once). |
| `msecrets recipient ls`, `rm NAME`, `mv NAME NEW`, `rotate NAME KEY` (or `--generate`)     | List, remove (revokes everything), rename, or replace a key.                                            |
| `msecrets grant RECIPIENT ENV…`                                                          | Give access and re-encrypt what you can read.                                                           |
| `msecrets revoke RECIPIENT ENV…`                                                         | Take access away and re-encrypt without them; lists what to rotate.                                     |
| `msecrets sync [--env NAME]`                                                             | Re-encrypt values whose recipients changed.                                                             |

### Run your app

| Command                                                      |                                                                                                                                                                             |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `msecrets run [--env NAME] [--override] -- COMMAND…`         | Run any command with the environment's secrets as variables. Variables already set win unless `--override`. The child never sees your key. The exit code is passed through. |
| `msecrets export [--format FORMAT]` | Print the decrypted environment: `dotenv` (default), `json`, `shell`, or `powershell`.                                                                                                                                            |
| `msecrets import FILE [--overwrite]` (`-` reads stdin)                    | Import a dotenv file into an environment.                                                                                                                                   |

`run` and `export` refuse an incomplete environment, so an app never starts with half of its secrets.

### CI and git

| Command                   |                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------- |
| `msecrets check [--json]` | Exit 1 unless every value is present, current, and signed. Needs no keys.                       |
| `msecrets git setup`      | Adds `msecrets.json diff=msecrets merge=msecrets` to `.gitattributes` and configures this clone. |

After `git setup`, `git diff` and pull request reviews show changes like:

```diff
 secrets:
   DATABASE_URL: # Primary database
-    production: signed by alice 3f9a0c21d4e8
+    production: signed by bob 77c1e0b9a2f4
```

Two branches that change different secrets, environments, or access lists merge cleanly. Changing the same value on
both sides is a conflict: git keeps your side and lists the conflicting values.

### AI agents

| Command                            |                                                                                                                              |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `msecrets skill [--global] [--print]` | Install the msecrets [agent skill](../ai/) into `.claude/skills` and `.agents/skills` of this repository (or your home directory). |

## Global options

| Option                  |                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------- |
| `-f, --file PATH`       | Secrets file. Default: `MSECRETS_FILE`, else `msecrets.json` in the working directory or a parent. |
| `-e, --env NAME`        | Environment. Default: `MSECRETS_ENV`, else `development` when it exists, else the only one.       |
| `-i, --identity SOURCE` | Use this key or source instead of the defaults (repeatable).                                      |
| `--as RECIPIENT`        | Sign as this recipient when you hold several keys.                                                |

Exit codes: `0` success, `1` failure, `2` usage error, `130` cancelled. `NO_COLOR` and `FORCE_COLOR` are honored.
