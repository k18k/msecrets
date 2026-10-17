---
layout: default
title: Keys
description: Where msecrets private keys live, for developers and machines.
eyebrow: Identities
lead: A key is one line of text. Keep it in your OS keychain, your password manager, or your platform's secret store, never in the repository.
permalink: /identities/
hero_shell: |-
  msecrets identity new
  msecrets identity use op://Private/msecrets/identity
  msecrets whoami
---

## Key types

| Private key (identity)                               | Public key (in `msecrets.json`) | Can                  |
| ---------------------------------------------------- | ------------------------------ | -------------------- |
| `AGE-SECRET-KEY-1…`                                  | `msecrets1…`                   | read and write       |
| `AGE-SECRET-KEY-PQ-1…` (post-quantum, `--pq`)        | `msecrets1…`                   | read and write       |
| any of the above                                     | `age1…` / `age1pq1…`           | read only (machines) |
| OpenSSH `ssh-ed25519`, plain or passphrase-protected | `ssh-ed25519 AAAA…`            | read and write       |

Identities are standard [age](https://age-encryption.org) keys, so keys made with `age-keygen` work, and values can
be decrypted with `age` itself. An `msecrets1…` public key carries the age encryption key and an Ed25519 key that
verifies the values its owner writes; the signing key is derived from the identity.

Post-quantum keys (ML-KEM-768 + X25519, the age `mlkem768x25519` recipient type) protect values against future
quantum computers, which matters for data that stays in git history forever. Everyone who reads them needs Node.js
24.7 or newer. An environment mixing post-quantum and classical recipients is only as strong as the classical ones,
and `msecrets check` warns about it.

## For developers

`msecrets init`, `join`, and `identity new` create a key and store it in the OS keychain: the macOS Keychain, the
Windows Credential Manager, or the Linux Secret Service (`secret-tool`). Where none is available they fall back to a
private file in your config directory (`--passphrase` encrypts it). They never replace a key that is already stored
there: it may be the only copy that decrypts your secrets. Use `--account NAME` for another key, or
`msecrets identity use keychain:default` to use the existing one.

To use a password manager instead, put the key there and point msecrets at it:

| Source                  | Reads the key with                                                |
| ----------------------- | ----------------------------------------------------------------- |
| `op://vault/item/field` | 1Password CLI: `op read`                                          |
| `bw:ITEM`               | Bitwarden CLI: `bw get password ITEM`                             |
| `pass:NAME`             | `pass show NAME`                                                  |
| `keychain:ACCOUNT`      | the OS keychain                                                   |
| `file:PATH` or a path   | a key file (age format; SSH keys; passphrase-encrypted age files) |
| `env:NAME`              | an environment variable                                           |
| `cmd:COMMAND ARGS…`     | any command that prints the key (gopass, Vault, KeePassXC, …)     |

```bash
msecrets identity new --store print     # prints a new key once; paste it into your password manager
msecrets identity use op://Private/msecrets/identity
msecrets whoami                          # shows which sources were used and what you can access
```

The sources are saved in `config.json` in your config directory (`$XDG_CONFIG_HOME/msecrets` or `~/.config/msecrets`;
`%APPDATA%\msecrets` on Windows; `MSECRETS_CONFIG_DIR` overrides it). They never come from the repository, because a
repository must not be able to run commands on your machine.

## For machines

```bash
msecrets recipient add ci --generate --env staging --env production
```

This prints a new identity once. Store it in your CI or runtime secret store and provide it as `MSECRETS_IDENTITY`,
`MSECRETS_IDENTITY_FILE`, `/run/secrets/msecrets_identity`, or the systemd credential `msecrets_identity`. The SDK
and `msecrets run` remove `MSECRETS_IDENTITY` from the environment before your code runs, and `run` hides all
`MSECRETS_IDENTITY*` variables and `MSECRETS_PASSPHRASE` from the child process.

## Rotating keys

```bash
msecrets recipient rotate ci --generate         # new machine key; values are re-encrypted
msecrets identity new --account new             # your own new key, loaded next to the old one
msecrets recipient rotate alice msecrets1…      # then switch your recipient to it
```

Rotation needs someone who can read every affected environment. Old values remain readable with old keys in git
history, so rotate the secrets themselves when a key was exposed.
