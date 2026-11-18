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

When you already have a key, `msecrets init` and `join` use it and say which one and where it comes from
(`msecrets whoami` lists them all). Without one, they ask on a terminal how you want to unlock secrets: a new key in
the OS keychain, a passphrase-protected key file, a [password](#password-members), or a key printed once for your
password manager. `--store` and `--password` choose without asking.

`msecrets init`, `join`, and `identity new` store a new key in the OS keychain: the macOS Keychain, the Windows
Credential Manager, or the Linux Secret Service (`secret-tool`). Where none is available (for example in WSL) they
fall back to a private file in your config directory (`--passphrase` encrypts it), and say so. They never replace a
key that is already stored there: it may be the only copy that decrypts your secrets. Use `--account NAME` for
another key, or `msecrets identity use keychain:default` to use the existing one.

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

## Password members

A password member has no key file at all: the key is derived from a password and a random salt stored with the
recipient in `msecrets.json`, so typing the password unlocks it on any machine.

```bash
msecrets init --password                               # or: msecrets join --password
msecrets recipient add dana --password --env development   # for someone else; prints a generated password once
msecrets recipient rotate dana --password              # change the password (re-encrypts dana's values)
```

msecrets asks for the password when it needs a key and none of your loaded keys belongs to the file (Enter skips),
and reads `MSECRETS_PASSPHRASE` without a terminal, also in the SDK. A new password needs at least 16 characters;
press Enter at the prompt for a generated one (`xxxxx-xxxxx-xxxxx-xxxxx`, 100 bits). The public key is in the
repository, so anyone can try to guess the password offline, at about a second per guess: use a generated password,
or a long passphrase, and keep it in a password manager. Forgetting it loses the key; another member can give you a
new one with `msecrets recipient rotate NAME --password`.

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
