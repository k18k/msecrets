---
layout: default
title: Architecture
description: Package boundaries and architecture of msecrets.
eyebrow: Monorepo
lead: One private core with all logic, bundled into two published packages that have no dependencies.
permalink: /architecture/
hero_shell: |-
  @msecrets/ui      CLI + TUI  ─┐
                                ├─ core ─ node:crypto
  @msecrets/ts-sdk  runtime    ─┘
---

## Packages

<div class="cards three">
  <article class="card accent">
    <h3><code>packages/core</code></h3>
    <p>Private. age (X25519, ML-KEM-768 + X25519, scrypt, ssh-ed25519), keys, the file format and validation, operations, status, file storage, identity sources, and the OS keychain.</p>
  </article>
  <article class="card blue">
    <h3><code>@msecrets/ts-sdk</code></h3>
    <p>Runtime: <code>createClient</code> turns an imported secrets file into typed values; <code>injectEnv</code> fills <code>process.env</code>. ESM, CommonJS, and type declarations.</p>
  </article>
  <article class="card gold">
    <h3><code>@msecrets/ui</code></h3>
    <p>The <code>msecrets</code> binary: commands, the terminal UI, <code>run</code>, and git integration. A thin layer over core.</p>
  </article>
</div>

## Principles

- **Core is the source of truth.** The CLI, the terminal UI, and the SDK only call core operations.
- **Operations are transactions.** Each one runs on a copy of the document; the result is validated before an atomic
  write, and nothing is written when anything fails.
- **The file is the contract.** Everything durable is in `msecrets.json`. Keys and identity sources come from the
  caller, the environment, or the user's own config, never from the repository.
- **Standards over invention.** Encryption is age, so values interoperate with `age`, `rage`, and other tools.
- **No dependencies.** Cryptography is `node:crypto`; the terminal UI is plain ANSI. Packages are bundled with tsdown.

## Repository

```text
packages/core      src/crypto (age, bech32, ssh, bcrypt_pbkdf), keys, document, values, status,
                   operations, store, sources, keychain; test vectors and tests
packages/ts-sdk    src/index.ts
packages/ui        src/cli.ts, commands.ts, tui/, git.ts, spawn.ts
scripts            verify-packages.ts: pack, install offline, and exercise the published packages
docs               this site and the JSON schema
```
