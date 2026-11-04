---
layout: default
title: Architecture
description: Package boundaries and architecture of msecrets.
eyebrow: Monorepo
lead: One Go core with all logic, shipped as a native binary for the CLI and as WebAssembly for the SDK. Neither published package has npm dependencies.
permalink: /architecture/
hero_shell: |-
  msecrets          CLI + TUI  ─┐ native, 6 platforms
                                ├─ internal/core ─ filippo.io/age
  @msecrets/ts-sdk  runtime    ─┘ js/wasm
---

## Packages

<div class="cards three">
  <article class="card accent">
    <h3><code>internal/core</code></h3>
    <p>Go. Keys and age on <code>filippo.io/age</code> and <code>golang.org/x/crypto</code>, the file format and validation, operations, status, file storage, identity sources, and the OS keychain. All I/O goes through a <code>Host</code> interface.</p>
  </article>
  <article class="card blue">
    <h3><code>@msecrets/ts-sdk</code></h3>
    <p>Runtime: <code>createClient</code> turns an imported secrets file into typed values; <code>injectEnv</code> fills <code>process.env</code>. The core as WebAssembly, on Node.js synchronous APIs. ESM, CommonJS, and type declarations.</p>
  </article>
  <article class="card gold">
    <h3><code>msecrets</code></h3>
    <p>The binary: commands (cobra), the terminal UI (bubbletea), <code>run</code>, and git integration. A thin layer over core, installed by <code>@msecrets/cli</code> from a per-platform git branch.</p>
  </article>
</div>

## Principles

- **Core is the source of truth.** The CLI, the terminal UI, and the SDK only call core operations.
- **Operations are transactions.** Each one runs on a copy of the document; the result is validated before an atomic
  write, and nothing is written when anything fails.
- **The file is the contract.** Everything durable is in `msecrets.json`. Keys and identity sources come from the
  caller, the environment, or the user's own config, never from the repository.
- **Standards over invention.** Encryption is age (the reference Go implementation), so values interoperate with
  `age`, `rage`, and other tools.
- **No npm dependencies.** The published packages are a static binary and a WebAssembly module.

## Repository

```text
internal/core      keys, age, ssh, document, values, status, operations, store, sources, keychain; tests,
                   C2SP vectors, a file written by the TypeScript implementation
internal/cli       commands, git integration, run       cmd/msecrets   main
internal/tui       the terminal UI                      internal/termui  colors, symbols, sanitizing
sdk                wasm/ (Go host on Node.js), js/ (the package), test/
npm/cli            the Node.js shim that runs the platform binary
schema             the JSON schema
scripts            build-dist.sh, publish-branches.sh (git branches), test-install.sh (npm install from them)
docs               this site
```
