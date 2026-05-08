---
layout: default
title: Architecture
description: Package boundaries and architecture for msecrets.
eyebrow: Monorepo boundaries
lead: msecrets separates authoring, core workflows, runtime decryption, and local inspection so the committed file remains portable.
permalink: /architecture/
hero_shell: |-
  UI  ->  @msecrets/core  ->  .env.ms.json
                 |
  app  ->  @msecrets/ts-sdk  ->  adapters  ->  plaintext
---

## System shape

<div class="intro-strip">
  <div class="stat">
    <strong>Core owns logic</strong>
    <span>Validation, workflows, crypto, and file compatibility live in one place.</span>
  </div>
  <div class="stat">
    <strong>UI authors</strong>
    <span>Interactive local editing produces deterministic file changes.</span>
  </div>
  <div class="stat">
    <strong>SDK runs</strong>
    <span>Applications decrypt through stateless runtime adapters.</span>
  </div>
</div>

## Packages

<div class="cards">
  <article class="card accent">
    <h3><code>@msecrets/core</code></h3>
    <p>File format, validation, OpenPGP crypto, workflows, and shared runtime contracts. Core is the source of truth.</p>
  </article>
  <article class="card gold">
    <h3><code>@msecrets/ts-sdk</code></h3>
    <p>Runtime TypeScript client that validates the secrets file and asks adapters to decrypt values.</p>
  </article>
  <article class="card red">
    <h3><code>@msecrets/ts-sdk/adapters/*</code></h3>
    <p>Public stateless providers for private key access, bundled from core and exported by the SDK.</p>
  </article>
  <article class="card">
    <h3><code>@msecrets/ui</code></h3>
    <p>Local dashboard for managing a selected secrets file on the developer machine.</p>
  </article>
</div>

## Data flow

1. The UI imports recipient public keys and writes encrypted values.
2. The repository commits the portable `.env.ms.json` file.
3. An application loads that file with `@msecrets/ts-sdk`.
4. Runtime adapters provide private key access and return plaintext values.

## Design boundaries

- Business logic belongs in core.
- The UI is an authoring surface, not a runtime dependency.
- The SDK and adapters are the runtime path.
- GPG is convenience-only; OpenPGP is the portable system.
