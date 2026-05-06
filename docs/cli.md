---
layout: default
title: CLI
description: CLI authoring workflow for msecrets.
eyebrow: Authoring interface
lead: The msecrets CLI manages the committed secrets file. It stays thin and delegates file validation, encryption, and workflow logic to core.
permalink: /cli/
hero_shell: |-
  msecrets --config .env.ms.json init
  msecrets env add production
  msecrets secret create STRIPE_SECRET_KEY
  msecrets secret set STRIPE_SECRET_KEY production
---

## Install

```bash
npm install -g msecrets
```

## Authoring workflow

```bash
msecrets init
msecrets import-key
msecrets env add production
msecrets secret create DB_PASSWORD
msecrets secret set DB_PASSWORD production
msecrets secret share DB_PASSWORD
```

Use `--config` when the secrets file is not the default `.env.ms.json`.

```bash
msecrets --config secrets.ms.json init
```

<div class="cards three">
  <article class="card accent">
    <span class="kicker">Initialize</span>
    <h3>Create the contract</h3>
    <p><code>msecrets init</code> creates the repository secrets file and records the supported v2 format.</p>
  </article>
  <article class="card blue">
    <span class="kicker">Encrypt</span>
    <h3>Add values per environment</h3>
    <p>Secrets are set independently for each environment, so production and development values do not share ciphertext.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Review</span>
    <h3>Commit the file change</h3>
    <p>The encrypted file can move through normal Git review without exposing plaintext.</p>
  </article>
</div>

## Commands

<div class="cards two">
  <article class="card">
    <h3>Setup</h3>
    <ul>
      <li><code>msecrets init</code></li>
      <li><code>msecrets import-key</code></li>
      <li><code>msecrets key import</code></li>
      <li><code>msecrets key remove</code></li>
    </ul>
  </article>
  <article class="card">
    <h3>Environments</h3>
    <ul>
      <li><code>msecrets env list</code></li>
      <li><code>msecrets env add</code></li>
      <li><code>msecrets env rename</code></li>
      <li><code>msecrets env rm</code></li>
    </ul>
  </article>
  <article class="card">
    <h3>Secrets</h3>
    <ul>
      <li><code>msecrets secret create</code></li>
      <li><code>msecrets secret set</code></li>
      <li><code>msecrets secret rename</code></li>
      <li><code>msecrets secret delete</code></li>
    </ul>
  </article>
  <article class="card">
    <h3>Access and inspection</h3>
    <ul>
      <li><code>msecrets secret share</code></li>
      <li><code>msecrets secret revoke</code></li>
      <li><code>msecrets secret peek</code></li>
      <li><code>msecrets ui</code></li>
    </ul>
  </article>
</div>

## GPG boundary

> GPG support exists for local key discovery and convenience. Repository state is based on portable OpenPGP key material and encrypted messages, not on a local GPG keyring.
