---
layout: default
title: Docs
heading: msecrets
description: Documentation for msecrets, a repository-native encrypted secrets system.
eyebrow: Repository-native encrypted configuration
lead: Commit one portable secrets file, encrypt each value for explicit OpenPGP recipients, and decrypt at runtime through SDK adapters.
primary_link: "#quick-start"
primary_label: Quick start
secondary_link: "/runtime/"
secondary_label: Runtime SDK
hero_shell: |-
  npm install -g msecrets
  msecrets init
  msecrets import-key
  msecrets secret set DB_PASSWORD production
---

<div class="intro-strip">
  <div class="stat">
    <strong>1 file</strong>
    <span>Commit <code>.env.ms.json</code> with the code it configures.</span>
  </div>
  <div class="stat">
    <strong>OpenPGP</strong>
    <span>Portable keys and messages, not a local keyring contract.</span>
  </div>
  <div class="stat">
    <strong>Runtime SDK</strong>
    <span>Decrypt through stateless adapters in production code.</span>
  </div>
</div>

## Why teams use it

<div class="cards four">
  <article class="card accent">
    <span class="kicker">Portable</span>
    <h3>No mandatory secrets server</h3>
    <p>Secrets move with the repository as encrypted OpenPGP messages, so development and deployment do not start with provisioning a central service.</p>
  </article>
  <article class="card blue">
    <span class="kicker">Explicit</span>
    <h3>Recipients are visible</h3>
    <p>Access is encoded directly in the file. There is no hidden policy layer and no ambient local machine state.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Repository-first</span>
    <h3>Works with code review</h3>
    <p>Environment changes are file changes. Teams can review when a secret is added, renamed, shared, or revoked.</p>
  </article>
  <article class="card red">
    <span class="kicker">Small surface</span>
    <h3>Thin CLI, real SDK</h3>
    <p>The CLI authors secrets; applications consume them through the SDK and adapters instead of shelling out to tools at runtime.</p>
  </article>
</div>

## Quick start

{: #quick-start }

Install the authoring CLI and initialize a repository secrets file.

```bash
npm install -g msecrets
msecrets init
msecrets import-key
msecrets env add production
msecrets secret create DB_PASSWORD
msecrets secret set DB_PASSWORD production
```

The result is an encrypted `.env.ms.json` file suitable for committing to Git.

## How the pieces fit

<div class="cards two">
  <article class="card accent">
    <h3>Authoring</h3>
    <p>Use the <a href="{{ '/cli/' | relative_url }}">CLI</a> or <a href="{{ '/ui/' | relative_url }}">local UI</a> to manage environments, recipient public keys, and encrypted values. Core workflows keep file changes deterministic.</p>
  </article>
  <article class="card blue">
    <h3>Runtime</h3>
    <p>Use the <a href="{{ '/runtime/' | relative_url }}">SDK and adapters</a> inside applications. Adapters provide private key access and return plaintext only.</p>
  </article>
</div>

<div class="callout">
  <div>
    <h2>Built for developers who want fewer moving parts.</h2>
    <p>msecrets is deliberately not a KMS, policy engine, or hosted secrets platform. It is a compact OpenPGP-based workflow for encrypted configuration in Git.</p>
  </div>
  <a class="button secondary" href="https://github.com/k18k/msecrets">Star or sponsor</a>
</div>

## Read next

<div class="cards">
  <article class="card">
    <h3><a href="{{ '/ui/' | relative_url }}">UI</a></h3>
    <p>Use the local browser dashboard to inspect and edit a workspace file.</p>
  </article>
  <article class="card">
    <h3><a href="{{ '/file-format/' | relative_url }}">File format</a></h3>
    <p>Understand the portable <code>.env.ms.json</code> contract.</p>
  </article>
  <article class="card">
    <h3><a href="{{ '/architecture/' | relative_url }}">Architecture</a></h3>
    <p>See how core, CLI, SDK, adapters, and UI fit together.</p>
  </article>
</div>
