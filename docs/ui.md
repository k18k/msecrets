---
layout: default
title: UI
description: Local browser UI for managing msecrets workspaces.
eyebrow: Local authoring dashboard
lead: The msecrets UI is a local browser dashboard for inspecting and editing the portable msecrets file.
permalink: /ui/
hero_shell: |-
  npx @msecrets/ui
---

## What the UI is

The UI is an authoring interface for the repository secrets file. It launches a small local server, opens a browser dashboard, and reads or writes the selected `.env.ms.json` or `secrets.ms.json` file on your machine.

It does not replace the runtime SDK. Applications should still consume secrets through `@msecrets/ts-sdk` and stateless adapters.

<div class="cards three">
  <article class="card accent">
    <span class="kicker">Local-first</span>
    <h3>Bound to loopback</h3>
    <p>The production UI server binds to <code>127.0.0.1</code> and serves the dashboard over local HTTPS with a throwaway certificate.</p>
  </article>
  <article class="card blue">
    <span class="kicker">File-native</span>
    <h3>Same portable contract</h3>
    <p>All durable changes are edits to the portable msecrets file: environments, public keys, secrets, encrypted values, and owners.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Runtime-aware</span>
    <h3>Private keys stay temporary</h3>
    <p>Runtime private keys are loaded into the local UI process only for peek/decrypt flows and are not written into the workspace file.</p>
  </article>
</div>

## Start the dashboard

From a project that already uses msecrets, launch the UI against the default file:

```bash
npx @msecrets/ui .env.ms.json
```

Or point it at a specific file:

```bash
npx @msecrets/ui secrets.ms.json
```

The standalone UI package accepts the workspace file as the first positional argument:

```bash
npx @msecrets/ui .env.ms.json --port 9842
```

If no file is provided, the UI defaults to `.env.ms.json`.

> Your browser may show a certificate warning. The local certificate is generated at startup for loopback HTTPS and is not intended to establish public trust.

## Screenshots

<figure class="screenshot-frame">
  <img src="{{ '/assets/img/ui/overview.svg' | relative_url }}" alt="msecrets UI overview page with workspace health, quick actions, and the secret environment matrix" />
  <figcaption>Overview summarizes file health, common actions, counts, and the per-environment secret matrix.</figcaption>
</figure>

<figure class="screenshot-frame">
  <img src="{{ '/assets/img/ui/secrets.svg' | relative_url }}" alt="msecrets UI secrets page with search, value status, owners, and actions" />
  <figcaption>Secrets are managed as rows with per-environment value status, owner fingerprints, and actions such as set, peek, share, revoke, rename, or delete.</figcaption>
</figure>

<figure class="screenshot-frame">
  <img src="{{ '/assets/img/ui/keys.svg' | relative_url }}" alt="msecrets UI recipient keys page and runtime private key workflow" />
  <figcaption>Recipient public keys are committed OpenPGP key material. Runtime private keys are temporary local inputs for decrypt/peek operations.</figcaption>
</figure>

## Main areas

<div class="cards two">
  <article class="card">
    <h3>Overview</h3>
    <p>Shows workspace health, quick actions, summary counts, actionable diagnostics, and the secret-environment matrix.</p>
  </article>
  <article class="card">
    <h3>Secrets</h3>
    <p>Create, rename, delete, search, and inspect secrets. Set encrypted values per environment and manage sharing or revocation for configured recipients.</p>
  </article>
  <article class="card">
    <h3>Environments</h3>
    <p>Add, rename, and remove environment names. Values remain independent per environment because each secret value is encrypted separately.</p>
  </article>
  <article class="card">
    <h3>Recipient Keys</h3>
    <p>Import and inspect committed OpenPGP public keys, then review which secrets and encrypted values depend on each recipient.</p>
  </article>
  <article class="card">
    <h3>Runtime Keys</h3>
    <p>Import temporary private key material so the local UI process can decrypt values for peek flows. These keys are process memory only.</p>
  </article>
  <article class="card">
    <h3>Raw JSON and Diagnostics</h3>
    <p>Review the underlying file structure and validation findings without leaving the dashboard.</p>
  </article>
</div>

## How edits flow

1. The browser calls the local UI server.
2. The server delegates file validation and workflow changes to `@msecrets/core`.
3. Core updates the selected msecrets file on disk.
4. You review and commit the encrypted file change through normal Git workflow.

The UI should stay an authoring layer. Business rules, validation, encryption, sharing, revocation, and file-format compatibility belong in core.

## Security model

- The UI is for local authoring and inspection, not for hosting as a shared web app.
- The server binds to `127.0.0.1`, not your LAN interface.
- The local HTTPS certificate is throwaway and may trigger a browser warning.
- Public keys are durable because they are part of the committed access contract.
- Private keys imported for runtime/peek workflows are temporary and kept out of `.env.ms.json`.
- Decrypted plaintext is only shown when matching runtime private key material is available.

## When to use the UI

Use the UI when you want a visual overview of environments, recipient keys, ownership, diagnostics, and value coverage before committing a file change.

Use the SDK in application code; do not shell out to the UI or depend on a local browser dashboard at runtime.
