---
layout: default
title: File format
description: The msecrets .env.ms.json compatibility contract.
eyebrow: Compatibility contract
lead: The committed .env.ms.json file is the portable source of truth for recipients, environments, and encrypted values.
permalink: /file-format/
hero_shell: |-
  {
    "version": "2.0.0",
    "environments": ["production"],
    "keys": [],
    "secrets": {}
  }
---

## Current version

The current format major is `2.x.x`.

Core validates semver and hard-fails on incompatible major versions. Compatible v2 files should remain readable across v2 releases.

## Contract rules

<div class="cards two">
  <article class="card accent">
    <h3>Portable</h3>
    <p>The file must not depend on local environment state, local keyrings, or runtime-only data.</p>
  </article>
  <article class="card blue">
    <h3>Explicit</h3>
    <p>Recipients define access. There is no hidden policy engine or central authority.</p>
  </article>
  <article class="card gold">
    <h3>Per-secret encryption</h3>
    <p>Each secret value is encrypted independently for the recipients that should have access.</p>
  </article>
  <article class="card red">
    <h3>Tool-independent</h3>
    <p>Stored public keys and encrypted messages are OpenPGP artifacts, not local GPG state.</p>
  </article>
</div>

## Revocation model

msecrets has no retroactive revocation. Removing or revoking access affects future encrypted values and file transformations; it cannot make already copied plaintext or ciphertext disappear.

## What not to store

- Private keys.
- Machine-specific runtime configuration.
- External KMS references required to understand the file.
- Unencrypted secret values.
