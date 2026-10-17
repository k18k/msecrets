---
layout: default
title: Docs
heading: msecrets
description: Encrypted secrets that live in your repository. One committed file, age encryption, signed values, zero dependencies.
eyebrow: Encrypted secrets that live in your repository
lead: Commit one file. Every value is encrypted to the people and machines of its environment and signed by whoever wrote it. No server, no account, nothing to provision.
primary_link: "#quick-start"
primary_label: Quick start
secondary_link: "/cli/"
secondary_label: CLI & terminal UI
hero_shell: |-
  npm install --save-dev @msecrets/ui
  npx msecrets init
  npx msecrets set DATABASE_URL
  npx msecrets run -- npm start
---

<div class="intro-strip">
  <div class="stat">
    <strong>1 file</strong>
    <span><code>msecrets.json</code> is committed with the code it configures.</span>
  </div>
  <div class="stat">
    <strong>age + Ed25519</strong>
    <span>Standard encryption, post-quantum optional, every value signed.</span>
  </div>
  <div class="stat">
    <strong>0 dependencies</strong>
    <span>Pure TypeScript on <code>node:crypto</code>. Linux, macOS, Windows, Node.js 20+.</span>
  </div>
</div>

## Never worry about secrets again

<div class="cards four">
  <article class="card accent">
    <span class="kicker">Complete</span>
    <h3>Every environment has every secret</h3>
    <p><code>msecrets check</code> fails CI when a value is missing, and apps refuse to start with half an environment.</p>
  </article>
  <article class="card blue">
    <span class="kicker">In sync</span>
    <h3>Access changes cannot drift</h3>
    <p>Values encrypted for an outdated set of people show up as <em>needs sync</em> until a member runs <code>msecrets sync</code>.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Trustworthy</span>
    <h3>Tampering is detected</h3>
    <p>Each value is signed by a member of its environment and bound to its slot. Swapped or injected ciphertext is rejected.</p>
  </article>
  <article class="card red">
    <span class="kicker">Reviewable</span>
    <h3>Readable diffs, clean merges</h3>
    <p><code>git diff</code> shows which values changed and who signed them; independent changes merge without conflicts.</p>
  </article>
</div>

## Quick start

{: #quick-start }

```bash
npm install --save-dev @msecrets/ui
npx msecrets init                 # creates msecrets.json and your key (OS keychain when available)
npx msecrets set DATABASE_URL     # prompts for the value
npx msecrets                      # the terminal UI: every secret in every environment
npx msecrets run -- npm start     # your app reads the secrets as environment variables
npx msecrets git setup            # readable diffs and structural merges
git add msecrets.json .gitattributes
```

In TypeScript or JavaScript, import the file and get your secrets as a typed object:

```ts
import { createClient } from "@msecrets/ts-sdk";
import file from "./msecrets.json" with { type: "json" };

const secrets = createClient(file);
secrets.DATABASE_URL; // string, typed from msecrets.json
```

## How the pieces fit

<div class="cards three">
  <article class="card accent">
    <h3>Author</h3>
    <p>The <a href="{{ '/cli/' | relative_url }}">CLI and terminal UI</a> create the file, set values, and manage environments and access.</p>
  </article>
  <article class="card blue">
    <h3>Run</h3>
    <p>The <a href="{{ '/runtime/' | relative_url }}">runtime SDK</a> or <code>msecrets run</code> decrypt the selected environment for your app.</p>
  </article>
  <article class="card gold">
    <h3>Keys</h3>
    <p><a href="{{ '/identities/' | relative_url }}">Private keys</a> stay in your keychain or password manager, and in your CI or container secret store.</p>
  </article>
</div>

<div class="callout">
  <div>
    <h2>Upgrading from msecrets 3?</h2>
    <p>Version 4 uses a new file format and age instead of OpenPGP. Export your values with v3, then run <code>msecrets init</code> and <code>msecrets import</code>. See the <a href="{{ '/file-format/' | relative_url }}">file format</a> page.</p>
  </div>
</div>
