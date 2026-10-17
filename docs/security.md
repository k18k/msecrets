---
layout: default
title: Security
description: The msecrets security model, guarantees, and limits.
eyebrow: Threat model
lead: msecrets protects secret values at rest in your repository and makes every change to them attributable and reviewable.
permalink: /security/
---

## Cryptography

- **Encryption:** every value is an independent [age v1](https://c2sp.org/age) file encrypted to the recipients
  of its environment: X25519, or ML-KEM-768 + X25519 (X-Wing) for post-quantum keys, with ChaCha20-Poly1305 and
  HKDF-SHA-256. The implementation passes the complete [C2SP age test vector suite](https://github.com/C2SP/CCTV/tree/main/age)
  and is tested for interoperability with the reference `age` implementation.
- **Signatures:** every value is signed with Ed25519 by a recipient of its environment. The signature covers the
  file id, the secret name, the environment, the digest of the recipient keys, and the ciphertext.
- **Primitives:** all cryptography comes from Node.js `node:crypto` (OpenSSL). msecrets has no dependencies.

## What is protected

<div class="cards two">
  <article class="card accent">
    <h3>Confidentiality</h3>
    <p>Only the private keys of an environment's recipients decrypt its values. The repository, its forks, CI logs of <code>check</code>, and anyone with read access see only ciphertext.</p>
  </article>
  <article class="card blue">
    <h3>Integrity</h3>
    <p>Readers verify signatures before decrypting. A value that was edited, moved to another secret, environment, or file, or written by someone outside the environment is rejected.</p>
  </article>
  <article class="card gold">
    <h3>Least privilege</h3>
    <p>Access is per environment. Machine keys are read-only. Revocation re-encrypts every affected value or fails, so it can never silently leave access behind.</p>
  </article>
  <article class="card red">
    <h3>No hidden state</h3>
    <p>Who can read what is written in the file and visible in diffs. Keys and identity sources never come from the repository.</p>
  </article>
</div>

## What you must still do

- **Review changes to recipients and access.** Anyone who can push can add their own key to an environment's
  recipients in the file. That change is plain text in the pull request (`git diff` shows it after
  `msecrets git setup`); require review for `.env.ms.json`, for example with CODEOWNERS.
- **Rotate after revoking.** Encryption cannot take back what someone already copied, and old ciphertext stays in
  git history. `msecrets revoke` lists every value the person could read.
- **Protect machine keys** like any credential: one per deployment target, stored in the platform's secret store.
- **Rollback is possible.** Restoring an older, validly signed value from git history passes verification. Treat a
  value change in a pull request as a change, even when it is signed.

## Reporting a vulnerability

Please report security issues privately through
[GitHub security advisories](https://github.com/k18k/msecrets/security/advisories/new).
