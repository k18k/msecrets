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

## Safe to review

The file is plain text, and so is everything msecrets prints from it. Descriptions cannot contain control
characters, error messages escape names, and revealed values are sanitized in the terminal UI, so a pull request
cannot hide lines from reviewers or write to their clipboard with terminal escape sequences.

## Hostile pull requests

Treat the whole `msecrets.json` of a pull request as attacker-controlled, including who may read and sign. The
file cannot prove who a recipient really is; trust starts with the reviewed version on your default branch. Each
row is a [regression test](https://github.com/k18k/msecrets/blob/master/packages/ui/test/hostile-changes.test.ts):

| The pull request…                                   | Signatures and encryption                                                                                   | `git diff` shows                                   |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| adds its author as a recipient                      | Reveal nothing; values become _needs sync_ and `msecrets check` fails. A member's `sync` would grant access. | the new recipient and the changed access list      |
| replaces a member's key with its own                | Every value that member signed becomes invalid. New values signed with the replaced key verify.            | the member's key fingerprint changing              |
| restores an older signed value                      | The old value verifies (rollback).                                                                          | the value's signature line changing                |
| moves or edits values, or claims another signer     | Rejected: the value is invalid and never decrypted.                                                         | the changed values                                 |
| writes with a read-only machine key                 | Impossible: machine keys cannot sign.                                                                       | nothing to review                                  |

So review every change to recipients, access, and values, and never run `msecrets sync` or `grant` on a pull
request you have not reviewed.

## Hostile input

Parsers reject everything that is not canonical, and input is bounded: an age header has at most 1024 stanzas and
1 MiB, an environment at most 1024 recipients, and a secrets file at most 64 MiB. Signatures are checked before any
value is decrypted, so a forged ciphertext never reaches the age parser.

- **Differential fuzzing:** every CI run generates valid age files (every recipient type, unknown stanzas, chunk
  boundaries, armor) and mutations of them, and checks that msecrets accepts and rejects exactly what the
  reference `age` does, with the same plaintext. A weekly run covers 20,000 cases per platform with a fresh seed.
- **Properties on every platform:** every single-bit flip and truncation of a file is rejected, mutations never
  yield other plaintext, random input only ever fails with a clean error, base64 accepts exactly the canonical
  encodings, a single changed character in a key is rejected, and edited secrets files never reveal a value they
  do not authenticate.
- The complete [C2SP age test vectors](https://github.com/C2SP/CCTV/tree/main/age) and round-trips with `age` in
  both directions.

These are tests, not an audit: the implementation has not had an independent security review yet.

## What you must still do

- **Review changes to recipients and access.** Anyone who can push can add their own key to an environment's
  recipients in the file. That change is plain text in the pull request (`git diff` shows it after
  `msecrets git setup`); require review for `msecrets.json`, for example with CODEOWNERS.
- **Rotate after revoking.** Encryption cannot take back what someone already copied, and old ciphertext stays in
  git history. `msecrets revoke` lists every value the person could read.
- **Protect machine keys** like any credential: one per deployment target, stored in the platform's secret store.
- **Rollback is possible.** Restoring an older, validly signed value from git history passes verification. Treat a
  value change in a pull request as a change, even when it is signed.

## Reporting a vulnerability

Please report security issues privately through
[GitHub security advisories](https://github.com/k18k/msecrets/security/advisories/new).
