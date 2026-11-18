---
layout: default
title: File format
description: The msecrets v6 msecrets.json format.
eyebrow: Compatibility contract
lead: msecrets.json is plain JSON with a published schema. It holds recipients, environments, signed age ciphertext, and plain values you chose to keep readable, and nothing else.
permalink: /file-format/
hero_shell: |-
  {
    "$schema": "https://raw.githubusercontent.com/k18k/msecrets/master/schema/v6.json",
    "version": 6,
    "id": "…",
    "recipients": {},
    "environments": {},
    "secrets": {}
  }
---

## Example

```json
{
  "$schema": "https://raw.githubusercontent.com/k18k/msecrets/master/schema/v6.json",
  "version": 6,
  "id": "6f1c0b4f8c0e4a35a1b7f6e2d9c3a8b0",
  "recipients": {
    "alice": { "key": "msecrets1q…" },
    "api-production": { "key": "age1…", "description": "Production API containers" },
    "dana": { "key": "msecrets1q…", "salt": "+GSxTe9LnQRQk2EMQDFLpQ==" }
  },
  "environments": {
    "development": { "recipients": ["alice", "dana"] },
    "production": { "recipients": ["alice", "api-production"] }
  },
  "secrets": {
    "API_URL": {
      "plain": true,
      "values": {
        "development": { "by": "alice", "sig": "q8Zt…", "value": "http://localhost:8080" },
        "production": { "by": "alice", "sig": "Lr0P…", "value": "https://api.example.com" }
      }
    },
    "DATABASE_URL": {
      "description": "Primary database",
      "values": {
        "development": { "to": "0606e5bc…", "by": "alice", "sig": "WMwc…", "data": "YWdlLWVu…" },
        "production": { "to": "9a41c2d7…", "by": "alice", "sig": "Hk2N…", "data": "YWdlLWVu…" }
      }
    },
    "SENTRY_DSN": { "environments": ["production"], "values": { "production": { "…": "…" } } }
  }
}
```

The [JSON schema](https://raw.githubusercontent.com/k18k/msecrets/master/schema/v6.json), served from this repository, gives editors completion and validation.

## Fields

| Field                                 |                                                                                                                                            |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `version`                             | `6`. msecrets also reads version `4` files and writes them back as version 6.                                                              |
| `id`                                  | Random 128-bit id, bound into every signature so values cannot be copied between files.                                                    |
| `recipients.NAME.key`                 | `msecrets1…` (read and write), `age1…` / `age1pq1…` (read only), or `ssh-ed25519 AAAA…`.                                                   |
| `recipients.NAME.salt`                | Only for password members: the key is derived from the member's password and this salt. The password is not in the file.                   |
| `environments.NAME.recipients`        | Who can read the environment. Recipients with a signing key can also write it. Order of environments is display order.                     |
| `secrets.NAME.environments`           | Optional: the environments the secret applies to. Absent means all.                                                                        |
| `secrets.NAME.plain`                  | Optional, always `true`: a plain secret, for configuration that is not secret. Its values are signed but not encrypted.                    |
| `secrets.NAME.values.ENV.to`          | Digest of the recipient keys the value is encrypted to. When it differs from the environment's current recipients, the value _needs sync_. |
| `secrets.NAME.values.ENV.by` / `.sig` | The signing recipient and its Ed25519 signature.                                                                                           |
| `secrets.NAME.values.ENV.data`        | Base64 of a binary age file, so `age` itself can decrypt it (see below).                                                                   |
| `secrets.NAME.values.ENV.value`       | The text of a plain value (plain secrets only; they have no `to` and `data`).                                                              |

## Padding

The age payload is the value followed by zero bytes, to 64 bytes or the next power of two (128, 256, …), so the
file shows a size range instead of the exact length of each secret. Values never contain NUL, so the first zero
byte ends the value. Payloads without a zero byte are values written by msecrets 5 and earlier; they stay
readable, and are padded the next time they are set. See [what stays public](../security/#what-stays-public).

## Decrypting without msecrets

```bash
jq -r '.secrets.DATABASE_URL.values.production.data' msecrets.json | base64 -d | age -d -i key.txt | tr -d '\0'
```

`tr -d '\0'` removes the padding. Plain values need no key: `jq -r '.secrets.API_URL.values.production.value' msecrets.json`.

## Rules

- Secret names are environment variable names; environment and recipient names are lowercase.
- Unknown fields are rejected, so typos never pass silently.
- msecrets writes the file canonically: sorted names, fixed field order, two-space indentation, final newline.
  Unchanged values are never re-encrypted, so diffs stay minimal.
- Every write is validated and atomic (temporary file and rename). msecrets processes take turns through
  `msecrets.json.lock` (a lock left by a crashed process is cleared automatically), and changes made by anything else
  during a write, such as an editor or git, are detected.

## Versions

| msecrets | Writes | Reads   |
| -------- | ------ | ------- |
| 6        | 6      | 4 and 6 |
| 4 and 5  | 4      | 4       |

The first change a msecrets 6 user makes to a version 4 file turns it into version 6, which msecrets 4 and 5 refuse
to read, so upgrade everyone who uses the file (developers, CI, and deployed apps through the SDK) together.

## Coming from msecrets 3

Version 4 replaces OpenPGP with age and the v2/v3 `.env.ms.json` with `msecrets.json`; there is no automatic
conversion, because the new format adds signatures that only the current value holders can create. Both files can
exist side by side while you migrate:

```bash
# 1. With msecrets 3 (its UI or SDK), collect each environment's values into a dotenv file outside the repository.
# 2. With msecrets 4:
msecrets init --env development,production
msecrets import ~/production.env --env production
msecrets import ~/development.env --env development
msecrets check
# 3. Delete the dotenv files and .env.ms.json.
```
