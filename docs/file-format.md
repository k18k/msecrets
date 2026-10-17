---
layout: default
title: File format
description: The msecrets v4 .env.ms.json format.
eyebrow: Compatibility contract
lead: .env.ms.json is plain JSON with a published schema. It holds recipients, environments, and signed age ciphertext, and nothing else.
permalink: /file-format/
hero_shell: |-
  {
    "$schema": "https://cdn.jsdelivr.net/npm/@msecrets/ts-sdk@4/schema/v4.json",
    "version": 4,
    "id": "…",
    "recipients": {},
    "environments": {},
    "secrets": {}
  }
---

## Example

```json
{
  "$schema": "https://cdn.jsdelivr.net/npm/@msecrets/ts-sdk@4/schema/v4.json",
  "version": 4,
  "id": "6f1c0b4f8c0e4a35a1b7f6e2d9c3a8b0",
  "recipients": {
    "alice": { "key": "msecrets1q…" },
    "api-production": { "key": "age1…", "description": "Production API containers" }
  },
  "environments": {
    "development": { "recipients": ["alice"] },
    "production": { "recipients": ["alice", "api-production"] }
  },
  "secrets": {
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

The [JSON schema](https://cdn.jsdelivr.net/npm/@msecrets/ts-sdk@4/schema/v4.json), published with `@msecrets/ts-sdk`, gives editors completion and validation.

## Fields

| Field                                 |                                                                                                                                            |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `version`                             | Always `4`.                                                                                                                                |
| `id`                                  | Random 128-bit id, bound into every signature so values cannot be copied between files.                                                    |
| `recipients.NAME.key`                 | `msecrets1…` (read and write), `age1…` / `age1pq1…` (read only), or `ssh-ed25519 AAAA…`.                                                   |
| `environments.NAME.recipients`        | Who can read the environment. Recipients with a signing key can also write it. Order of environments is display order.                     |
| `secrets.NAME.environments`           | Optional: the environments the secret applies to. Absent means all.                                                                        |
| `secrets.NAME.values.ENV.to`          | Digest of the recipient keys the value is encrypted to. When it differs from the environment's current recipients, the value _needs sync_. |
| `secrets.NAME.values.ENV.by` / `.sig` | The signing recipient and its Ed25519 signature.                                                                                           |
| `secrets.NAME.values.ENV.data`        | Base64 of a binary age file; `base64 -d \| age -d -i key.txt` decrypts it.                                                                 |

## Rules

- Secret names are environment variable names; environment and recipient names are lowercase.
- Unknown fields are rejected, so typos never pass silently.
- msecrets writes the file canonically: sorted names, fixed field order, two-space indentation, final newline.
  Unchanged values are never re-encrypted, so diffs stay minimal.
- Every write is validated, atomic (temporary file and rename), and detects concurrent modification.

## Coming from msecrets 3

Version 4 replaces OpenPGP with age and the v2/v3 file layout with this one; there is no automatic conversion,
because the new format adds signatures that only the current value holders can create. To migrate:

```bash
# 1. With msecrets 3 (its UI or SDK), collect each environment's values into a dotenv file outside the repository.
# 2. With msecrets 4:
mv .env.ms.json .env.ms.v3.json
npx msecrets init --env development,production
npx msecrets import ~/production.env --env production
npx msecrets import ~/development.env --env development
npx msecrets check
# 3. Delete the dotenv files and the v3 file.
```
