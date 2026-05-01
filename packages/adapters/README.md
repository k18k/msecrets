# @msecrets/adapters

Runtime decryption adapters for msecrets.

## Install

```bash
npm install @msecrets/adapters
```

## Included Adapters

- `@msecrets/adapters/raw-pks`
- `@msecrets/adapters/gpg`
- `@msecrets/adapters/docker-secrets`

## Recommended Runtime Path

Prefer `raw-pks` for OpenPGP-native runtime decryption without local GPG coupling.

## Build

```bash
npm --workspace @msecrets/adapters run build
```
