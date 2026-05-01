# msecrets (CLI)

CLI for repository-native encrypted secrets.

## Install

```bash
npm install -g msecrets
```

## Core Commands

```bash
msecrets init
msecrets import-key
msecrets key import
msecrets key remove
msecrets env list
msecrets env add
msecrets env rename
msecrets env rm
msecrets secret create
msecrets secret set
msecrets secret rename
msecrets secret delete
msecrets secret share
msecrets secret revoke
msecrets secret peek
msecrets ui
```

## Config Path

Use `--config`:

```bash
msecrets --config secrets.ms.json init
```

## UI Launch

`msecrets ui` launches the prebuilt local UI runtime.

Behavior:
- binds to `127.0.0.1`
- provisions local HTTPS certs in `~/.msecrets/certs`
- fails fast if UI build assets are missing

## Secrets File Version

`init` writes version `2.0.0` and uses the current `2.x.x` contract.
