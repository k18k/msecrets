# @msecrets/ui

Local UI runtime for msecrets.

## Install

```bash
npm install -g @msecrets/ui
```

## Usage

Pass the secrets file as the first positional argument:

```bash
npx @msecrets/ui secrets.ms.json
```

Optional port:

```bash
npx @msecrets/ui secrets.ms.json --port 9842
```

## Security Defaults

- binds to `127.0.0.1`
- serves over local HTTPS
- startup failures are surfaced explicitly

## Local Dev

```bash
npm --workspace @msecrets/ui run build
npm --workspace @msecrets/ui run test:e2e
```
