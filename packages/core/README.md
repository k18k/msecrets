# @msecrets/core

Core workflows and contracts for msecrets.

## Scope

- OpenPGP-native encryption/decryption primitives
- secrets file read/write helpers
- schema validation and compatibility checks
- workflow operations for keys/environments/secrets
- runtime adapter contracts
- internal runtime adapter implementations exported publicly through `@msecrets/ts-sdk/adapters/*`

## Secrets File Compatibility

Current file version baseline:

```text
2.0.0
```

Supported major range:

```text
2.x.x
```

Validation throws a dedicated version compatibility error on major mismatch.

## Build

```bash
npm --workspace @msecrets/core run build
```

## Notes

Business logic belongs here. CLI/UI/SDK should remain thin wrappers over core workflows.
