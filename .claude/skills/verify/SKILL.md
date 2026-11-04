---
name: verify
description: Run the full verify pipeline (format, lint, typecheck, build, tests, dist tests, packed install) and report only what failed
disable-model-invocation: true
context: fork
---

Run from the repository root:

```sh
mise exec node@26 -- npm run verify
```

The stages run in order and stop at the first failure. Report:

- the stage that failed (format:check, lint, typecheck, build, test, test:dist, verify:packages)
- the failing files and tests, with the relevant error lines only
- the likely cause in one line each

If everything passes, say so in one line. Do not fix anything.
