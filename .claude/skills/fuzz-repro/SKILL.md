---
name: fuzz-repro
description: Reproduce a failing age-fuzz or adversarial test from its printed seed and turn it into a regression test
disable-model-invocation: true
argument-hint: <seed> [case-index]
---

Reproduce and fix the fuzz failure for seed `$ARGUMENTS`.

1. Rerun only the failing suite with the seed. The reference `age` binary must be available
   (`MSECRETS_AGE_BIN`, `MSECRETS_AGE_KEYGEN_BIN`), otherwise say so and stop:

   ```sh
   MSECRETS_FUZZ_SEED=<seed> mise exec node@26 -- node --test --test-timeout=600000 packages/core/test/age-fuzz.test.ts
   ```

   For `adversarial.test.ts`, run that file instead. If it passes, raise `MSECRETS_FUZZ_CASES` (e.g. 5000).

2. The failure message names the case index, the mutations applied, both verdicts, and the saved file
   (`msecrets-fuzz-failure-*/<seed>-<index>.age` in the temp dir). Read the file and find where our parser and
   the reference disagree.

3. Fix the root cause in `packages/core/src/crypto`. Parsers stay strict: when in doubt, match the reference `age`
   (do not change the age wire format).

4. Add a regression test with the minimized input as a fixed case (not dependent on the seed) next to the existing
   ones in `packages/core/test/adversarial.test.ts` or `age-interop.test.ts`.

5. Run `mise exec node@26 -- npm test`, and the C2SP vectors (`age-vectors.test.ts`) must still pass.
