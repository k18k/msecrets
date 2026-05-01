import { defineConfig } from "tsdown/config";

export default defineConfig({
  entry: {
    crypto: "./src/crypto.ts",
    "key-material": "./src/key-material.ts",
    runtime: "./src/runtime.ts",
    "secret-helpers": "./src/secret-helpers.ts",
    "secrets-file": "./src/secrets-file.ts",
    providers: "./src/providers/index.ts",
    types: "./src/types.ts",
    validation: "./src/validation.ts",
    workflows: "./src/workflows.ts",
  },
  exports: {},
  format: ["cjs", "esm"],
  dts: true,
  deps: { onlyBundle: ["zod", "openpgp"] },
});
