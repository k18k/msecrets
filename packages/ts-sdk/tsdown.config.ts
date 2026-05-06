import { defineConfig } from "tsdown/config";

export default defineConfig({
  entry: {
    index: "index.ts",
    "adapters/docker-secrets": "adapters/docker-secrets.ts",
    "adapters/gpg": "adapters/gpg.ts",
    "adapters/raw-pks": "adapters/raw-pks.ts",
  },
  exports: {},
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  deps: { onlyBundle: ["openpgp", "zod"] },
});
