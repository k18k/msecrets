import { defineConfig } from "tsdown/config";

export default defineConfig({
  entry: {
    "docker-secrets": "./src/docker-secrets.ts",
    gpg: "./src/gpg.ts",
    "raw-pks": "./src/raw-pks.ts",
  },
  exports: {},
  format: ["cjs", "esm"],
  dts: true,
  deps: { skipNodeModulesBundle: true },
});
