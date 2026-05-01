import { defineConfig } from "tsdown/config";

export default defineConfig({
  entry: "index.ts",
  exports: {},
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
});
