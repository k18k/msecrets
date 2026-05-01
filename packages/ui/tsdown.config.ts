import { defineConfig } from "tsdown/config";

export default defineConfig({
  entry: "./server/start.ts",
  exports: {
    bin: {
      "@msecrets/ui": "./server/start.ts",
    },
  },
  format: ["esm"],
});
