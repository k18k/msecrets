import { defineConfig } from "tsdown/config";

export default defineConfig({
  exports: {
    bin: {
      msecrets: "./src/index.ts",
    },
  },
  format: ["esm"],
});
