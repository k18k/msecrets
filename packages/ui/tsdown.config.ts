import { type UserConfig, defineConfig } from "tsdown";

const config: UserConfig = defineConfig({
  entry: { bin: "src/bin.ts" },
  format: ["esm"],
  platform: "node",
  dts: false,
  clean: true,
});

export default config;
