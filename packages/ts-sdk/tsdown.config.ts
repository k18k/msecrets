import { type UserConfig, defineConfig } from "tsdown";

const config: UserConfig = defineConfig({
  entry: { index: "src/index.ts", register: "src/register.ts" },
  format: ["esm", "cjs"],
  platform: "node",
  dts: true,
  clean: true,
});

export default config;
