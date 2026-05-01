import { getProdRuntimeOptions } from "./runtime-options.server.ts";

export function getConfigPath(): string {
  return getProdRuntimeOptions().configPath;
}
