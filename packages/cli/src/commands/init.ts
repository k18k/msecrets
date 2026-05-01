import { initializeSecretsFile } from "@msecrets/core/workflows";
import { getConfigPath } from "../program.ts";

export async function runInitCommand() {
  const configPath = getConfigPath();
  const result = initializeSecretsFile(configPath);

  if (!result.created) {
    console.log(`${configPath} already exists`);
    return;
  }

  console.log(`Initialized ${configPath}`);
}
