import { getConfigPath } from "#cli/program.ts";
import { listEnvironments } from "@msecrets/core/workflows";
import { Command } from "commander";

export const envListCommand = new Command()
  .command("list")
  .description("List environments")
  .action(() => {
    const secretsPath = getConfigPath();
    const environments = listEnvironments(secretsPath);

    if (!environments.length) {
      console.log("No environments found");
      return;
    }

    console.log("Environments:");
    environments.forEach((environment) => console.log(`- ${environment}`));
  });
