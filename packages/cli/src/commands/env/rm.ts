import { getConfigPath } from "#cli/program.ts";
import { listEnvironments, removeEnvironment } from "@msecrets/core/workflows";
import { Command } from "commander";
import inquirer from "inquirer";

export const envRmCommand = new Command()
  .command("rm")
  .description("Remove environment")
  .action(async () => {
    const secretsPath = getConfigPath();
    const environments = listEnvironments(secretsPath);

    if (!environments.length) {
      console.log("No environments to remove");
      return;
    }

    const { environment } = await inquirer.prompt({
      type: "select",
      name: "environment",
      message: "Select environment to remove",
      choices: environments,
    });

    const result = await removeEnvironment(secretsPath, String(environment));

    if (!result.removed) {
      console.log(`Environment ${result.environment} was already missing`);
      return;
    }

    if (result.removedValues) {
      console.log(
        `Removed environment ${result.environment} and cleaned up ${result.removedValues} value${result.removedValues === 1 ? "" : "s"}`,
      );
      return;
    }

    console.log(`Removed environment ${result.environment}`);
  });
