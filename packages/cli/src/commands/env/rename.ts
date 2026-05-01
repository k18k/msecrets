import { getConfigPath } from "#cli/program.ts";
import { listEnvironments, renameEnvironment } from "@msecrets/core/workflows";
import { Command } from "commander";
import inquirer from "inquirer";

export const envRenameCommand = new Command()
  .command("rename")
  .description("Rename environment")
  .action(async () => {
    const secretsPath = getConfigPath();
    const environments = listEnvironments(secretsPath);

    if (!environments.length) {
      console.log("No environments to rename");
      return;
    }

    const { environment } = await inquirer.prompt({
      type: "select",
      name: "environment",
      message: "Select environment to rename",
      choices: environments,
    });

    const currentEnvironment = String(environment);

    const { nextEnvironment } = await inquirer.prompt({
      type: "input",
      name: "nextEnvironment",
      message: "New environment name",
      default: currentEnvironment,
      validate: (value: string) => {
        const normalizedValue = value.trim();

        if (!normalizedValue) {
          return "New environment name is required";
        }

        if (normalizedValue !== currentEnvironment && environments.includes(normalizedValue)) {
          return "Environment already exists";
        }

        return true;
      },
    });

    const result = await renameEnvironment(secretsPath, {
      environment: currentEnvironment,
      nextEnvironment: String(nextEnvironment),
    });

    if (!result.renamed) {
      console.log(`Environment is already named ${result.nextEnvironment}`);
      return;
    }

    console.log(`Renamed environment ${result.environment} to ${result.nextEnvironment}`);
  });
