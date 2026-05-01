import { getConfigPath } from "#cli/program.ts";
import { addEnvironment } from "@msecrets/core/workflows";
import { Command } from "commander";
import inquirer from "inquirer";

export const envAddCommand = new Command()
  .command("add")
  .description("Add environment")
  .action(async () => {
    const secretsPath = getConfigPath();
    const { environment } = await inquirer.prompt({
      type: "input",
      name: "environment",
      message: "Enter environment name",
    });

    const result = await addEnvironment(secretsPath, String(environment));

    if (!result.added) {
      console.log("Environment already exists");
      return;
    }

    console.log(`Added environment ${result.environment}`);
  });
