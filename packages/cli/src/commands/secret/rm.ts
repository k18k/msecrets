import { Command } from "commander";
import inquirer from "inquirer";

import { getSecretNames } from "./shared.ts";
import { getConfigPath } from "#cli/program.ts";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { removeSecretValue } from "@msecrets/core/workflows";

export const secretRmCommand = new Command()
  .command("rm")
  .description("Remove secret value")
  .action(async () => {
    const secretsPath = getConfigPath();
    const file = getSecretsFile(secretsPath);
    const secretNames = getSecretNames(file);

    if (!secretNames.length) {
      console.log("No secrets found");
      return;
    }

    const { name } = await inquirer.prompt({
      type: "search",
      name: "name",
      message: "Secret",
      source: async (input?: string) =>
        secretNames
          .filter((secretName) =>
            !input ? true : secretName.toLowerCase().includes(input.toLowerCase()),
          )
          .map((secretName) => ({
            name: secretName,
            value: secretName,
          })),
    });

    const secret = file.secrets[String(name)];

    if (!secret) {
      console.log(`Missing secret ${String(name)}`);
      return;
    }

    const environments = Object.keys(secret.values).sort((left, right) =>
      left.localeCompare(right),
    );

    if (!environments.length) {
      console.log(`No values found for ${String(name)}`);
      return;
    }

    const { environment } = await inquirer.prompt({
      type: "select",
      name: "environment",
      message: "Environment",
      choices: environments,
    });

    const result = await removeSecretValue(secretsPath, {
      environment: String(environment),
      name: String(name),
    });

    if (result.removedSecret) {
      console.log(`Removed secret ${result.name}`);
      return;
    }

    console.log(`Removed ${result.name}.${result.environment}`);
  });
