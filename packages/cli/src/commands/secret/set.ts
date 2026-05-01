import { Command } from "commander";
import inquirer from "inquirer";

import { promptSecretValueInput } from "./prompt-encrypted-value.ts";
import { getSecretNames } from "./shared.ts";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { getConfigPath } from "#cli/program.ts";
import { setSecretValue } from "@msecrets/core/workflows";

export const secretSetCommand = new Command()
  .command("set")
  .description("Set encrypted secret value")
  .action(async () => {
    const secretsPath = getConfigPath();
    const file = getSecretsFile(secretsPath);
    const secretNames = getSecretNames(file);

    if (!secretNames.length) {
      console.log("No secrets found");
      return;
    }

    const { name, environment } = await inquirer.prompt([
      {
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
      },
      {
        type: "select",
        name: "environment",
        message: "Environment",
        choices: file.environments,
      },
    ]);
    const { fingerprint, plaintextValue } = await promptSecretValueInput(file);

    const result = await setSecretValue(secretsPath, {
      environment: String(environment),
      fingerprint,
      name: String(name),
      plaintextValue,
    });

    console.log(`Updated ${result.name}.${result.environment}`);
  });
