import { Command } from "commander";
import inquirer from "inquirer";

import { promptSecretValueInput } from "./prompt-encrypted-value.ts";
import { getConfigPath } from "#cli/program.ts";
import { createSecret } from "@msecrets/core/workflows";
import { getSecretsFile } from "@msecrets/core/secrets-file";

export const secretCreateCommand = new Command()
  .command("create")
  .description("Create secret")
  .action(async () => {
    const secretsPath = getConfigPath();
    const file = getSecretsFile(secretsPath);
    const { name, description, shouldSetValue } = await inquirer.prompt([
      {
        type: "input",
        name: "name",
        message: "Secret name",
        validate: (value: string) => {
          if (!value.trim()) {
            return "Secret name is required";
          }

          if (file.secrets[value]) {
            return "Secret already exists";
          }

          return true;
        },
      },
      {
        type: "input",
        name: "description",
        message: "Description (optional)",
      },
      {
        type: "confirm",
        name: "shouldSetValue",
        message: "Set an initial encrypted value?",
        default: false,
      },
    ]);

    let environment: string | undefined;
    let fingerprint: string | undefined;
    let plaintextValue: string | undefined;

    if (shouldSetValue) {
      const environmentPrompt = await inquirer.prompt([
        {
          type: "select",
          name: "environment",
          message: "Environment",
          choices: file.environments,
        },
      ]);

      environment = String(environmentPrompt.environment);

      const valueInput = await promptSecretValueInput(file);
      fingerprint = valueInput.fingerprint;
      plaintextValue = valueInput.plaintextValue;
    }

    const result = await createSecret(secretsPath, {
      description: String(description),
      environment,
      fingerprint,
      name: String(name),
      plaintextValue,
    });

    console.log(`Created secret ${result.name}`);
  });
