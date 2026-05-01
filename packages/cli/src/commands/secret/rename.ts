import { Command } from "commander";
import inquirer from "inquirer";

import { getSecretNames } from "./shared.ts";
import { getConfigPath } from "#cli/program.ts";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { renameSecret } from "@msecrets/core/workflows";

export const secretRenameCommand = new Command()
  .command("rename")
  .description("Rename secret")
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

    const currentName = String(name);

    const { nextName } = await inquirer.prompt({
      type: "input",
      name: "nextName",
      message: "New secret name",
      default: currentName,
      validate: (value: string) => {
        const normalizedValue = value.trim();

        if (!normalizedValue) {
          return "New secret name is required";
        }

        if (normalizedValue !== currentName && file.secrets[normalizedValue]) {
          return "Secret already exists";
        }

        return true;
      },
    });

    const result = await renameSecret(secretsPath, {
      name: currentName,
      nextName: String(nextName),
    });

    if (!result.renamed) {
      console.log(`Secret is already named ${result.name}`);
      return;
    }

    console.log(`Renamed secret ${result.previousName} to ${result.name}`);
  });
