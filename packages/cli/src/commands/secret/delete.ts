import { Command } from "commander";
import inquirer from "inquirer";

import { getSecretNames } from "./shared.ts";
import { getConfigPath } from "#cli/program.ts";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { deleteSecret } from "@msecrets/core/workflows";

export const secretDeleteCommand = new Command()
  .command("delete")
  .description("Delete secret and all environment values")
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

    const result = await deleteSecret(secretsPath, String(name));

    if (!result.removed) {
      console.log(`Secret ${result.name} was already missing`);
      return;
    }

    console.log(
      `Deleted secret ${result.name} and removed ${result.removedValues} value${result.removedValues === 1 ? "" : "s"}`,
    );
  });
