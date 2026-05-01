import { Command } from "commander";
import inquirer from "inquirer";

import { formatKeyLabel } from "@msecrets/core/secret-helpers";
import { getSecretEnvironments, getSecretNames, getSecretValue } from "./shared.ts";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { getConfigPath } from "#cli/program.ts";
import { shareSecretValue } from "@msecrets/core/workflows";

export const secretShareCommand = new Command()
  .command("share")
  .description("Share a secret value with another configured key")
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

    const environments = getSecretEnvironments(secret);

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

    const currentValue = getSecretValue(file, String(name), String(environment));

    if (!currentValue) {
      console.log(`Missing ${String(name)}.${String(environment)}`);
      return;
    }

    const shareableKeys = file.keys.filter((key) => !currentValue.owners.includes(key.fingerprint));

    if (!shareableKeys.length) {
      console.log(`No additional keys available for ${String(name)}.${String(environment)}`);
      return;
    }

    const { fingerprint } = await inquirer.prompt({
      type: "select",
      name: "fingerprint",
      message: "Share to",
      choices: shareableKeys.map((key) => ({
        name: formatKeyLabel(key),
        value: key.fingerprint,
      })),
    });

    const result = await shareSecretValue(secretsPath, {
      environment: String(environment),
      fingerprint: String(fingerprint),
      name: String(name),
    });

    console.log(`Shared ${result.name}.${result.environment} with ${String(fingerprint)}`);
  });
