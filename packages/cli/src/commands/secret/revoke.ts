import { Command } from "commander";
import inquirer from "inquirer";

import { formatKeyLabel } from "@msecrets/core/secret-helpers";
import { getSecretEnvironments, getSecretNames, getSecretValue } from "./shared.ts";
import { getConfigPath } from "#cli/program.ts";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { revokeSecretValue } from "@msecrets/core/workflows";

export const secretRevokeCommand = new Command()
  .command("revoke")
  .description("Revoke a configured key from a secret value")
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

    if (currentValue.owners.length < 2) {
      console.log(`Cannot revoke the only recipient from ${String(name)}.${String(environment)}`);
      return;
    }

    const revokableKeys = file.keys.filter((key) => currentValue.owners.includes(key.fingerprint));

    const { fingerprint } = await inquirer.prompt({
      type: "select",
      name: "fingerprint",
      message: "Revoke from",
      choices: revokableKeys.map((key) => ({
        name: formatKeyLabel(key),
        value: key.fingerprint,
      })),
    });

    const result = await revokeSecretValue(secretsPath, {
      environment: String(environment),
      fingerprint: String(fingerprint),
      name: String(name),
    });

    console.log(`Revoked ${String(fingerprint)} from ${result.name}.${result.environment}`);
  });
