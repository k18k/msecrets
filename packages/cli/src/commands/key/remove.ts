import { getConfigPath } from "#cli/program.ts";
import { formatKeyLabel } from "@msecrets/core/secret-helpers";
import { getSecretsFile } from "@msecrets/core/secrets-file";
import { removeConfiguredKey } from "@msecrets/core/workflows";
import { Command } from "commander";
import inquirer from "inquirer";

export const keyRemoveCommand = new Command()
  .command("remove")
  .description("Remove configured key")
  .action(async () => {
    const secretsPath = getConfigPath();
    const file = getSecretsFile(secretsPath);

    if (!file.keys.length) {
      console.log("No configured keys found");
      return;
    }

    const { fingerprint } = await inquirer.prompt({
      type: "select",
      name: "fingerprint",
      message: "Key",
      choices: file.keys.map((key) => ({
        name: formatKeyLabel(key),
        value: key.fingerprint,
      })),
    });

    const result = await removeConfiguredKey(secretsPath, String(fingerprint));

    if (!result.removed) {
      console.log(`Key ${result.fingerprint} was already missing`);
      return;
    }

    if (!result.updatedValues) {
      console.log(`Removed key ${result.fingerprint}`);
      return;
    }

    console.log(
      `Removed key ${result.fingerprint} and re-encrypted ${result.updatedValues} value${result.updatedValues === 1 ? "" : "s"}`,
    );
  });
