import inquirer from "inquirer";
import { formatKeyLabel } from "@msecrets/core/secret-helpers";
import { importConfiguredKey, listImportableKeys } from "@msecrets/core/workflows";
import { getConfigPath } from "#cli/program.ts";

export async function runImportKeyCommand() {
  const secretsPath = getConfigPath();
  const importableKeys = await listImportableKeys(secretsPath);

  if (!importableKeys.length) {
    console.log("No keys available to import");
    return;
  }

  const selected = await inquirer.prompt({
    type: "select",
    message: "Select a key to import",
    name: "fingerprint",
    choices: importableKeys.map((key) => ({
      name: formatKeyLabel(key),
      value: key.fingerprint,
    })),
  });

  const result = await importConfiguredKey(secretsPath, String(selected.fingerprint));

  if (result.alreadyImported) {
    console.log("Key already imported");
    return;
  }

  console.log(`Imported key ${result.key.fingerprint}`);
}
