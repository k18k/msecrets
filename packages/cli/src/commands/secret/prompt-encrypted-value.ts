import inquirer from "inquirer";
import { keyProviders, type KeyIdentity } from "@msecrets/core/providers";
import type { SecretsFile } from "@msecrets/core/types";
import { formatKeyLabel } from "@msecrets/core/secret-helpers";

export async function promptSecretValueInput(
  file: SecretsFile,
): Promise<{ fingerprint: string; plaintextValue: string }> {
  if (!file.keys.length) {
    throw new Error("No keys available in config file");
  }

  const { fingerprint } = await inquirer.prompt([
    {
      type: "select",
      name: "fingerprint",
      message: "GPG key",
      choices: file.keys.map((key) => ({
        name: formatKeyLabel(key as KeyIdentity),
        value: key.fingerprint,
      })),
    },
  ]);

  const privateKey = await keyProviders.getPrivateKey(String(fingerprint));

  if (!privateKey) {
    throw new Error(`Private key not found: ${String(fingerprint)}`);
  }

  const { plaintextValue } = await inquirer.prompt([
    {
      type: "password",
      name: "plaintextValue",
      message: "Secret value",
      mask: "*",
      validate: (value: string) => (value ? true : "Secret value is required"),
    },
  ]);

  return {
    fingerprint: privateKey.fingerprint,
    plaintextValue: String(plaintextValue),
  };
}
