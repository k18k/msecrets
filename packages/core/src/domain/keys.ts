import type { PublicKey } from "../keys/types.ts";
import type { SecretsFile } from "../model.ts";
import { getSecretNames } from "./secrets.ts";

export function getConfiguredKeyFingerprints(file: SecretsFile): Set<string> {
  return new Set(file.keys.map((key) => key.fingerprint));
}

export function getConfiguredKey(file: SecretsFile, fingerprint: string) {
  return file.keys.find((key) => key.fingerprint === fingerprint) ?? null;
}

export function getRequiredConfiguredKeys(
  file: SecretsFile,
  fingerprints: string[],
): SecretsFile["keys"] {
  return fingerprints.map((fingerprint) => {
    const key = getConfiguredKey(file, fingerprint);

    if (!key) {
      throw new Error(`Configured key not found: ${fingerprint}`);
    }

    return key;
  });
}

export function addConfiguredKeyToFile(file: SecretsFile, key: PublicKey) {
  if (file.keys.find((currentKey) => currentKey.fingerprint === key.fingerprint)) {
    return { alreadyImported: true };
  }

  file.keys.push(key);
  return { alreadyImported: false };
}

export function getValuesOwnedByKey(
  file: SecretsFile,
  fingerprint: string,
): Array<{ environment: string; secretName: string }> {
  const values: Array<{ environment: string; secretName: string }> = [];

  for (const secretName of getSecretNames(file)) {
    const secret = file.secrets[secretName];

    if (!secret) {
      continue;
    }

    for (const environment of Object.keys(secret.values)) {
      const value = secret.values[environment];

      if (value?.owners.includes(fingerprint)) {
        values.push({ environment, secretName });
      }
    }
  }

  return values;
}
