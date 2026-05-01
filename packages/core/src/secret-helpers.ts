import type { KeyIdentity } from "./providers/types.ts";
import type { Secret, SecretDef, SecretsFile } from "./types.ts";

export function formatKeyLabel(key: Pick<KeyIdentity, "fingerprint" | "userIds">): string {
  const userIds = key.userIds.length ? key.userIds.join(", ") : "Unnamed key";
  return `${userIds} (${key.fingerprint})`;
}

export function createSecretDef(encryptedValue: string, owners: string[]): SecretDef {
  if (!owners.length) {
    throw new Error("Secret owners are required");
  }

  return {
    encryptedValue,
    owners,
  };
}

export function getSecretNames(file: SecretsFile): string[] {
  return Object.keys(file.secrets).sort((left, right) => left.localeCompare(right));
}

export function getSecretEnvironments(secret: Secret): string[] {
  return Object.keys(secret.values).sort((left, right) => left.localeCompare(right));
}

export function getSecretValue(
  file: SecretsFile,
  name: string,
  environment: string,
): SecretDef | null {
  return file.secrets[name]?.values[environment] ?? null;
}

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
