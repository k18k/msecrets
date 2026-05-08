import type { SecretValue, SecretsFile } from "../model.ts";

export function removeSecretValueFromFile(
  file: SecretsFile,
  input: { environment: string; name: string },
): { file: SecretsFile; removedSecret: boolean } {
  const secret = file.secrets[input.name];
  if (!secret) {
    throw new Error(`Missing secret ${input.name}`);
  }

  if (!secret.values[input.environment]) {
    throw new Error(`Missing ${input.name}.${input.environment}`);
  }

  delete secret.values[input.environment];
  if (!Object.keys(secret.values).length) {
    delete file.secrets[input.name];
    return { file, removedSecret: true };
  }

  return { file, removedSecret: false };
}

export function planOwnerChange(
  file: SecretsFile,
  input: { environment: string; name: string; nextOwners: string[] },
): { currentValue: SecretValue; nextOwners: string[] } {
  const value = file.secrets[input.name]?.values[input.environment];
  if (!value) {
    throw new Error(`Missing ${input.name}.${input.environment}`);
  }

  if (!input.nextOwners.length) {
    throw new Error("Select at least one existing recipient key");
  }

  return {
    currentValue: value,
    nextOwners: [...new Set(input.nextOwners)],
  };
}
