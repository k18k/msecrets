import type { Secret, SecretValue, SecretsFile } from "../model.ts";

export function createSecretValue(encryptedValue: string, owners: string[]): SecretValue {
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
): SecretValue | null {
  return file.secrets[name]?.values[environment] ?? null;
}

export function addSecretToFile(file: SecretsFile, name: string, secret: Secret) {
  if (file.secrets[name]) {
    throw new Error("Secret already exists");
  }

  file.secrets[name] = secret;
}

export function renameSecretInFile(
  file: SecretsFile,
  input: { name: string; nextName: string },
): { file: SecretsFile; renamed: boolean } {
  if (input.name === input.nextName) {
    return { file, renamed: false };
  }

  const secret = file.secrets[input.name];

  if (!secret) {
    throw new Error(`Missing secret ${input.name}`);
  }

  if (file.secrets[input.nextName]) {
    throw new Error(`Secret already exists: ${input.nextName}`);
  }

  file.secrets[input.nextName] = secret;
  delete file.secrets[input.name];

  return { file, renamed: true };
}

export function deleteSecretFromFile(
  file: SecretsFile,
  name: string,
): { file: SecretsFile; removed: boolean; removedValues: number } {
  const secret = file.secrets[name];

  if (!secret) {
    return { file, removed: false, removedValues: 0 };
  }

  const removedValues = Object.keys(secret.values).length;
  delete file.secrets[name];

  return { file, removed: true, removedValues };
}
