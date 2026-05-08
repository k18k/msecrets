import {
  addSecretToFile,
  createSecretValue,
  deleteSecretFromFile,
  renameSecretInFile,
} from "../domain/secrets.ts";
import { requireName } from "../domain/names.ts";
import { modifySecretsFile } from "../file-store.ts";
import type { Secret } from "../model.ts";
import {
  getEncryptedSecretValue,
  getRequiredSecretFile,
  validateEnvironment,
  type WorkflowDependencyOverrides,
} from "./deps.ts";

export async function createSecret(
  path: string,
  input: {
    description?: string;
    environment?: string;
    fingerprint?: string;
    name: string;
    plaintextValue?: string;
  },
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ hasInitialValue: boolean; name: string }> {
  const normalizedName = requireName(input.name, "Secret name");

  const file = getRequiredSecretFile(path);

  if (file.secrets[normalizedName]) {
    throw new Error("Secret already exists");
  }

  const description = input.description?.trim() || undefined;
  const secret: Secret = {
    description,
    values: {},
  };

  if (input.plaintextValue !== undefined) {
    if (!input.environment) {
      throw new Error("Environment is required when setting an initial value");
    }

    const normalizedEnvironment = requireName(input.environment, "Environment name");
    validateEnvironment(file, normalizedEnvironment);

    const { encryptedValue, fingerprint } = await getEncryptedSecretValue(
      file,
      input.fingerprint ?? "",
      input.plaintextValue,
      dependencies,
    );

    secret.values[normalizedEnvironment] = createSecretValue(encryptedValue, [fingerprint]);
  }

  await modifySecretsFile(path, async (current) => {
    addSecretToFile(current, normalizedName, secret);
  });

  return {
    hasInitialValue: input.plaintextValue !== undefined,
    name: normalizedName,
  };
}

export async function renameSecret(
  path: string,
  input: { name: string; nextName: string },
): Promise<{ name: string; previousName: string; renamed: boolean }> {
  const normalizedName = requireName(input.name, "Secret name");
  const normalizedNextName = requireName(input.nextName, "New secret name");

  let renamed = normalizedName !== normalizedNextName;

  await modifySecretsFile(path, async (current) => {
    const result = renameSecretInFile(current, {
      name: normalizedName,
      nextName: normalizedNextName,
    });
    renamed = result.renamed;
  });

  return {
    name: normalizedNextName,
    previousName: normalizedName,
    renamed,
  };
}

export async function deleteSecret(
  path: string,
  name: string,
): Promise<{ name: string; removed: boolean; removedValues: number }> {
  const normalizedName = requireName(name, "Secret name");

  let removed = false;
  let removedValues = 0;

  await modifySecretsFile(path, async (current) => {
    const result = deleteSecretFromFile(current, normalizedName);
    removed = result.removed;
    removedValues = result.removedValues;
  });

  return {
    name: normalizedName,
    removed,
    removedValues,
  };
}
