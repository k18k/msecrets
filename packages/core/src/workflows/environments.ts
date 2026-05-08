import {
  addEnvironmentToFile,
  getEnvironmentUsage,
  removeEnvironmentFromFile,
  renameEnvironmentInFile,
  type EnvironmentUsageReport,
} from "../domain/environments.ts";
import { requireName } from "../domain/names.ts";
import { modifySecretsFile } from "../file-store.ts";
import { getRequiredSecretFile } from "./deps.ts";

export type { EnvironmentUsageReport } from "../domain/environments.ts";

export function listEnvironments(path: string): string[] {
  return [...getRequiredSecretFile(path).environments];
}

export async function addEnvironment(
  path: string,
  environment: string,
): Promise<{ added: boolean; environment: string }> {
  const normalizedEnvironment = requireName(environment, "Environment name");

  let added = false;

  await modifySecretsFile(path, async (file) => {
    const result = addEnvironmentToFile(file, normalizedEnvironment);
    added = result.added;
  });

  return { added, environment: normalizedEnvironment };
}

export async function removeEnvironment(
  path: string,
  environment: string,
): Promise<{
  environment: string;
  removed: boolean;
  removedSecrets: string[];
  removedValues: number;
}> {
  const normalizedEnvironment = requireName(environment, "Environment name");
  let result: { removed: boolean; removedSecrets: string[]; removedValues: number } = {
    removed: false,
    removedSecrets: [],
    removedValues: 0,
  };

  await modifySecretsFile(path, async (file) => {
    const { file: nextFile, ...next } = removeEnvironmentFromFile(file, normalizedEnvironment);
    result = next;
    return nextFile;
  });

  return {
    ...result,
    environment: normalizedEnvironment,
  };
}

export async function renameEnvironment(
  path: string,
  input: { environment: string; nextEnvironment: string },
): Promise<{ environment: string; nextEnvironment: string; renamed: boolean }> {
  const normalizedEnvironment = requireName(input.environment, "Environment name");
  const normalizedNextEnvironment = requireName(input.nextEnvironment, "New environment name");

  let renamed = normalizedEnvironment !== normalizedNextEnvironment;

  await modifySecretsFile(path, async (file) => {
    const result = renameEnvironmentInFile(file, {
      environment: normalizedEnvironment,
      nextEnvironment: normalizedNextEnvironment,
    });
    renamed = result.renamed;
  });

  return {
    environment: normalizedEnvironment,
    nextEnvironment: normalizedNextEnvironment,
    renamed,
  };
}

export function planEnvironmentRemoval(path: string, environment: string): EnvironmentUsageReport {
  const normalizedEnvironment = requireName(environment, "Environment name");

  return getEnvironmentUsage(getRequiredSecretFile(path), normalizedEnvironment);
}
