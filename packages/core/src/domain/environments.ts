import type { SecretsFile } from "../model.ts";
import { getSecretNames } from "./secrets.ts";

export type EnvironmentUsageReport = {
  environment: string;
  exists: boolean;
  secretCount: number;
  secrets: string[];
};

export function getEnvironmentUsage(
  file: SecretsFile,
  environment: string,
): EnvironmentUsageReport {
  const secrets = getSecretNames(file).filter((secretName) =>
    Boolean(file.secrets[secretName]?.values[environment]),
  );

  return {
    environment,
    exists: file.environments.includes(environment),
    secretCount: secrets.length,
    secrets,
  };
}

export function getEnvironmentUsageReports(file: SecretsFile): EnvironmentUsageReport[] {
  return file.environments.map((environment) => getEnvironmentUsage(file, environment));
}

export function addEnvironmentToFile(
  file: SecretsFile,
  environment: string,
): { added: boolean; file: SecretsFile } {
  file.environments ||= [];

  if (file.environments.includes(environment)) {
    return { added: false, file };
  }

  file.environments.push(environment);
  return { added: true, file };
}

export function removeEnvironmentFromFile(
  file: SecretsFile,
  environment: string,
): { file: SecretsFile; removed: boolean; removedSecrets: string[]; removedValues: number } {
  if (!file.environments.includes(environment)) {
    return { file, removed: false, removedSecrets: [], removedValues: 0 };
  }

  let removedValues = 0;
  const removedSecrets: string[] = [];
  file.environments = file.environments.filter(
    (currentEnvironment) => currentEnvironment !== environment,
  );

  getSecretNames(file).forEach((secretName) => {
    const secret = file.secrets[secretName];

    if (!secret?.values[environment]) {
      return;
    }

    delete secret.values[environment];
    removedValues += 1;

    if (!Object.keys(secret.values).length) {
      delete file.secrets[secretName];
      removedSecrets.push(secretName);
    }
  });

  return { file, removed: true, removedSecrets, removedValues };
}

export function renameEnvironmentInFile(
  file: SecretsFile,
  input: { environment: string; nextEnvironment: string },
): { file: SecretsFile; renamed: boolean } {
  if (input.environment === input.nextEnvironment) {
    return { file, renamed: false };
  }

  if (!file.environments.includes(input.environment)) {
    throw new Error(`Environment not found: ${input.environment}`);
  }

  if (file.environments.includes(input.nextEnvironment)) {
    throw new Error(`Environment already exists: ${input.nextEnvironment}`);
  }

  file.environments = file.environments.map((environment) =>
    environment === input.environment ? input.nextEnvironment : environment,
  );

  getSecretNames(file).forEach((secretName) => {
    const secret = file.secrets[secretName];
    const value = secret?.values[input.environment];

    if (!secret || !value) {
      return;
    }

    secret.values[input.nextEnvironment] = value;
    delete secret.values[input.environment];
  });

  return { file, renamed: true };
}
