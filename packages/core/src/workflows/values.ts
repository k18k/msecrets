import { getConfiguredKey } from "../domain/keys.ts";
import { requireName } from "../domain/names.ts";
import { createSecretValue, getSecretValue } from "../domain/secrets.ts";
import { removeSecretValueFromFile } from "../domain/values.ts";
import { modifySecretsFile } from "../file-store.ts";
import {
  decryptThenEncryptForOwners,
  getArmoredPrivateKeysForOwners,
  getEncryptedSecretValue,
  getRequiredSecret,
  getRequiredSecretFile,
  resolveOwners,
  resolveWorkflowDependencies,
  validateEnvironment,
  type WorkflowDependencyOverrides,
} from "./deps.ts";

export async function setSecretValue(
  path: string,
  input: {
    environment: string;
    fingerprint: string;
    name: string;
    plaintextValue: string;
  },
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ environment: string; name: string }> {
  const normalizedName = requireName(input.name, "Secret name");
  const normalizedEnvironment = requireName(input.environment, "Environment name");
  const file = getRequiredSecretFile(path);

  getRequiredSecret(file, normalizedName);
  validateEnvironment(file, normalizedEnvironment);

  const { encryptedValue, fingerprint } = await getEncryptedSecretValue(
    file,
    input.fingerprint,
    input.plaintextValue,
    dependencies,
  );

  await modifySecretsFile(path, async (current) => {
    const secret = current.secrets[normalizedName];
    if (!secret) {
      throw new Error(`Missing secret ${normalizedName}`);
    }

    secret.values[normalizedEnvironment] = createSecretValue(encryptedValue, [fingerprint]);
  });

  return {
    environment: normalizedEnvironment,
    name: normalizedName,
  };
}

export async function peekSecretValue(
  path: string,
  input: { environment: string; name: string },
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ environment: string; info: string; name: string; payload: string }> {
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedName = requireName(input.name, "Secret name");
  const normalizedEnvironment = requireName(input.environment, "Environment name");
  const file = getRequiredSecretFile(path);
  const value = getSecretValue(file, normalizedName, normalizedEnvironment);

  if (!value) {
    throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
  }

  const privateKeyMaterial = await getArmoredPrivateKeysForOwners(
    value.owners,
    `${normalizedName}.${normalizedEnvironment}`,
    dependencies,
  );
  const { info, payload } = await cryptoBackend.decrypt({
    ...privateKeyMaterial,
    ciphertext: value.encryptedValue,
  });

  return {
    environment: normalizedEnvironment,
    info: info ?? "",
    name: normalizedName,
    payload,
  };
}

export async function removeSecretValue(
  path: string,
  input: { environment: string; name: string },
): Promise<{ environment: string; name: string; removedSecret: boolean }> {
  const normalizedName = requireName(input.name, "Secret name");
  const normalizedEnvironment = requireName(input.environment, "Environment name");
  let removedSecret = false;

  await modifySecretsFile(path, async (current) => {
    const result = removeSecretValueFromFile(current, {
      environment: normalizedEnvironment,
      name: normalizedName,
    });
    removedSecret = result.removedSecret;
  });

  return {
    environment: normalizedEnvironment,
    name: normalizedName,
    removedSecret,
  };
}

export async function shareSecretValue(
  path: string,
  input: {
    environment: string;
    fingerprint: string;
    name: string;
  },
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ environment: string; name: string; owners: string[] }> {
  const normalizedName = requireName(input.name, "Secret name");
  const normalizedEnvironment = requireName(input.environment, "Environment name");
  const normalizedFingerprint = requireName(input.fingerprint, "Key fingerprint");
  const file = getRequiredSecretFile(path);
  const value = getSecretValue(file, normalizedName, normalizedEnvironment);

  if (!value) {
    throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
  }

  const owners = resolveOwners(file, value.owners);

  if (owners.includes(normalizedFingerprint)) {
    throw new Error(
      `${normalizedFingerprint} already has access to ${normalizedName}.${normalizedEnvironment}`,
    );
  }

  if (!getConfiguredKey(file, normalizedFingerprint)) {
    throw new Error(`Configured key not found: ${normalizedFingerprint}`);
  }

  const nextOwners = [...owners, normalizedFingerprint];
  const nextValue = await decryptThenEncryptForOwners({
    dependencies,
    file,
    nextOwners,
    value,
    valueLabel: `${normalizedName}.${normalizedEnvironment}`,
  });

  await modifySecretsFile(path, async (current) => {
    const latestValue = getSecretValue(current, normalizedName, normalizedEnvironment);
    if (!latestValue) {
      throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
    }

    current.secrets[normalizedName]!.values[normalizedEnvironment] = nextValue;
  });

  return {
    environment: normalizedEnvironment,
    name: normalizedName,
    owners: nextOwners,
  };
}

export async function revokeSecretValue(
  path: string,
  input: {
    environment: string;
    fingerprint: string;
    name: string;
  },
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ environment: string; name: string; owners: string[] }> {
  const normalizedName = requireName(input.name, "Secret name");
  const normalizedEnvironment = requireName(input.environment, "Environment name");
  const normalizedFingerprint = requireName(input.fingerprint, "Key fingerprint");
  const file = getRequiredSecretFile(path);
  const value = getSecretValue(file, normalizedName, normalizedEnvironment);

  if (!value) {
    throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
  }

  const owners = resolveOwners(file, value.owners);

  if (!owners.includes(normalizedFingerprint)) {
    throw new Error(
      `${normalizedFingerprint} does not currently have access to ${normalizedName}.${normalizedEnvironment}`,
    );
  }

  if (owners.length < 2) {
    throw new Error(
      `Cannot revoke the only recipient from ${normalizedName}.${normalizedEnvironment}`,
    );
  }

  const nextOwners = owners.filter((owner) => owner !== normalizedFingerprint);
  const nextValue = await decryptThenEncryptForOwners({
    dependencies,
    file,
    nextOwners,
    value,
    valueLabel: `${normalizedName}.${normalizedEnvironment}`,
  });

  await modifySecretsFile(path, async (current) => {
    const latestValue = getSecretValue(current, normalizedName, normalizedEnvironment);
    if (!latestValue) {
      throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
    }

    current.secrets[normalizedName]!.values[normalizedEnvironment] = nextValue;
  });

  return {
    environment: normalizedEnvironment,
    name: normalizedName,
    owners: nextOwners,
  };
}
