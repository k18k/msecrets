import { defaultCryptoBackend, type CryptoBackend } from "./crypto.ts";
import { parseArmoredKeyMaterial } from "./key-material.ts";
import { keyProviders } from "./providers/index.ts";
import type {
  KeyIdentity,
  MSecretsPrivateKey,
  MSecretsPublicKey,
} from "./providers/types.ts";
import {
  createSecretDef,
  getConfiguredKey,
  getConfiguredKeyFingerprints,
  getRequiredConfiguredKeys,
  getSecretNames,
  getSecretValue,
} from "./secret-helpers.ts";
import {
  getSecretsFile,
  hasSecretsFile,
  modFile,
  readSecretsFileData,
  writeSecretsFile,
} from "./secrets-file.ts";
import type { Secret, SecretsFile } from "./types.ts";
import {
  CURRENT_SECRETS_FILE_VERSION,
  type SecretsFileValidationIssue,
  type SecretsFileValidationResult,
  validateSecretsFile,
} from "./validation.ts";

export type WorkspaceSnapshot = {
  exists: boolean;
  file: SecretsFile | null;
  importableKeys: KeyIdentity[];
  localKeys: KeyIdentity[];
};

export type WorkflowKeyAccess = {
  listAllKeys(): Promise<KeyIdentity[]>;
  getPublicKey(fingerprint: string): Promise<MSecretsPublicKey | null>;
  getPrivateKey(fingerprint: string): Promise<MSecretsPrivateKey | null>;
};

export type WorkflowDependencies = {
  cryptoBackend: CryptoBackend;
  keyAccess: WorkflowKeyAccess;
};

export type WorkflowDependencyOverrides = Partial<WorkflowDependencies>;

export type EnvironmentUsageReport = {
  environment: string;
  exists: boolean;
  secretCount: number;
  secrets: string[];
};

export type WorkspaceAuditFinding = SecretsFileValidationIssue & {
  source: "file" | "workspace";
};

export type WorkspaceAuditReport = {
  exists: boolean;
  file: SecretsFile | null;
  findings: WorkspaceAuditFinding[];
  importableKeys: KeyIdentity[];
  localKeys: KeyIdentity[];
  path: string;
  summary: {
    configuredKeyCount: number;
    emptySecrets: string[];
    environmentCount: number;
    environmentUsage: EnvironmentUsageReport[];
    importableKeyCount: number;
    localKeyCount: number;
    secretCount: number;
    valueCount: number;
  };
  valid: boolean;
};

function createEmptySecretsFile(): SecretsFile {
  return {
    version: CURRENT_SECRETS_FILE_VERSION,
    environments: ["development"],
    keys: [],
    secrets: {},
  };
}

function resolveWorkflowDependencies(
  dependencies?: WorkflowDependencyOverrides,
): WorkflowDependencies {
  return {
    cryptoBackend: dependencies?.cryptoBackend ?? defaultCryptoBackend,
    keyAccess: dependencies?.keyAccess ?? keyProviders,
  };
}

function getRequiredSecretFile(path: string): SecretsFile {
  if (!hasSecretsFile(path)) {
    throw new Error(`Secrets file not found: ${path}`);
  }

  return getSecretsFile(path);
}

function normalizeText(value: string): string {
  return value.trim();
}

async function getEncryptedSecretValue(
  file: SecretsFile,
  fingerprint: string,
  plaintextValue: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ encryptedValue: string; fingerprint: string }> {
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedFingerprint = normalizeText(fingerprint);
  const normalizedPlaintext = plaintextValue;

  if (!normalizedFingerprint) {
    throw new Error("A key fingerprint is required");
  }

  if (!normalizedPlaintext) {
    throw new Error("Secret value is required");
  }

  if (!getConfiguredKey(file, normalizedFingerprint)) {
    throw new Error(`Configured key not found: ${normalizedFingerprint}`);
  }

  return {
    encryptedValue: await cryptoBackend.encrypt({
      plaintext: normalizedPlaintext,
      recipients: getRequiredConfiguredKeys(file, [normalizedFingerprint]),
    }),
    fingerprint: normalizedFingerprint,
  };
}

function validateEnvironment(file: SecretsFile, environment: string) {
  if (!file.environments.includes(environment)) {
    throw new Error(`Environment not found: ${environment}`);
  }
}

function getRequiredSecret(file: SecretsFile, name: string) {
  const secret = file.secrets[name];

  if (!secret) {
    throw new Error(`Missing secret ${name}`);
  }

  return secret;
}

function resolveOwners(file: SecretsFile, owners: string[]): string[] {
  if (!owners.length) {
    throw new Error("Select at least one existing recipient key");
  }

  const configuredFingerprints = getConfiguredKeyFingerprints(file);
  for (const owner of owners) {
    if (!configuredFingerprints.has(owner)) {
      throw new Error(`Configured key not found: ${owner}`);
    }
  }

  return [...new Set(owners)];
}

async function getArmoredPrivateKeysForOwners(
  owners: string[],
  valueLabel: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<string[]> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const normalizedOwners = [
    ...new Set(owners.map((owner) => normalizeText(owner)).filter(Boolean)),
  ];

  if (!normalizedOwners.length) {
    throw new Error(`No owners configured for ${valueLabel}`);
  }

  const privateKeys = await Promise.all(
    normalizedOwners.map((owner) => keyAccess.getPrivateKey(owner)),
  );
  const availablePrivateKeys = privateKeys.filter(
    (privateKey): privateKey is MSecretsPrivateKey => privateKey !== null,
  );

  if (!availablePrivateKeys.length) {
    throw new Error(`Private key not found for any owner of ${valueLabel}`);
  }

  return availablePrivateKeys.map((privateKey) => privateKey.privateKey);
}

function createWorkspaceFinding(
  finding: Omit<WorkspaceAuditFinding, "source">,
  source: WorkspaceAuditFinding["source"],
): WorkspaceAuditFinding {
  return {
    ...finding,
    source,
  };
}

function countSecretValues(file: SecretsFile): number {
  return Object.values(file.secrets).reduce(
    (count, secret) => count + Object.keys(secret.values).length,
    0,
  );
}

function getEmptySecrets(file: SecretsFile): string[] {
  return getSecretNames(file).filter((secretName) => {
    const secret = file.secrets[secretName];
    return secret ? Object.keys(secret.values).length === 0 : false;
  });
}

function getEnvironmentUsage(file: SecretsFile, environment: string): EnvironmentUsageReport {
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

function getEnvironmentUsageReports(file: SecretsFile): EnvironmentUsageReport[] {
  return file.environments.map((environment) => getEnvironmentUsage(file, environment));
}

export async function getWorkspaceSnapshot(
  path: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<WorkspaceSnapshot> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const localKeys = await keyAccess.listAllKeys();

  if (!hasSecretsFile(path)) {
    return {
      exists: false,
      file: null,
      importableKeys: localKeys,
      localKeys,
    };
  }

  const file = getSecretsFile(path);
  const configuredFingerprints = getConfiguredKeyFingerprints(file);

  return {
    exists: true,
    file,
    importableKeys: localKeys.filter((key) => !configuredFingerprints.has(key.fingerprint)),
    localKeys,
  };
}

export async function auditWorkspace(
  path: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<WorkspaceAuditReport> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const localKeys = await keyAccess.listAllKeys();

  if (!hasSecretsFile(path)) {
    return {
      exists: false,
      file: null,
      findings: [
        createWorkspaceFinding(
          {
            code: "workspace_missing",
            message: `Secrets file not found at ${path}`,
            path: "$",
            severity: "warning",
          },
          "workspace",
        ),
      ],
      importableKeys: localKeys,
      localKeys,
      path,
      summary: {
        configuredKeyCount: 0,
        emptySecrets: [],
        environmentCount: 0,
        environmentUsage: [],
        importableKeyCount: localKeys.length,
        localKeyCount: localKeys.length,
        secretCount: 0,
        valueCount: 0,
      },
      valid: false,
    };
  }

  let validation: SecretsFileValidationResult;
  let file: SecretsFile | null = null;

  try {
    const rawFile = readSecretsFileData(path);
    validation = validateSecretsFile(rawFile);

    if (validation.valid) {
      file = rawFile as SecretsFile;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to parse secrets file";

    validation = {
      issues: [
        {
          code: "file_parse_failed",
          message,
          path: "$",
          severity: "error",
        },
      ],
      valid: false,
    };
  }

  const findings = validation.issues.map((issue) => createWorkspaceFinding(issue, "file"));

  if (!localKeys.length) {
    findings.push(
      createWorkspaceFinding(
        {
          code: "local_keys_missing_all",
          message: "No private keys are available through the current runtime key sources",
          path: "$.keys",
          severity: "warning",
        },
        "workspace",
      ),
    );
  }

  if (!file) {
    return {
      exists: true,
      file: null,
      findings,
      importableKeys: localKeys,
      localKeys,
      path,
      summary: {
        configuredKeyCount: 0,
        emptySecrets: [],
        environmentCount: 0,
        environmentUsage: [],
        importableKeyCount: localKeys.length,
        localKeyCount: localKeys.length,
        secretCount: 0,
        valueCount: 0,
      },
      valid: false,
    };
  }

  const configuredFingerprints = getConfiguredKeyFingerprints(file);
  const localFingerprints = new Set(localKeys.map((key) => key.fingerprint));

  file.keys.forEach((key) => {
    if (!localFingerprints.has(key.fingerprint)) {
      findings.push(
        createWorkspaceFinding(
          {
            code: "configured_key_missing_locally",
            message: `Configured key ${key.fingerprint} is not available through the current runtime key sources`,
            path: "$.keys",
            severity: "warning",
          },
          "workspace",
        ),
      );
    }
  });

  return {
    exists: true,
    file,
    findings,
    importableKeys: localKeys.filter((key) => !configuredFingerprints.has(key.fingerprint)),
    localKeys,
    path,
    summary: {
      configuredKeyCount: file.keys.length,
      emptySecrets: getEmptySecrets(file),
      environmentCount: file.environments.length,
      environmentUsage: getEnvironmentUsageReports(file),
      importableKeyCount: localKeys.filter((key) => !configuredFingerprints.has(key.fingerprint))
        .length,
      localKeyCount: localKeys.length,
      secretCount: getSecretNames(file).length,
      valueCount: countSecretValues(file),
    },
    valid: validation.valid,
  };
}

export function initializeSecretsFile(path: string): { created: boolean } {
  if (hasSecretsFile(path)) {
    return { created: false };
  }

  writeSecretsFile(path, createEmptySecretsFile());
  return { created: true };
}

export function listEnvironments(path: string): string[] {
  return [...getRequiredSecretFile(path).environments];
}

export async function addEnvironment(
  path: string,
  environment: string,
): Promise<{ added: boolean; environment: string }> {
  const normalizedEnvironment = normalizeText(environment);

  if (!normalizedEnvironment) {
    throw new Error("Environment name is required");
  }

  let added = false;

  await modFile(path, async (file) => {
    file.environments ||= [];

    if (!file.environments.includes(normalizedEnvironment)) {
      file.environments.push(normalizedEnvironment);
      added = true;
    }

    return file;
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
  const normalizedEnvironment = normalizeText(environment);
  let removed = false;
  let removedValues = 0;
  const removedSecrets: string[] = [];

  await modFile(path, async (file) => {
    if (!file.environments.includes(normalizedEnvironment)) {
      removed = false;
      return file;
    }

    const nextEnvironments = file.environments.filter(
      (currentEnvironment) => currentEnvironment !== normalizedEnvironment,
    );

    removed = nextEnvironments.length !== file.environments.length;
    file.environments = nextEnvironments;

    getSecretNames(file).forEach((secretName) => {
      const secret = file.secrets[secretName];

      if (!secret?.values[normalizedEnvironment]) {
        return;
      }

      delete secret.values[normalizedEnvironment];
      removedValues += 1;

      if (!Object.keys(secret.values).length) {
        delete file.secrets[secretName];
        removedSecrets.push(secretName);
      }
    });

    return file;
  });

  return {
    removed,
    environment: normalizedEnvironment,
    removedSecrets,
    removedValues,
  };
}

export async function renameEnvironment(
  path: string,
  input: { environment: string; nextEnvironment: string },
): Promise<{ environment: string; nextEnvironment: string; renamed: boolean }> {
  const normalizedEnvironment = normalizeText(input.environment);
  const normalizedNextEnvironment = normalizeText(input.nextEnvironment);

  if (!normalizedEnvironment) {
    throw new Error("Environment name is required");
  }

  if (!normalizedNextEnvironment) {
    throw new Error("New environment name is required");
  }

  if (normalizedEnvironment === normalizedNextEnvironment) {
    return {
      environment: normalizedEnvironment,
      nextEnvironment: normalizedNextEnvironment,
      renamed: false,
    };
  }

  await modFile(path, async (file) => {
    if (!file.environments.includes(normalizedEnvironment)) {
      throw new Error(`Environment not found: ${normalizedEnvironment}`);
    }

    if (file.environments.includes(normalizedNextEnvironment)) {
      throw new Error(`Environment already exists: ${normalizedNextEnvironment}`);
    }

    file.environments = file.environments.map((environment) =>
      environment === normalizedEnvironment ? normalizedNextEnvironment : environment,
    );

    getSecretNames(file).forEach((secretName) => {
      const secret = file.secrets[secretName];
      const value = secret?.values[normalizedEnvironment];

      if (!secret || !value) {
        return;
      }

      secret.values[normalizedNextEnvironment] = value;
      delete secret.values[normalizedEnvironment];
    });

    return file;
  });

  return {
    environment: normalizedEnvironment,
    nextEnvironment: normalizedNextEnvironment,
    renamed: true,
  };
}

export async function listImportableKeys(
  path: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<KeyIdentity[]> {
  return (await getWorkspaceSnapshot(path, dependencies)).importableKeys;
}

export function planEnvironmentRemoval(path: string, environment: string): EnvironmentUsageReport {
  const normalizedEnvironment = normalizeText(environment);

  if (!normalizedEnvironment) {
    throw new Error("Environment name is required");
  }

  return getEnvironmentUsage(getRequiredSecretFile(path), normalizedEnvironment);
}

export async function importConfiguredKey(
  path: string,
  fingerprint: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ alreadyImported: boolean; key: MSecretsPublicKey }> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const normalizedFingerprint = normalizeText(fingerprint);
  const publicKey = await keyAccess.getPublicKey(normalizedFingerprint);

  if (!publicKey) {
    throw new Error(`Key not found: ${normalizedFingerprint}`);
  }

  let alreadyImported = false;

  await modFile(path, async (file) => {
    if (file.keys.find((key) => key.fingerprint === publicKey.fingerprint)) {
      alreadyImported = true;
      return file;
    }

    file.keys.push(publicKey);
    return file;
  });

  return { alreadyImported, key: publicKey };
}

export async function importConfiguredArmoredKey(
  path: string,
  armoredKey: string,
): Promise<{ alreadyImported: boolean; key: MSecretsPublicKey }> {
  const parsedKey = await parseArmoredKeyMaterial(armoredKey);

  if (parsedKey.kind !== "public") {
    throw new Error("Expected an armored public key, but received a private key");
  }

  let alreadyImported = false;

  await modFile(path, async (file) => {
    if (file.keys.find((key) => key.fingerprint === parsedKey.fingerprint)) {
      alreadyImported = true;
      return file;
    }

    file.keys.push({
      fingerprint: parsedKey.fingerprint,
      publicKey: parsedKey.publicKey,
      userIds: parsedKey.userIds,
    });
    return file;
  });

  return {
    alreadyImported,
    key: {
      fingerprint: parsedKey.fingerprint,
      publicKey: parsedKey.publicKey,
      userIds: parsedKey.userIds,
    },
  };
}

export async function removeConfiguredKey(
  path: string,
  fingerprint: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ fingerprint: string; removed: boolean; updatedValues: number }> {
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedFingerprint = normalizeText(fingerprint);

  if (!normalizedFingerprint) {
    throw new Error("Key fingerprint is required");
  }

  let removed = false;
  let updatedValues = 0;

  await modFile(path, async (file) => {
    if (!getConfiguredKey(file, normalizedFingerprint)) {
      removed = false;
      return file;
    }

    for (const secretName of getSecretNames(file)) {
      const secret = file.secrets[secretName];

      if (!secret) {
        continue;
      }

      for (const environment of Object.keys(secret.values)) {
        const value = secret.values[environment];

        if (!value || !value.owners.includes(normalizedFingerprint)) {
          continue;
        }

        if (value.owners.length < 2) {
          throw new Error(
            `Cannot remove key ${normalizedFingerprint} because it is the only owner of ${secretName}.${environment}`,
          );
        }

        const nextOwners = value.owners.filter((owner) => owner !== normalizedFingerprint);
        const { payload } = await cryptoBackend.decrypt({
          armoredPrivateKeys: await getArmoredPrivateKeysForOwners(
            value.owners,
            `${secretName}.${environment}`,
            dependencies,
          ),
          ciphertext: value.encryptedValue,
        });
        const encryptedValue = await cryptoBackend.encrypt({
          plaintext: payload,
          recipients: getRequiredConfiguredKeys(file, nextOwners),
        });

        secret.values[environment] = createSecretDef(encryptedValue, nextOwners);
        updatedValues += 1;
      }
    }

    file.keys = file.keys.filter((key) => key.fingerprint !== normalizedFingerprint);
    removed = true;

    return file;
  });

  return {
    fingerprint: normalizedFingerprint,
    removed,
    updatedValues,
  };
}

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
  const normalizedName = normalizeText(input.name);

  if (!normalizedName) {
    throw new Error("Secret name is required");
  }

  const file = getRequiredSecretFile(path);

  if (file.secrets[normalizedName]) {
    throw new Error("Secret already exists");
  }

  const description = input.description?.trim() || undefined;
  const secret: Secret = {
    description,
    values: {},
  };

  const hasInitialValue = Boolean(input.plaintextValue);

  if (hasInitialValue) {
    if (!input.environment) {
      throw new Error("Environment is required when setting an initial value");
    }

    validateEnvironment(file, input.environment);

    const { encryptedValue, fingerprint } = await getEncryptedSecretValue(
      file,
      input.fingerprint ?? "",
      input.plaintextValue ?? "",
      dependencies,
    );

    secret.values[input.environment] = createSecretDef(encryptedValue, [fingerprint]);
  }

  await modFile(path, async (current) => {
    if (current.secrets[normalizedName]) {
      throw new Error("Secret already exists");
    }

    current.secrets[normalizedName] = secret;
    return current;
  });

  return {
    hasInitialValue,
    name: normalizedName,
  };
}

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
  const normalizedName = normalizeText(input.name);
  const normalizedEnvironment = normalizeText(input.environment);
  const file = getRequiredSecretFile(path);

  getRequiredSecret(file, normalizedName);
  validateEnvironment(file, normalizedEnvironment);

  const { encryptedValue, fingerprint } = await getEncryptedSecretValue(
    file,
    input.fingerprint,
    input.plaintextValue,
    dependencies,
  );

  await modFile(path, async (current) => {
    const secret = current.secrets[normalizedName];

    if (!secret) {
      throw new Error(`Missing secret ${normalizedName}`);
    }

    secret.values[normalizedEnvironment] = createSecretDef(encryptedValue, [fingerprint]);
    return current;
  });

  return {
    environment: normalizedEnvironment,
    name: normalizedName,
  };
}

export async function renameSecret(
  path: string,
  input: { name: string; nextName: string },
): Promise<{ name: string; previousName: string; renamed: boolean }> {
  const normalizedName = normalizeText(input.name);
  const normalizedNextName = normalizeText(input.nextName);

  if (!normalizedName) {
    throw new Error("Secret name is required");
  }

  if (!normalizedNextName) {
    throw new Error("New secret name is required");
  }

  if (normalizedName === normalizedNextName) {
    return {
      name: normalizedNextName,
      previousName: normalizedName,
      renamed: false,
    };
  }

  await modFile(path, async (current) => {
    const secret = current.secrets[normalizedName];

    if (!secret) {
      throw new Error(`Missing secret ${normalizedName}`);
    }

    if (current.secrets[normalizedNextName]) {
      throw new Error(`Secret already exists: ${normalizedNextName}`);
    }

    current.secrets[normalizedNextName] = secret;
    delete current.secrets[normalizedName];

    return current;
  });

  return {
    name: normalizedNextName,
    previousName: normalizedName,
    renamed: true,
  };
}

export async function deleteSecret(
  path: string,
  name: string,
): Promise<{ name: string; removed: boolean; removedValues: number }> {
  const normalizedName = normalizeText(name);

  if (!normalizedName) {
    throw new Error("Secret name is required");
  }

  let removed = false;
  let removedValues = 0;

  await modFile(path, async (current) => {
    const secret = current.secrets[normalizedName];

    if (!secret) {
      removed = false;
      return current;
    }

    removedValues = Object.keys(secret.values).length;
    delete current.secrets[normalizedName];
    removed = true;

    return current;
  });

  return {
    name: normalizedName,
    removed,
    removedValues,
  };
}

export async function peekSecretValue(
  path: string,
  input: { environment: string; name: string },
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ environment: string; info: string; name: string; payload: string }> {
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedName = normalizeText(input.name);
  const normalizedEnvironment = normalizeText(input.environment);
  const file = getRequiredSecretFile(path);
  const value = getSecretValue(file, normalizedName, normalizedEnvironment);

  if (!value) {
    throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
  }

  const { info, payload } = await cryptoBackend.decrypt({
    armoredPrivateKeys: await getArmoredPrivateKeysForOwners(
      value.owners,
      `${normalizedName}.${normalizedEnvironment}`,
      dependencies,
    ),
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
  const normalizedName = normalizeText(input.name);
  const normalizedEnvironment = normalizeText(input.environment);
  let removedSecret = false;

  await modFile(path, async (current) => {
    const secret = current.secrets[normalizedName];

    if (!secret) {
      throw new Error(`Missing secret ${normalizedName}`);
    }

    if (!secret.values[normalizedEnvironment]) {
      throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
    }

    delete secret.values[normalizedEnvironment];

    if (!Object.keys(secret.values).length) {
      delete current.secrets[normalizedName];
      removedSecret = true;
    }

    return current;
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
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedName = normalizeText(input.name);
  const normalizedEnvironment = normalizeText(input.environment);
  const normalizedFingerprint = normalizeText(input.fingerprint);
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
  const { payload } = await cryptoBackend.decrypt({
    armoredPrivateKeys: await getArmoredPrivateKeysForOwners(
      value.owners,
      `${normalizedName}.${normalizedEnvironment}`,
      dependencies,
    ),
    ciphertext: value.encryptedValue,
  });
  const encryptedValue = await cryptoBackend.encrypt({
    plaintext: payload,
    recipients: getRequiredConfiguredKeys(file, nextOwners),
  });

  await modFile(path, async (current) => {
    const latestValue = getSecretValue(current, normalizedName, normalizedEnvironment);

    if (!latestValue) {
      throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
    }

    current.secrets[normalizedName]!.values[normalizedEnvironment] = createSecretDef(
      encryptedValue,
      nextOwners,
    );

    return current;
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
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedName = normalizeText(input.name);
  const normalizedEnvironment = normalizeText(input.environment);
  const normalizedFingerprint = normalizeText(input.fingerprint);
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
  const { payload } = await cryptoBackend.decrypt({
    armoredPrivateKeys: await getArmoredPrivateKeysForOwners(
      value.owners,
      `${normalizedName}.${normalizedEnvironment}`,
      dependencies,
    ),
    ciphertext: value.encryptedValue,
  });
  const encryptedValue = await cryptoBackend.encrypt({
    plaintext: payload,
    recipients: getRequiredConfiguredKeys(file, nextOwners),
  });

  await modFile(path, async (current) => {
    const latestValue = getSecretValue(current, normalizedName, normalizedEnvironment);

    if (!latestValue) {
      throw new Error(`Missing ${normalizedName}.${normalizedEnvironment}`);
    }

    current.secrets[normalizedName]!.values[normalizedEnvironment] = createSecretDef(
      encryptedValue,
      nextOwners,
    );

    return current;
  });

  return {
    environment: normalizedEnvironment,
    name: normalizedName,
    owners: nextOwners,
  };
}

export { getSecretEnvironments, getSecretNames, getSecretValue } from "./secret-helpers.ts";
export {
  type SecretsFileValidationIssue,
  type SecretsFileValidationResult,
  SecretsFileValidationError,
  formatValidationIssues,
  validateSecretsFile,
} from "./validation.ts";
