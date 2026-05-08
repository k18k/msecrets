import { defaultCryptoBackend, type CryptoBackend } from "../crypto/index.ts";
import { requireName } from "../domain/names.ts";
import {
  getConfiguredKey,
  getConfiguredKeyFingerprints,
  getRequiredConfiguredKeys,
} from "../domain/keys.ts";
import { keyProviders } from "../keys/index.ts";
import type { KeyIdentity, PrivateKey, PublicKey } from "../keys/types.ts";
import { getSecretsFile, hasSecretsFile } from "../file-store.ts";
import type { SecretDef, SecretsFile } from "../model.ts";
import { CURRENT_SECRETS_FILE_VERSION } from "../validation/index.ts";

export type WorkflowKeyAccess = {
  listAllKeys(): Promise<KeyIdentity[]>;
  getPublicKey(fingerprint: string): Promise<PublicKey | null>;
  getPrivateKey(fingerprint: string): Promise<PrivateKey | null>;
};

export type WorkflowDependencies = {
  cryptoBackend: CryptoBackend;
  keyAccess: WorkflowKeyAccess;
};

export type WorkflowDependencyOverrides = Partial<WorkflowDependencies>;

export function createEmptySecretsFile(): SecretsFile {
  return {
    version: CURRENT_SECRETS_FILE_VERSION,
    environments: ["development"],
    keys: [],
    secrets: {},
  };
}

export function resolveWorkflowDependencies(
  dependencies?: WorkflowDependencyOverrides,
): WorkflowDependencies {
  return {
    cryptoBackend: dependencies?.cryptoBackend ?? defaultCryptoBackend,
    keyAccess: dependencies?.keyAccess ?? keyProviders,
  };
}

export function getRequiredSecretFile(path: string): SecretsFile {
  if (!hasSecretsFile(path)) {
    throw new Error(`Secrets file not found: ${path}`);
  }

  return getSecretsFile(path);
}

export function normalizeText(value: string): string {
  return value.trim();
}

export function validateEnvironment(file: SecretsFile, environment: string) {
  if (!file.environments.includes(environment)) {
    throw new Error(`Environment not found: ${environment}`);
  }
}

export function getRequiredSecret(file: SecretsFile, name: string) {
  const secret = file.secrets[name];

  if (!secret) {
    throw new Error(`Missing secret ${name}`);
  }

  return secret;
}

export function resolveOwners(file: SecretsFile, owners: string[]): string[] {
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

export async function getArmoredPrivateKeysForOwners(
  owners: string[],
  valueLabel: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<string[]> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const normalizedOwners = [...new Set(owners.map((owner) => owner.trim()).filter(Boolean))];

  if (!normalizedOwners.length) {
    throw new Error(`No owners configured for ${valueLabel}`);
  }

  const privateKeys = await Promise.all(
    normalizedOwners.map((owner) => keyAccess.getPrivateKey(owner)),
  );
  const availablePrivateKeys = privateKeys.filter(
    (privateKey): privateKey is PrivateKey => privateKey !== null,
  );

  if (!availablePrivateKeys.length) {
    throw new Error(`Private key not found for any owner of ${valueLabel}`);
  }

  return availablePrivateKeys.map((privateKey) => privateKey.privateKey);
}

export async function getEncryptedSecretValue(
  file: SecretsFile,
  fingerprint: string,
  plaintextValue: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ encryptedValue: string; fingerprint: string }> {
  const { cryptoBackend } = resolveWorkflowDependencies(dependencies);
  const normalizedFingerprint = requireName(fingerprint, "A key fingerprint");
  const normalizedPlaintext = plaintextValue;

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

export async function decryptThenEncryptForOwners(args: {
  dependencies?: WorkflowDependencyOverrides;
  file: SecretsFile;
  nextOwners: string[];
  value: SecretDef;
  valueLabel: string;
}): Promise<SecretDef> {
  const { cryptoBackend } = resolveWorkflowDependencies(args.dependencies);
  const nextOwners = resolveOwners(args.file, args.nextOwners);
  const { payload } = await cryptoBackend.decrypt({
    armoredPrivateKeys: await getArmoredPrivateKeysForOwners(
      args.value.owners,
      args.valueLabel,
      args.dependencies,
    ),
    ciphertext: args.value.encryptedValue,
  });
  const encryptedValue = await cryptoBackend.encrypt({
    plaintext: payload,
    recipients: getRequiredConfiguredKeys(args.file, nextOwners),
  });

  return {
    encryptedValue,
    owners: nextOwners,
  };
}
