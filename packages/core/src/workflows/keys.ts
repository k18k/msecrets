import {
  addConfiguredKeyToFile,
  getConfiguredKey,
  getValuesOwnedByKey,
} from "../domain/keys.ts";
import { requireName } from "../domain/names.ts";
import { modifySecretsFile } from "../file-store.ts";
import { parseArmoredKeyMaterial } from "../key-material.ts";
import type { KeyIdentity, PublicKey } from "../keys/types.ts";
import {
  decryptThenEncryptForOwners,
  resolveWorkflowDependencies,
  type WorkflowDependencyOverrides,
} from "./deps.ts";
import { getWorkspaceSnapshot } from "./workspace.ts";

export async function listImportableKeys(
  path: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<KeyIdentity[]> {
  return (await getWorkspaceSnapshot(path, dependencies)).importableKeys;
}

export async function importConfiguredKey(
  path: string,
  fingerprint: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ alreadyImported: boolean; key: PublicKey }> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const normalizedFingerprint = requireName(fingerprint, "Key fingerprint");
  const publicKey = await keyAccess.getPublicKey(normalizedFingerprint);

  if (!publicKey) {
    throw new Error(`Key not found: ${normalizedFingerprint}`);
  }

  let alreadyImported = false;

  await modifySecretsFile(path, async (file) => {
    const result = addConfiguredKeyToFile(file, publicKey);
    alreadyImported = result.alreadyImported;
  });

  return { alreadyImported, key: publicKey };
}

export async function importConfiguredArmoredKey(
  path: string,
  armoredKey: string,
): Promise<{ alreadyImported: boolean; key: PublicKey }> {
  const parsedKey = await parseArmoredKeyMaterial(armoredKey);

  if (parsedKey.kind !== "public") {
    throw new Error("Expected an armored public key, but received a private key");
  }

  const key = {
    fingerprint: parsedKey.fingerprint,
    publicKey: parsedKey.publicKey,
    userIds: parsedKey.userIds,
  };
  let alreadyImported = false;

  await modifySecretsFile(path, async (file) => {
    const result = addConfiguredKeyToFile(file, key);
    alreadyImported = result.alreadyImported;
  });

  return { alreadyImported, key };
}

export async function removeConfiguredKey(
  path: string,
  fingerprint: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<{ fingerprint: string; removed: boolean; updatedValues: number }> {
  const normalizedFingerprint = requireName(fingerprint, "Key fingerprint");

  let removed = false;
  let updatedValues = 0;

  await modifySecretsFile(path, async (file) => {
    if (!getConfiguredKey(file, normalizedFingerprint)) {
      removed = false;
      return;
    }

    for (const { secretName, environment } of getValuesOwnedByKey(file, normalizedFingerprint)) {
      const secret = file.secrets[secretName];
      const value = secret?.values[environment];

      if (!secret || !value) {
        continue;
      }

      if (value.owners.length < 2) {
        throw new Error(
          `Cannot remove key ${normalizedFingerprint} because it is the only owner of ${secretName}.${environment}`,
        );
      }

      const nextOwners = value.owners.filter((owner) => owner !== normalizedFingerprint);
      secret.values[environment] = await decryptThenEncryptForOwners({
        dependencies,
        file,
        nextOwners,
        value,
        valueLabel: `${secretName}.${environment}`,
      });
      updatedValues += 1;
    }

    file.keys = file.keys.filter((key) => key.fingerprint !== normalizedFingerprint);
    removed = true;
  });

  return {
    fingerprint: normalizedFingerprint,
    removed,
    updatedValues,
  };
}
