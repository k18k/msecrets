import {
  keyProviders,
  type KeyIdentity,
  type PrivateKey,
  type PublicKey,
} from "@msecrets/core/providers";
import type { WorkflowKeyAccess } from "@msecrets/core/workflows";

import {
  getRuntimePrivateKey,
  listRuntimePrivateKeyIdentities,
} from "./runtime-private-keys.server.ts";

export function hasOptionalGpgImport(): boolean {
  return keyProviders.all().some((provider) => provider.isAvailable());
}

export async function listOptionalGpgKeys(): Promise<KeyIdentity[]> {
  if (!hasOptionalGpgImport()) {
    return [];
  }

  return keyProviders.listAllKeys();
}

export async function getOptionalGpgPublicKey(fingerprint: string): Promise<PublicKey | null> {
  if (!hasOptionalGpgImport()) {
    return null;
  }

  return keyProviders.getPublicKey(fingerprint);
}

export async function getOptionalGpgPrivateKey(fingerprint: string): Promise<PrivateKey | null> {
  if (!hasOptionalGpgImport()) {
    return null;
  }

  return keyProviders.getPrivateKey(fingerprint);
}

export const uiKeyAccess: WorkflowKeyAccess = {
  async listAllKeys() {
    return listRuntimePrivateKeyIdentities();
  },
  async getPublicKey(fingerprint: string) {
    return getOptionalGpgPublicKey(fingerprint);
  },
  async getPrivateKey(fingerprint: string) {
    return getRuntimePrivateKey(fingerprint);
  },
};
