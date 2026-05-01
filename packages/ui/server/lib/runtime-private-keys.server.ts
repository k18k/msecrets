import type { KeyIdentity, PrivateKey } from "@msecrets/core/providers";

const runtimePrivateKeys = new Map<string, PrivateKey>();

export function listRuntimePrivateKeys(): PrivateKey[] {
  return [...runtimePrivateKeys.values()];
}

export function listRuntimePrivateKeyIdentities(): KeyIdentity[] {
  return listRuntimePrivateKeys().map(({ fingerprint, userIds }) => ({
    fingerprint,
    userIds,
  }));
}

export function getRuntimePrivateKey(fingerprint: string): PrivateKey | null {
  return runtimePrivateKeys.get(fingerprint) ?? null;
}

export function upsertRuntimePrivateKey(privateKey: PrivateKey): void {
  runtimePrivateKeys.set(privateKey.fingerprint, privateKey);
}

export function clearRuntimePrivateKey(fingerprint: string): boolean {
  return runtimePrivateKeys.delete(fingerprint);
}

export function clearRuntimePrivateKeys(): void {
  runtimePrivateKeys.clear();
}
