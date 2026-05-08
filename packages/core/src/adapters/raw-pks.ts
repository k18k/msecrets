import { type PrivateKey, readPrivateKeys, decrypt, readMessage } from "openpgp";

import { normalizeDecryptedPayload } from "../crypto.ts";
import type { MSecretsAdapter } from "../runtime.ts";

export type RawPKsAdapterOptions = {
  rawPrivateKeys?: string[];
  keys?: string[];
};

export async function rawPrivateKeys(options: RawPKsAdapterOptions): Promise<MSecretsAdapter> {
  const keys = options.rawPrivateKeys ?? options.keys ?? [];
  const map = new Map<string, PrivateKey>();
  for (const key of keys) {
    let privateKeys: PrivateKey[];
    try {
      privateKeys = await readPrivateKeys({ armoredKeys: key });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to load raw-pks private key: ${message}`);
    }

    for (const privateKey of privateKeys) {
      map.set(privateKey.getFingerprint(), privateKey);
    }
  }
  return {
    name: "raw-pks",
    async decrypt({ environment, key, value: { encryptedValue: armoredMessage, owners } }) {
      for (const owner of owners) {
        if (map.has(owner)) {
          try {
            const decrypted = await decrypt({
              message: await readMessage({
                armoredMessage,
              }),
              decryptionKeys: map.get(owner)!,
            });
            if (decrypted) {
              return normalizeDecryptedPayload(decrypted.data);
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`raw-pks failed to decrypt ${key}.${environment}: ${message}`);
          }
        }
      }
      return null;
    },
  };
}

export const rawPKs = rawPrivateKeys;
