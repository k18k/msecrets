import type { MSecretsAdapter } from "@msecrets/core/runtime";
import { type PrivateKey, readPrivateKeys, decrypt, readMessage } from "openpgp";

export type RawPKsAdapterOptions = {
  keys: string[];
};

export async function rawPKs({ keys }: RawPKsAdapterOptions): Promise<MSecretsAdapter> {
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
    async decrypt({ key, mode, value: { encryptedValue: armoredMessage, owners } }) {
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
              return decrypted.data;
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`raw-pks failed to decrypt ${key}.${mode}: ${message}`);
          }
        }
      }
      return null;
    },
  };
}
