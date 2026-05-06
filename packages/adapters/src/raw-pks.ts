import type { MSecretsAdapter } from "@msecrets/core/runtime";
import { type PrivateKey, readPrivateKeys, decrypt, readMessage } from "node-rpgp";

export type RawPKsAdapterOptions = {
  keys: string[];
};

export function rawPKs({ keys }: RawPKsAdapterOptions): MSecretsAdapter {
  const map = new Map<string, PrivateKey>();
  for (const key of keys) {
    let privateKeys: PrivateKey[];
    try {
      privateKeys = readPrivateKeys({ armoredKeys: key });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to load raw-pks private key: ${message}`);
    }

    for (const privateKey of privateKeys) {
      if (!privateKey.fingerprint) {
        throw new Error("Failed to load raw-pks private key: missing fingerprint");
      }
      map.set(privateKey.fingerprint, privateKey);
    }
  }
  return {
    name: "raw-pks",
    decrypt({ key, mode, value: { encryptedValue: armoredMessage, owners } }) {
      for (const owner of owners) {
        if (map.has(owner)) {
          try {
            const decrypted = decrypt({
              message: readMessage({
                armoredMessage,
              }),
              decryptionKeys: map.get(owner)!,
            });
            if (decrypted) {
              if (typeof decrypted.data === "string") {
                return decrypted.data;
              } else {
                return new TextDecoder().decode(decrypted.data);
              }
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
