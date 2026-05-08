import { createGpgCliProvider } from "./gpg-cli.ts";
import type { KeyIdentity, KeyProvider, PrivateKey, PublicKey } from "./types.ts";

export { createGpgCliProvider };
export type * from "./types.ts";

function getProviders(): KeyProvider[] {
  return [createGpgCliProvider()].filter((provider): provider is KeyProvider => provider !== null);
}

export const keyProviders = {
  all(): KeyProvider[] {
    return getProviders();
  },

  async listAllKeys(): Promise<KeyIdentity[]> {
    const keys = await Promise.all(getProviders().map((provider) => provider.listKeys()));
    return keys.flat();
  },

  async getPublicKey(fingerprint: string): Promise<PublicKey | null> {
    for (const provider of getProviders()) {
      const keys = await provider.listKeys();
      if (!keys.some((key) => key.fingerprint === fingerprint)) {
        continue;
      }

      return provider.getPublicKey(fingerprint);
    }

    return null;
  },

  async getPrivateKey(fingerprint: string): Promise<PrivateKey | null> {
    for (const provider of getProviders()) {
      const keys = await provider.listKeys();
      if (!keys.some((key) => key.fingerprint === fingerprint)) {
        continue;
      }

      return provider.getPrivateKey(fingerprint);
    }

    return null;
  },
};
