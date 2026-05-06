import { gpgProvider } from "./gpg.provider.ts";
import type {
  KeyIdentity,
  KeyProvider,
  MSecretsPrivateKey,
  MSecretsPublicKey,
} from "./types.ts";

export type * from "./types.ts";

const providers = [gpgProvider].filter((provider): provider is KeyProvider => provider !== null);

export const keyProviders = {
  all(): KeyProvider[] {
    return [...providers];
  },

  async listAllKeys(): Promise<KeyIdentity[]> {
    const keys = await Promise.all(providers.map((provider) => provider.listKeys()));
    return keys.flat();
  },

  async getPublicKey(fingerprint: string): Promise<MSecretsPublicKey | null> {
    for (const provider of providers) {
      const keys = await provider.listKeys();

      if (!keys.some((key) => key.fingerprint === fingerprint)) {
        continue;
      }

      return provider.getPublicKey(fingerprint);
    }

    return null;
  },

  async getPrivateKey(fingerprint: string): Promise<MSecretsPrivateKey | null> {
    for (const provider of providers) {
      const keys = await provider.listKeys();

      if (!keys.some((key) => key.fingerprint === fingerprint)) {
        continue;
      }

      return provider.getPrivateKey(fingerprint);
    }

    return null;
  },
};
