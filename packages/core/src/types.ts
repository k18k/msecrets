import type { MSecretsPublicKey } from "./providers/types.ts";

export type Key = MSecretsPublicKey;

export type SecretDef = {
  encryptedValue: string;
  owners: string[];
};

export type Secret = {
  description?: string;
  values: Record<string, SecretDef>;
};

export type SecretsFile = {
  version: string;
  environments: string[];
  secrets: Record<string, Secret>;
  keys: Key[];
};
