import type { PublicKey } from "./keys/types.ts";

export type Key = PublicKey;

export type SecretValue = {
  encryptedValue: string;
  owners: string[];
};

export type SecretDef = SecretValue;

export type Secret = {
  description?: string;
  values: Record<string, SecretValue>;
};

export type SecretsFile = {
  version: string;
  environments: string[];
  secrets: Record<string, Secret>;
  keys: Key[];
};
