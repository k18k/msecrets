import type { Secret, SecretDef, SecretsFile } from "./types.ts";

export type MSecretsAdapterContext = {
  key: string;
  mode: string;
  secret: Secret;
  value: SecretDef;
  secrets: SecretsFile;
};

export type MSecretsAdapter = {
  name: string;
  decrypt(
    context: MSecretsAdapterContext,
  ): Promise<string | null | undefined> | string | null | undefined;
};
