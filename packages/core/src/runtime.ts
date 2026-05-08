import type { Secret, SecretValue, SecretsFile } from "./model.ts";

export type MSecretsAdapterContext = {
  key: string;
  environment: string;
  /** @deprecated Use environment instead. */
  mode: string;
  secret: Secret;
  value: SecretValue;
  secrets: SecretsFile;
};

export type MSecretsAdapter = {
  name: string;
  decrypt(
    context: MSecretsAdapterContext,
  ): Promise<string | null | undefined> | string | null | undefined;
};
