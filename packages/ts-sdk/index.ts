import type { MSecretsAdapter } from "../core/src/runtime.ts";
import type { SecretsFile } from "../core/src/types.ts";
import { assertValidSecretsFile } from "../core/src/validation.ts";

export type { MSecretsAdapter, MSecretsAdapterContext } from "../core/src/runtime.ts";

export type MSecretsConfig = {
  secrets: SecretsFile;
  mode: string;
  adapters: MSecretsAdapter[];
};

export class MSecrets {
  private readonly cache = new Map<string, string>();
  private readonly config: MSecretsConfig;

  constructor(config: MSecretsConfig) {
    assertValidSecretsFile(config.secrets);
    this.config = config;

    if (!config.adapters.length) {
      throw new Error("At least one runtime adapter is required");
    }

    if (!config.secrets.environments.includes(config.mode)) {
      throw new Error(`Mode ${config.mode} not found in secrets file`);
    }
  }

  listKeys(): string[] {
    return Object.entries(this.config.secrets.secrets)
      .filter(([, secret]) => Boolean(secret.values[this.config.mode]))
      .map(([key]) => key);
  }

  has(key: string): boolean {
    return Boolean(this.config.secrets.secrets[key]?.values[this.config.mode]);
  }

  async get(key: string): Promise<string> {
    const cached = this.cache.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const secret = this.config.secrets.secrets[key];
    if (!secret) {
      throw new Error(`Secret ${key} not found`);
    }

    const value = secret.values[this.config.mode];
    if (!value) {
      throw new Error(`Secret ${key} is not defined for mode ${this.config.mode}`);
    }

    const errors: string[] = [];

    for (const adapter of this.config.adapters) {
      try {
        const decrypted = await adapter.decrypt({
          key,
          mode: this.config.mode,
          secret,
          value,
          secrets: this.config.secrets,
        });

        if (typeof decrypted !== "string") {
          continue;
        }

        this.cache.set(key, decrypted);
        return decrypted;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        errors.push(`[${adapter.name}] ${message}`);
      }
    }

    throw new Error(
      [
        `Failed to decrypt secret ${key} for mode ${this.config.mode}.`,
        errors.length ? errors.join("\n") : "No adapter could decrypt this value.",
      ].join("\n"),
    );
  }
}
