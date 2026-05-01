import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import type { MSecretsAdapter } from "@msecrets/core/runtime";

import { cleanupDir, createTempGpgHome, decryptWithGpg, importPrivateKey } from "./shared.ts";

const DEFAULT_KEY_FILENAMES = [
  "msecrets-private-key.asc",
  "msecrets-private-key.gpg",
  "msecrets-private-key",
];

export type DockerSecretsAdapterOptions = {
  directory?: string;
  keyFilenames?: string[];
};

export function dockerSecrets(options: DockerSecretsAdapterOptions = {}): MSecretsAdapter {
  const directory = options.directory ?? "/run/secrets";
  const keyFilenames = options.keyFilenames ?? DEFAULT_KEY_FILENAMES;
  let homedir: string | null = null;

  process.once("exit", () => {
    if (homedir) {
      cleanupDir(homedir);
    }
  });

  function ensureKeyring(): string {
    if (homedir) {
      return homedir;
    }

    const nextHomedir = createTempGpgHome();
    const importedFrom: string[] = [];

    try {
      for (const filename of keyFilenames) {
        const path = join(directory, filename);
        const entry = statSync(path, { throwIfNoEntry: false });

        if (!entry?.isFile()) {
          continue;
        }

        importPrivateKey(readFileSync(path), { homedir: nextHomedir });
        importedFrom.push(path);
      }
    } catch (error) {
      cleanupDir(nextHomedir);
      throw error;
    }

    if (!importedFrom.length) {
      cleanupDir(nextHomedir);
      throw new Error(
        `No Docker secret private key files found in ${directory}. Tried: ${keyFilenames.join(", ")}`,
      );
    }

    homedir = nextHomedir;
    return homedir;
  }

  return {
    name: "docker-secrets",
    decrypt({ value }) {
      return decryptWithGpg(value.encryptedValue, { homedir: ensureKeyring() });
    },
  };
}
