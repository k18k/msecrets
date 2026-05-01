import { execFileSync, spawnSync } from "node:child_process";

import { parseKeys } from "../gpg.ts";
import type { KeyProvider, PrivateKey, PublicKey } from "./types.ts";

function hasGpgBinary(): boolean {
  return spawnSync("which", ["gpg"], { stdio: "ignore" }).status === 0;
}

function runGpg(args: string[]): string {
  return execFileSync("gpg", args, { encoding: "utf8" }).trim();
}

function createGpgProvider(): KeyProvider | null {
  if (!hasGpgBinary()) {
    return null;
  }

  return {
    name: "gpg",
    isAvailable: hasGpgBinary,
    async listKeys() {
      return parseKeys(runGpg(["--list-secret-keys", "--with-colons"]));
    },
    async getPublicKey(fingerprint: string): Promise<PublicKey> {
      const keys = await this.listKeys();
      const key = keys.find((candidate) => candidate.fingerprint === fingerprint);

      if (!key) {
        throw new Error(`Key not found: ${fingerprint}`);
      }

      return {
        ...key,
        publicKey: runGpg(["--export", "--armor", fingerprint]),
      };
    },
    async getPrivateKey(fingerprint: string): Promise<PrivateKey> {
      const keys = await this.listKeys();
      const key = keys.find((candidate) => candidate.fingerprint === fingerprint);

      if (!key) {
        throw new Error(`Key not found: ${fingerprint}`);
      }

      return {
        ...key,
        privateKey: runGpg(["--export-secret-keys", "--armor", fingerprint]),
      };
    },
  };
}

export const gpgProvider: KeyProvider | null = createGpgProvider();
