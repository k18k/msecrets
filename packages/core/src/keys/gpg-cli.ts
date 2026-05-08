import { execFileSync, spawnSync } from "node:child_process";

import type { KeyIdentity, KeyProvider, PrivateKey, PublicKey } from "./types.ts";

function parseKeys(raw: string): KeyIdentity[] {
  const lines = raw.split("\n");
  const keys: KeyIdentity[] = [];
  let current: Partial<KeyIdentity> | null = null;

  for (const line of lines) {
    const parts = line.split(":");
    const type = parts[0];

    if (type === "sec") {
      if (current?.fingerprint) {
        keys.push({ fingerprint: current.fingerprint, userIds: current.userIds ?? [] });
      }
      current = { userIds: [] };
    }

    if (!current) {
      continue;
    }

    if (type === "uid" && parts[9]) {
      current.userIds ??= [];
      current.userIds.push(parts[9]);
    }

    if (type === "fpr" && parts[9]) {
      current.fingerprint = parts[9];
    }
  }

  if (current?.fingerprint) {
    keys.push({ fingerprint: current.fingerprint, userIds: current.userIds ?? [] });
  }

  return keys;
}

let gpgAvailability: boolean | null = null;

function hasGpgBinary(): boolean {
  if (gpgAvailability !== null) {
    return gpgAvailability;
  }
  gpgAvailability = spawnSync("which", ["gpg"], { stdio: "ignore" }).status === 0;
  return gpgAvailability;
}

function runGpg(args: string[]): string {
  return execFileSync("gpg", args, { encoding: "utf8" }).trim();
}

export function createGpgCliProvider(): KeyProvider | null {
  if (!hasGpgBinary()) {
    return null;
  }

  return {
    name: "gpg-cli",
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
