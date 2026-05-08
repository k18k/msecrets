import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as openpgp from "openpgp";

import type { WorkflowKeyAccess } from "../src/workflows.ts";
import type { SecretsFile } from "../src/types.ts";

export type TestKeyMaterial = {
  fingerprint: string;
  privateKey: string;
  publicKey: string;
  userIds: string[];
};

export function createTempSecretsPath() {
  const dir = mkdtempSync(join(tmpdir(), "msecrets-core-workflows-"));
  return join(dir, ".env.ms.json");
}

export function createFixtureFile(): SecretsFile {
  return {
    version: "2.0.0",
    environments: ["development", "staging"],
    keys: [
      {
        fingerprint: "owner-1",
        publicKey: "public-key-1",
        userIds: ["Owner One"],
      },
      {
        fingerprint: "owner-2",
        publicKey: "public-key-2",
        userIds: ["Owner Two"],
      },
    ],
    secrets: {
      API_KEY: {
        description: "api key",
        values: {
          development: {
            encryptedValue: "ciphertext-dev",
            owners: ["owner-1"],
          },
          staging: {
            encryptedValue: "ciphertext-staging",
            owners: ["owner-1", "owner-2"],
          },
        },
      },
      STAGING_ONLY: {
        values: {
          staging: {
            encryptedValue: "ciphertext-staging-only",
            owners: ["owner-1"],
          },
        },
      },
    },
  };
}

export async function generateTestKey(name: string): Promise<TestKeyMaterial> {
  const keyPair = await openpgp.generateKey({
    type: "curve25519",
    userIDs: [{ name }],
  });
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: keyPair.privateKey,
  });

  return {
    fingerprint: privateKey.getFingerprint(),
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    userIds: [name],
  };
}

export function createKeyAccess(keys: TestKeyMaterial[]): WorkflowKeyAccess {
  return {
    async listAllKeys() {
      return keys.map(({ fingerprint, userIds }) => ({
        fingerprint,
        userIds,
      }));
    },
    async getPublicKey(fingerprint) {
      const key = keys.find((candidate) => candidate.fingerprint === fingerprint);
      if (!key) {
        return null;
      }

      return {
        fingerprint: key.fingerprint,
        publicKey: key.publicKey,
        userIds: key.userIds,
      };
    },
    async getPrivateKey(fingerprint) {
      const key = keys.find((candidate) => candidate.fingerprint === fingerprint);
      if (!key) {
        return null;
      }

      return {
        fingerprint: key.fingerprint,
        privateKey: key.privateKey,
        userIds: key.userIds,
      };
    },
  };
}

export function createMissingPrivateKeyAccess(
  keys: TestKeyMaterial[],
  unavailableFingerprints: string[],
): WorkflowKeyAccess {
  const fullKeyAccess = createKeyAccess(keys);
  const missing = new Set(unavailableFingerprints);

  return {
    async listAllKeys() {
      return fullKeyAccess.listAllKeys();
    },
    async getPublicKey(fingerprint) {
      return fullKeyAccess.getPublicKey(fingerprint);
    },
    async getPrivateKey(fingerprint) {
      if (missing.has(fingerprint)) {
        return null;
      }

      return fullKeyAccess.getPrivateKey(fingerprint);
    },
  };
}
