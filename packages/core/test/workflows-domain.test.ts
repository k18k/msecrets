import assert from "node:assert";
import { test } from "node:test";

import type { CryptoBackend } from "../src/crypto.ts";
import { getSecretsFile, writeSecretsFile } from "../src/secrets-file.ts";
import {
  revokeSecretValue,
  shareSecretValue,
  type WorkflowKeyAccess,
} from "../src/workflows.ts";
import { createFixtureFile, createTempSecretsPath } from "./helpers.ts";

const fakeCryptoBackend: CryptoBackend = {
  async decrypt({ ciphertext }) {
    return { payload: ciphertext };
  },
  async encrypt({ plaintext, recipients }) {
    return `encrypted:${recipients.map((recipient) => recipient.fingerprint).join(",")}:${plaintext}`;
  },
};

const fakeKeyAccess: WorkflowKeyAccess = {
  async listAllKeys() {
    return [];
  },
  async getPublicKey() {
    return null;
  },
  async getPrivateKey(fingerprint) {
    return {
      fingerprint,
      privateKey: `private-key-${fingerprint}`,
      userIds: [fingerprint],
    };
  },
};

test("share and revoke workflows can exercise owner changes with fake crypto", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  const shared = await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: "owner-2",
      name: "API_KEY",
    },
    { cryptoBackend: fakeCryptoBackend, keyAccess: fakeKeyAccess },
  );

  assert.deepEqual(shared.owners, ["owner-1", "owner-2"]);
  assert.equal(
    getSecretsFile(secretsPath).secrets["API_KEY"]?.values["development"]?.encryptedValue,
    "encrypted:owner-1,owner-2:ciphertext-dev",
  );

  const revoked = await revokeSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: "owner-1",
      name: "API_KEY",
    },
    { cryptoBackend: fakeCryptoBackend, keyAccess: fakeKeyAccess },
  );

  assert.deepEqual(revoked.owners, ["owner-2"]);
  assert.equal(
    getSecretsFile(secretsPath).secrets["API_KEY"]?.values["development"]?.encryptedValue,
    "encrypted:owner-2:encrypted:owner-1,owner-2:ciphertext-dev",
  );
});
