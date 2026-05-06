import assert from "node:assert";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import * as openpgp from "openpgp";

import { getSecretsFile } from "../core/src/secrets-file.ts";
import type { WorkflowKeyAccess } from "../core/src/workflows.ts";
import {
  createSecret,
  importConfiguredKey,
  initializeSecretsFile,
  revokeSecretValue,
  shareSecretValue,
} from "../core/src/workflows.ts";

import { rawPKs } from "./adapters/raw-pks.ts";

import { MSecrets } from "./index.ts";

type TestKeyMaterial = {
  fingerprint: string;
  privateKey: string;
  publicKey: string;
  userIds: string[];
};

function createTempSecretsPath() {
  const dir = mkdtempSync(join(tmpdir(), "msecrets-release-workflow-"));
  return join(dir, ".env.ms.json");
}

async function generateTestKey(name: string): Promise<TestKeyMaterial> {
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

function createKeyAccess(keys: TestKeyMaterial[]): WorkflowKeyAccess {
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

test("non-GPG release workflow covers authoring, sharing, revocation, and SDK decrypt", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const keyAccess = createKeyAccess([ownerA, ownerB]);
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);

  await importConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess });
  await importConfiguredKey(secretsPath, ownerB.fingerprint, { keyAccess });

  await createSecret(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
      plaintextValue: "release-secret",
    },
    { keyAccess },
  );

  let file = getSecretsFile(secretsPath);
  assert.deepEqual(file.secrets["API_KEY"]?.values["development"]?.owners, [ownerA.fingerprint]);

  const ownerAClient = new MSecrets({
    mode: "development",
    adapters: [
      await rawPKs({
        keys: [ownerA.privateKey],
      }),
    ],
    secrets: file,
  });

  assert.equal(await ownerAClient.get("API_KEY"), "release-secret");

  await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerB.fingerprint,
      name: "API_KEY",
    },
    { keyAccess },
  );

  file = getSecretsFile(secretsPath);
  assert.deepEqual(file.secrets["API_KEY"]?.values["development"]?.owners, [
    ownerA.fingerprint,
    ownerB.fingerprint,
  ]);

  const ownerBClient = new MSecrets({
    mode: "development",
    adapters: [
      await rawPKs({
        keys: [ownerB.privateKey],
      }),
    ],
    secrets: file,
  });

  assert.equal(await ownerBClient.get("API_KEY"), "release-secret");

  await revokeSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
    },
    { keyAccess },
  );

  file = getSecretsFile(secretsPath);
  assert.deepEqual(file.secrets["API_KEY"]?.values["development"]?.owners, [ownerB.fingerprint]);

  const revokedOwnerClient = new MSecrets({
    mode: "development",
    adapters: [
      await rawPKs({
        keys: [ownerA.privateKey],
      }),
    ],
    secrets: file,
  });

  await assert.rejects(
    () => revokedOwnerClient.get("API_KEY"),
    /Failed to decrypt secret API_KEY for mode development\.\nNo adapter could decrypt this value\./,
  );

  const remainingOwnerClient = new MSecrets({
    mode: "development",
    adapters: [
      await rawPKs({
        keys: [ownerB.privateKey],
      }),
    ],
    secrets: file,
  });

  assert.equal(await remainingOwnerClient.get("API_KEY"), "release-secret");
});
