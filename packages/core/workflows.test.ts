import assert from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { generateKey, readPrivateKey } from "node-rpgp";

import { openPgpCryptoBackend } from "./src/crypto.ts";
import { getSecretsFile, writeSecretsFile } from "./src/secrets-file.ts";
import type { SecretsFile } from "./src/types.d.ts";
import {
  addEnvironment,
  auditWorkspace,
  createSecret,
  deleteSecret,
  getWorkspaceSnapshot,
  importConfiguredArmoredKey,
  importConfiguredKey,
  initializeSecretsFile,
  listEnvironments,
  listImportableKeys,
  planEnvironmentRemoval,
  peekSecretValue,
  removeEnvironment,
  removeConfiguredKey,
  removeSecretValue,
  renameEnvironment,
  renameSecret,
  revokeSecretValue,
  setSecretValue,
  shareSecretValue,
  type WorkflowKeyAccess,
} from "./src/workflows.ts";

type TestKeyMaterial = {
  fingerprint: string;
  privateKey: string;
  publicKey: string;
  userIds: string[];
};

function createTempSecretsPath() {
  const dir = mkdtempSync(join(tmpdir(), "msecrets-core-workflows-"));
  return join(dir, ".env.ms.json");
}

function createFixtureFile(): SecretsFile {
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

async function generateTestKey(name: string): Promise<TestKeyMaterial> {
  const keyPair = generateKey({
    type: "ecc",
    userIDs: [{ name }],
  });
  const privateKey = readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  if (!privateKey.fingerprint) {
    throw new Error("Generated test key is missing a fingerprint");
  }

  return {
    fingerprint: privateKey.fingerprint,
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

function createMissingPrivateKeyAccess(
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

test("initializeSecretsFile creates a versioned default workspace", () => {
  const secretsPath = createTempSecretsPath();

  const first = initializeSecretsFile(secretsPath);
  const second = initializeSecretsFile(secretsPath);
  const file = getSecretsFile(secretsPath);

  assert.deepEqual(first, { created: true });
  assert.deepEqual(second, { created: false });
  assert.equal(file.version, "2.0.0");
  assert.deepEqual(file.environments, ["development"]);
  assert.deepEqual(file.keys, []);
  assert.deepEqual(file.secrets, {});
});

test("workspace snapshot and importable key listing use injected key access", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const ownerC = await generateTestKey("Owner C");
  const keyAccess = createKeyAccess([ownerA, ownerB, ownerC]);
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);
  await importConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess });
  await importConfiguredKey(secretsPath, ownerB.fingerprint, { keyAccess });

  const snapshot = await getWorkspaceSnapshot(secretsPath, { keyAccess });

  assert.equal(snapshot.exists, true);
  assert.deepEqual(
    snapshot.localKeys.map((key) => key.fingerprint),
    [ownerA.fingerprint, ownerB.fingerprint, ownerC.fingerprint],
  );
  assert.deepEqual(
    snapshot.importableKeys.map((key) => key.fingerprint),
    [ownerC.fingerprint],
  );

  const importableKeys = await listImportableKeys(secretsPath, { keyAccess });
  assert.deepEqual(
    importableKeys.map((key) => key.fingerprint),
    [ownerC.fingerprint],
  );
});

test("importConfiguredArmoredKey imports public keys and rejects invalid key material", async () => {
  const ownerA = await generateTestKey("Owner A");
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);

  const firstImport = await importConfiguredArmoredKey(secretsPath, ownerA.publicKey);
  assert.equal(firstImport.alreadyImported, false);
  assert.equal(firstImport.key.fingerprint, ownerA.fingerprint);
  assert.deepEqual(firstImport.key.userIds, ownerA.userIds);
  assert.match(firstImport.key.publicKey, /BEGIN PGP PUBLIC KEY BLOCK/);

  const secondImport = await importConfiguredArmoredKey(secretsPath, ownerA.publicKey);
  assert.equal(secondImport.alreadyImported, true);
  assert.equal(secondImport.key.fingerprint, ownerA.fingerprint);
  assert.deepEqual(secondImport.key.userIds, ownerA.userIds);

  await assert.rejects(
    () => importConfiguredArmoredKey(secretsPath, ownerA.privateKey),
    /Expected an armored public key, but received a private key/,
  );
  await assert.rejects(
    () => importConfiguredArmoredKey(secretsPath, "not-a-key"),
    /Failed to parse armored PGP key:/,
  );
});

test("createSecret and setSecretValue only require configured public keys", async () => {
  const ownerA = await generateTestKey("Owner A");
  const secretsPath = createTempSecretsPath();
  const noPrivateKeyAccess = createKeyAccess([]);

  initializeSecretsFile(secretsPath);
  await importConfiguredArmoredKey(secretsPath, ownerA.publicKey);

  assert.deepEqual(
    await createSecret(
      secretsPath,
      {
        environment: "development",
        fingerprint: ownerA.fingerprint,
        name: "API_KEY",
        plaintextValue: "dev-secret",
      },
      { keyAccess: noPrivateKeyAccess },
    ),
    {
      hasInitialValue: true,
      name: "API_KEY",
    },
  );

  assert.deepEqual(
    await setSecretValue(
      secretsPath,
      {
        environment: "development",
        fingerprint: ownerA.fingerprint,
        name: "API_KEY",
        plaintextValue: "next-secret",
      },
      { keyAccess: noPrivateKeyAccess },
    ),
    {
      environment: "development",
      name: "API_KEY",
    },
  );
});

test("auditWorkspace reports missing file and local key availability through injected key access", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const keyAccess = createKeyAccess([ownerA, ownerB]);
  const secretsPath = createTempSecretsPath();

  const report = await auditWorkspace(secretsPath, { keyAccess });

  assert.equal(report.exists, false);
  assert.equal(report.file, null);
  assert.equal(report.valid, false);
  assert.equal(report.summary.localKeyCount, 2);
  assert.equal(report.summary.importableKeyCount, 2);
  assert.ok(report.findings.some((finding) => finding.code === "workspace_missing"));
});

test("auditWorkspace reports invalid file issues and falls back to local importable keys", async () => {
  const ownerA = await generateTestKey("Owner A");
  const keyAccess = createKeyAccess([ownerA]);
  const secretsPath = createTempSecretsPath();

  writeFileSync(
    secretsPath,
    JSON.stringify(
      {
        version: "2.0.0",
        environments: ["development", "staging"],
        keys: [
          {
            fingerprint: ownerA.fingerprint,
            publicKey: ownerA.publicKey,
            userIds: ownerA.userIds,
          },
          {
            fingerprint: "missing-local-owner",
            publicKey:
              "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmissing\n-----END PGP PUBLIC KEY BLOCK-----",
            userIds: ["Missing Local Owner"],
          },
        ],
        secrets: {
          API_KEY: {
            values: {
              qa: {
                encryptedValue: "ciphertext",
                owners: ["missing-local-owner", "unknown-owner"],
              },
            },
          },
        },
      },
      null,
      2,
    ),
  );

  const report = await auditWorkspace(secretsPath, { keyAccess });

  assert.equal(report.exists, true);
  assert.equal(report.valid, false);
  assert.equal(report.summary.configuredKeyCount, 0);
  assert.equal(report.summary.localKeyCount, 1);
  assert.ok(report.findings.some((finding) => finding.code === "secret_environment_unknown"));
  assert.ok(report.findings.some((finding) => finding.code === "secret_value_owner_unknown"));
  assert.deepEqual(
    report.importableKeys.map((key) => key.fingerprint),
    [ownerA.fingerprint],
  );
});

test("auditWorkspace reports configured keys missing locally for a valid file", async () => {
  const ownerA = await generateTestKey("Owner A");
  const keyAccess = createKeyAccess([ownerA]);
  const secretsPath = createTempSecretsPath();

  writeSecretsFile(secretsPath, {
    version: "2.0.0",
    environments: ["development"],
    keys: [
      {
        fingerprint: ownerA.fingerprint,
        publicKey: ownerA.publicKey,
        userIds: ownerA.userIds,
      },
      {
        fingerprint: "missing-local-owner",
        publicKey:
          "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmissing\n-----END PGP PUBLIC KEY BLOCK-----",
        userIds: ["Missing Local Owner"],
      },
    ],
    secrets: {},
  });

  const report = await auditWorkspace(secretsPath, { keyAccess });

  assert.equal(report.exists, true);
  assert.equal(report.valid, true);
  assert.equal(report.summary.configuredKeyCount, 2);
  assert.ok(report.findings.some((finding) => finding.code === "configured_key_missing_locally"));
  assert.deepEqual(report.importableKeys, []);
});

test("auditWorkspace warns when no local keys are available for an otherwise valid file", async () => {
  const secretsPath = createTempSecretsPath();

  writeSecretsFile(secretsPath, {
    version: "2.0.0",
    environments: ["development"],
    keys: [],
    secrets: {},
  });

  const report = await auditWorkspace(secretsPath, { keyAccess: createKeyAccess([]) });

  assert.equal(report.exists, true);
  assert.equal(report.valid, true);
  assert.ok(report.findings.some((finding) => finding.code === "local_keys_missing_all"));
  assert.equal(report.summary.localKeyCount, 0);
});

test("environment workflows add rename and remove with cleanup", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  assert.deepEqual(listEnvironments(secretsPath), ["development", "staging"]);
  assert.deepEqual(await addEnvironment(secretsPath, " preview "), {
    added: true,
    environment: "preview",
  });
  assert.deepEqual(await addEnvironment(secretsPath, "preview"), {
    added: false,
    environment: "preview",
  });

  assert.deepEqual(planEnvironmentRemoval(secretsPath, "staging"), {
    environment: "staging",
    exists: true,
    secretCount: 2,
    secrets: ["API_KEY", "STAGING_ONLY"],
  });

  assert.deepEqual(
    await renameEnvironment(secretsPath, {
      environment: "preview",
      nextEnvironment: "qa",
    }),
    {
      environment: "preview",
      nextEnvironment: "qa",
      renamed: true,
    },
  );
  assert.deepEqual(
    await renameEnvironment(secretsPath, {
      environment: "qa",
      nextEnvironment: "qa",
    }),
    {
      environment: "qa",
      nextEnvironment: "qa",
      renamed: false,
    },
  );

  await assert.rejects(
    () =>
      renameEnvironment(secretsPath, {
        environment: "missing",
        nextEnvironment: "prod",
      }),
    /Environment not found: missing/,
  );

  await assert.rejects(
    () =>
      renameEnvironment(secretsPath, {
        environment: "qa",
        nextEnvironment: "development",
      }),
    /Environment already exists: development/,
  );

  assert.deepEqual(await removeEnvironment(secretsPath, "staging"), {
    environment: "staging",
    removed: true,
    removedSecrets: ["STAGING_ONLY"],
    removedValues: 2,
  });

  const file = getSecretsFile(secretsPath);
  assert.deepEqual(file.environments, ["development", "qa"]);
  assert.equal(file.secrets["STAGING_ONLY"], undefined);
  assert.equal(file.secrets["API_KEY"]?.values["staging"], undefined);
});

test("secret workflows rename remove values and delete whole secrets", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  assert.deepEqual(
    await renameSecret(secretsPath, {
      name: "API_KEY",
      nextName: "RENAMED_API_KEY",
    }),
    {
      name: "RENAMED_API_KEY",
      previousName: "API_KEY",
      renamed: true,
    },
  );

  assert.deepEqual(
    await renameSecret(secretsPath, {
      name: "RENAMED_API_KEY",
      nextName: "RENAMED_API_KEY",
    }),
    {
      name: "RENAMED_API_KEY",
      previousName: "RENAMED_API_KEY",
      renamed: false,
    },
  );

  await assert.rejects(
    () =>
      renameSecret(secretsPath, {
        name: "RENAMED_API_KEY",
        nextName: "STAGING_ONLY",
      }),
    /Secret already exists: STAGING_ONLY/,
  );

  assert.deepEqual(
    await removeSecretValue(secretsPath, {
      name: "RENAMED_API_KEY",
      environment: "development",
    }),
    {
      environment: "development",
      name: "RENAMED_API_KEY",
      removedSecret: false,
    },
  );

  assert.deepEqual(
    await removeSecretValue(secretsPath, {
      name: "STAGING_ONLY",
      environment: "staging",
    }),
    {
      environment: "staging",
      name: "STAGING_ONLY",
      removedSecret: true,
    },
  );

  assert.deepEqual(await deleteSecret(secretsPath, "RENAMED_API_KEY"), {
    name: "RENAMED_API_KEY",
    removed: true,
    removedValues: 1,
  });

  assert.deepEqual(await deleteSecret(secretsPath, "RENAMED_API_KEY"), {
    name: "RENAMED_API_KEY",
    removed: false,
    removedValues: 0,
  });

  const file = getSecretsFile(secretsPath);
  assert.deepEqual(file.secrets, {});
});

test("configured key removal fails when the key is the only owner of a value", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  await assert.rejects(
    () => removeConfiguredKey(secretsPath, "owner-1"),
    /Cannot remove key owner-1 because it is the only owner of API_KEY.development/,
  );
});

test("configured key removal is a no-op when the key is not configured", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  assert.deepEqual(await removeConfiguredKey(secretsPath, "missing-owner"), {
    fingerprint: "missing-owner",
    removed: false,
    updatedValues: 0,
  });
});

test("configured key removal re-encrypts affected values for remaining owners", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const ownerC = await generateTestKey("Owner C");
  const keyAccess = createKeyAccess([ownerA, ownerB, ownerC]);
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);
  await addEnvironment(secretsPath, "staging");

  await importConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess });
  await importConfiguredKey(secretsPath, ownerB.fingerprint, { keyAccess });
  await importConfiguredKey(secretsPath, ownerC.fingerprint, { keyAccess });

  await createSecret(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
      plaintextValue: "dev-secret",
    },
    { keyAccess },
  );
  await setSecretValue(
    secretsPath,
    {
      environment: "staging",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
      plaintextValue: "staging-secret",
    },
    { keyAccess },
  );
  await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerB.fingerprint,
      name: "API_KEY",
    },
    { keyAccess },
  );
  await shareSecretValue(
    secretsPath,
    {
      environment: "staging",
      fingerprint: ownerC.fingerprint,
      name: "API_KEY",
    },
    { keyAccess },
  );

  assert.deepEqual(await removeConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess }), {
    fingerprint: ownerA.fingerprint,
    removed: true,
    updatedValues: 2,
  });

  const file = getSecretsFile(secretsPath);
  assert.equal(
    file.keys.some((key) => key.fingerprint === ownerA.fingerprint),
    false,
  );
  assert.deepEqual(file.secrets["API_KEY"]?.values["development"]?.owners, [ownerB.fingerprint]);
  assert.deepEqual(file.secrets["API_KEY"]?.values["staging"]?.owners, [ownerC.fingerprint]);

  const devCiphertext = file.secrets["API_KEY"]?.values["development"]?.encryptedValue ?? "";
  const stagingCiphertext = file.secrets["API_KEY"]?.values["staging"]?.encryptedValue ?? "";

  const devDecrypted = await openPgpCryptoBackend.decrypt({
    armoredPrivateKeys: [ownerB.privateKey],
    ciphertext: devCiphertext,
  });
  const stagingDecrypted = await openPgpCryptoBackend.decrypt({
    armoredPrivateKeys: [ownerC.privateKey],
    ciphertext: stagingCiphertext,
  });

  assert.equal(devDecrypted.payload, "dev-secret");
  assert.equal(stagingDecrypted.payload, "staging-secret");

  await assert.rejects(() =>
    openPgpCryptoBackend.decrypt({
      armoredPrivateKeys: [ownerA.privateKey],
      ciphertext: devCiphertext,
    }),
  );
});

test("configured key removal leaves the file unchanged when re-encryption cannot proceed", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const fullKeyAccess = createKeyAccess([ownerA, ownerB]);
  const missingPrivateKeyAccess = createMissingPrivateKeyAccess(
    [ownerA, ownerB],
    [ownerA.fingerprint, ownerB.fingerprint],
  );
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);
  await importConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess: fullKeyAccess });
  await importConfiguredKey(secretsPath, ownerB.fingerprint, { keyAccess: fullKeyAccess });

  await createSecret(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
      plaintextValue: "release-secret",
    },
    { keyAccess: fullKeyAccess },
  );
  await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerB.fingerprint,
      name: "API_KEY",
    },
    { keyAccess: fullKeyAccess },
  );

  const before = structuredClone(getSecretsFile(secretsPath));

  await assert.rejects(
    () =>
      removeConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess: missingPrivateKeyAccess }),
    /Private key not found for any owner of API_KEY.development/,
  );

  assert.deepEqual(getSecretsFile(secretsPath), before);
});

test("peekSecretValue surfaces malformed ciphertext through core decrypt", async () => {
  const ownerA = await generateTestKey("Owner A");
  const keyAccess = createKeyAccess([ownerA]);
  const secretsPath = createTempSecretsPath();

  writeSecretsFile(secretsPath, {
    version: "2.0.0",
    environments: ["development"],
    keys: [
      {
        fingerprint: ownerA.fingerprint,
        publicKey: ownerA.publicKey,
        userIds: ownerA.userIds,
      },
    ],
    secrets: {
      API_KEY: {
        values: {
          development: {
            encryptedValue: "not-a-message",
            owners: [ownerA.fingerprint],
          },
        },
      },
    },
  });

  await assert.rejects(
    () =>
      peekSecretValue(
        secretsPath,
        {
          environment: "development",
          name: "API_KEY",
        },
        { keyAccess },
      ),
    /Misformed armored text|Ascii armor integrity check failed|Unknown ASCII armor type/,
  );
});

test("shareSecretValue can re-encrypt when only one current owner private key is available", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const ownerC = await generateTestKey("Owner C");
  const fullKeyAccess = createKeyAccess([ownerA, ownerB, ownerC]);
  const partialKeyAccess = createMissingPrivateKeyAccess(
    [ownerA, ownerB, ownerC],
    [ownerB.fingerprint],
  );
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);
  await importConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess: fullKeyAccess });
  await importConfiguredKey(secretsPath, ownerB.fingerprint, { keyAccess: fullKeyAccess });
  await importConfiguredKey(secretsPath, ownerC.fingerprint, { keyAccess: fullKeyAccess });

  await createSecret(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
      plaintextValue: "shared-secret",
    },
    { keyAccess: fullKeyAccess },
  );
  await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerB.fingerprint,
      name: "API_KEY",
    },
    { keyAccess: fullKeyAccess },
  );

  const before =
    getSecretsFile(secretsPath).secrets["API_KEY"]?.values["development"]?.encryptedValue;

  const result = await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerC.fingerprint,
      name: "API_KEY",
    },
    { keyAccess: partialKeyAccess },
  );

  assert.deepEqual(result.owners, [ownerA.fingerprint, ownerB.fingerprint, ownerC.fingerprint]);

  const file = getSecretsFile(secretsPath);
  const value = file.secrets["API_KEY"]?.values["development"];
  assert.deepEqual(value?.owners, [ownerA.fingerprint, ownerB.fingerprint, ownerC.fingerprint]);
  assert.notEqual(value?.encryptedValue, before);

  const decrypted = await openPgpCryptoBackend.decrypt({
    armoredPrivateKeys: [ownerC.privateKey],
    ciphertext: value?.encryptedValue ?? "",
  });
  assert.equal(decrypted.payload, "shared-secret");
});

test("revokeSecretValue leaves the file unchanged when no current owner private keys are available", async () => {
  const ownerA = await generateTestKey("Owner A");
  const ownerB = await generateTestKey("Owner B");
  const fullKeyAccess = createKeyAccess([ownerA, ownerB]);
  const missingPrivateKeyAccess = createMissingPrivateKeyAccess(
    [ownerA, ownerB],
    [ownerA.fingerprint, ownerB.fingerprint],
  );
  const secretsPath = createTempSecretsPath();

  initializeSecretsFile(secretsPath);
  await importConfiguredKey(secretsPath, ownerA.fingerprint, { keyAccess: fullKeyAccess });
  await importConfiguredKey(secretsPath, ownerB.fingerprint, { keyAccess: fullKeyAccess });

  await createSecret(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerA.fingerprint,
      name: "API_KEY",
      plaintextValue: "release-secret",
    },
    { keyAccess: fullKeyAccess },
  );
  await shareSecretValue(
    secretsPath,
    {
      environment: "development",
      fingerprint: ownerB.fingerprint,
      name: "API_KEY",
    },
    { keyAccess: fullKeyAccess },
  );

  const before = structuredClone(getSecretsFile(secretsPath));

  await assert.rejects(
    () =>
      revokeSecretValue(
        secretsPath,
        {
          environment: "development",
          fingerprint: ownerA.fingerprint,
          name: "API_KEY",
        },
        { keyAccess: missingPrivateKeyAccess },
      ),
    /Private key not found for any owner of API_KEY.development/,
  );

  assert.deepEqual(getSecretsFile(secretsPath), before);
});

test("shareSecretValue rejects duplicate and unknown owners before re-encryption", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  await assert.rejects(
    () =>
      shareSecretValue(secretsPath, {
        environment: "development",
        fingerprint: "owner-1",
        name: "API_KEY",
      }),
    /owner-1 already has access to API_KEY.development/,
  );

  await assert.rejects(
    () =>
      shareSecretValue(secretsPath, {
        environment: "development",
        fingerprint: "missing-owner",
        name: "API_KEY",
      }),
    /Configured key not found: missing-owner/,
  );
});

test("revokeSecretValue rejects missing and last-owner revocations before re-encryption", async () => {
  const secretsPath = createTempSecretsPath();
  writeSecretsFile(secretsPath, createFixtureFile());

  await assert.rejects(
    () =>
      revokeSecretValue(secretsPath, {
        environment: "staging",
        fingerprint: "missing-owner",
        name: "API_KEY",
      }),
    /missing-owner does not currently have access to API_KEY.staging/,
  );

  await assert.rejects(
    () =>
      revokeSecretValue(secretsPath, {
        environment: "development",
        fingerprint: "owner-1",
        name: "API_KEY",
      }),
    /Cannot revoke the only recipient from API_KEY.development/,
  );
});
