import assert from "node:assert";
import { test } from "node:test";

import * as openpgp from "openpgp";

import { rawPKs } from "./src/raw-pks.ts";

test("rawPKs decrypts messages for matching owners", async () => {
  const keyPair = await openpgp.generateKey({
    type: "curve25519",
    userIDs: [{ name: "Adapter Test" }],
  });
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  const fingerprint = privateKey.getFingerprint();
  const plaintext = "hello from raw-pks";

  const encryptedValue = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: plaintext }),
    encryptionKeys: await openpgp.readKey({ armoredKey: keyPair.publicKey }),
  });

  const adapter = await rawPKs({
    keys: [keyPair.privateKey],
  });

  const decrypted = await adapter.decrypt({
    key: "API_KEY",
    mode: "development",
    secret: {
      values: {
        development: {
          encryptedValue,
          owners: [fingerprint],
        },
      },
    },
    value: {
      encryptedValue,
      owners: [fingerprint],
    },
    secrets: {
      version: "2.0.0",
      environments: ["development"],
      keys: [
        {
          fingerprint,
          publicKey: keyPair.publicKey,
          userIds: ["Adapter Test"],
        },
      ],
      secrets: {},
    },
  });

  assert.equal(decrypted, plaintext);
});

test("rawPKs returns null when no owner key matches", async () => {
  const keyPair = await openpgp.generateKey({
    type: "curve25519",
    userIDs: [{ name: "Adapter Test" }],
  });

  const encryptedValue = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: "secret" }),
    encryptionKeys: await openpgp.readKey({ armoredKey: keyPair.publicKey }),
  });

  const adapter = await rawPKs({
    keys: [keyPair.privateKey],
  });

  const decrypted = await adapter.decrypt({
    key: "API_KEY",
    mode: "development",
    secret: {
      values: {
        development: {
          encryptedValue,
          owners: ["missing-owner"],
        },
      },
    },
    value: {
      encryptedValue,
      owners: ["missing-owner"],
    },
    secrets: {
      version: "2.0.0",
      environments: ["development"],
      keys: [],
      secrets: {},
    },
  });

  assert.equal(decrypted, null);
});

test("rawPKs rejects malformed armored private keys clearly", async () => {
  await assert.rejects(
    () =>
      rawPKs({
        keys: ["not-a-private-key"],
      }),
    /Failed to load raw-pks private key:/,
  );
});

test("rawPKs rejects malformed ciphertext clearly", async () => {
  const keyPair = await openpgp.generateKey({
    type: "curve25519",
    userIDs: [{ name: "Adapter Test" }],
  });
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  const fingerprint = privateKey.getFingerprint();
  const adapter = await rawPKs({
    keys: [keyPair.privateKey],
  });

  await assert.rejects(
    async () =>
      adapter.decrypt({
        key: "API_KEY",
        mode: "development",
        secret: {
          values: {
            development: {
              encryptedValue: "not-a-message",
              owners: [fingerprint],
            },
          },
        },
        value: {
          encryptedValue: "not-a-message",
          owners: [fingerprint],
        },
        secrets: {
          version: "2.0.0",
          environments: ["development"],
          keys: [
            {
              fingerprint,
              publicKey: keyPair.publicKey,
              userIds: ["Adapter Test"],
            },
          ],
          secrets: {},
        },
      }),
    /raw-pks failed to decrypt API_KEY\.development:/,
  );
});
