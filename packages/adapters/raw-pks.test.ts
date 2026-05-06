import assert from "node:assert";
import { test } from "node:test";

import { createMessage, encrypt, generateKey, readKey, readPrivateKey } from "node-rpgp";

import { rawPKs } from "./src/raw-pks.ts";

test("rawPKs decrypts messages for matching owners", async () => {
  const keyPair = generateKey({
    type: "ecc",
    userIDs: [{ name: "Adapter Test" }],
  });
  const privateKey = readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  const fingerprint = privateKey.fingerprint;
  assert.equal(typeof fingerprint, "string");
  const plaintext = "hello from raw-pks";

  const encryptedValue = encrypt({
    message: createMessage({ text: plaintext }),
    encryptionKeys: readKey({ armoredKey: keyPair.publicKey }),
  });
  assert.equal(typeof encryptedValue, "string");

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
  const keyPair = generateKey({
    type: "ecc",
    userIDs: [{ name: "Adapter Test" }],
  });

  const encryptedValue = encrypt({
    message: createMessage({ text: "secret" }),
    encryptionKeys: readKey({ armoredKey: keyPair.publicKey }),
  });
  assert.equal(typeof encryptedValue, "string");

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
  assert.throws(
    () =>
      rawPKs({
        keys: ["not-a-private-key"],
      }),
    /Failed to load raw-pks private key:/,
  );
});

test("rawPKs rejects malformed ciphertext clearly", async () => {
  const keyPair = generateKey({
    type: "ecc",
    userIDs: [{ name: "Adapter Test" }],
  });
  const privateKey = readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  const fingerprint = privateKey.fingerprint;
  assert.equal(typeof fingerprint, "string");
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
