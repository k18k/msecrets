import assert from "node:assert";
import { test } from "node:test";

import { generateKey, readPrivateKey } from "node-rpgp";

import { openPgpCryptoBackend } from "./src/crypto.ts";

test("openPgpCryptoBackend encrypts and decrypts with armored keys", async () => {
  const keyPair = generateKey({
    type: "ecc",
    userIDs: [{ name: "Core Test" }],
  });

  const privateKey = readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  const fingerprint = privateKey.fingerprint;
  assert.equal(typeof fingerprint, "string");
  const plaintext = "hello from core crypto";

  const encryptedValue = await openPgpCryptoBackend.encrypt({
    plaintext,
    recipients: [
      {
        fingerprint,
        publicKey: keyPair.publicKey,
        userIds: ["Core Test"],
      },
    ],
  });

  assert.match(encryptedValue, /BEGIN PGP MESSAGE/);

  const decrypted = await openPgpCryptoBackend.decrypt({
    armoredPrivateKeys: [keyPair.privateKey],
    ciphertext: encryptedValue,
  });

  assert.equal(decrypted.payload, plaintext);
  assert.match(decrypted.info ?? "", /OpenPGP/);
});
