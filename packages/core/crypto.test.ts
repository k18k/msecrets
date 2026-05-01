import assert from "node:assert";
import { test } from "node:test";

import * as openpgp from "openpgp";

import { openPgpCryptoBackend } from "./src/crypto.ts";

test("openPgpCryptoBackend encrypts and decrypts with armored keys", async () => {
  const keyPair = await openpgp.generateKey({
    type: "curve25519",
    userIDs: [{ name: "Core Test" }],
  });

  const privateKey = await openpgp.readPrivateKey({
    armoredKey: keyPair.privateKey,
  });
  const fingerprint = privateKey.getFingerprint();
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
