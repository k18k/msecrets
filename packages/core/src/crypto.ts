import * as openpgp from "openpgp";

import type { PublicKey } from "./providers/types.ts";

export type EncryptInput = {
  plaintext: string;
  recipients: PublicKey[];
};

export type DecryptInput = {
  armoredPrivateKeys: string[];
  ciphertext: string;
  passphrases?: string[];
};

export type DecryptResult = {
  info?: string;
  payload: string;
};

export type CryptoBackend = {
  decrypt(input: DecryptInput): Promise<DecryptResult>;
  encrypt(input: EncryptInput): Promise<string>;
};

function getRecipientFingerprints(recipients: PublicKey[]): string[] {
  if (!recipients.length) {
    throw new Error("At least one recipient key is required");
  }

  return recipients.map((recipient) => {
    const fingerprint = recipient.fingerprint.trim();

    if (!fingerprint) {
      throw new Error("Recipient fingerprint is required");
    }

    return fingerprint;
  });
}

function getArmoredPublicKeys(recipients: PublicKey[]): string[] {
  return recipients.map((recipient) => {
    const publicKey = recipient.publicKey.trim();

    if (!publicKey) {
      throw new Error(`Armored public key is required for ${recipient.fingerprint}`);
    }

    return publicKey;
  });
}

function normalizeArmoredPrivateKeys(armoredPrivateKeys: string[]): string[] {
  const keys = armoredPrivateKeys
    .map((armoredPrivateKey) => armoredPrivateKey.trim())
    .filter((armoredPrivateKey) => armoredPrivateKey.length > 0);

  if (!keys.length) {
    throw new Error("At least one armored private key is required");
  }

  return keys;
}

async function loadDecryptionKeys(
  armoredPrivateKeys: string[],
  passphrases: string[] = [],
): Promise<openpgp.PrivateKey[]> {
  const normalizedPassphrases = passphrases
    .map((passphrase) => passphrase.trim())
    .filter((passphrase) => passphrase.length > 0);

  return Promise.all(
    normalizeArmoredPrivateKeys(armoredPrivateKeys).map(async (armoredPrivateKey) => {
      const privateKey = await openpgp.readPrivateKey({
        armoredKey: armoredPrivateKey,
      });

      if (!normalizedPassphrases.length) {
        return privateKey;
      }

      for (const passphrase of normalizedPassphrases) {
        try {
          return await openpgp.decryptKey({
            privateKey,
            passphrase,
          });
        } catch {
          continue;
        }
      }

      throw new Error("Unable to unlock OpenPGP private key with the provided passphrases");
    }),
  );
}

function normalizeDecryptedPayload(data: string | Uint8Array): string {
  if (typeof data === "string") {
    return data;
  }

  return new TextDecoder().decode(data);
}

async function loadEncryptionKeys(recipients: PublicKey[]): Promise<openpgp.PublicKey[]> {
  return Promise.all(
    getArmoredPublicKeys(recipients).map((armoredPublicKey) =>
      openpgp.readKey({
        armoredKey: armoredPublicKey,
      }),
    ),
  );
}

export const openPgpCryptoBackend: CryptoBackend = {
  async decrypt({ armoredPrivateKeys, ciphertext, passphrases }) {
    const message = await openpgp.readMessage({
      armoredMessage: ciphertext,
    });
    const decryptionKeys = await loadDecryptionKeys(armoredPrivateKeys, passphrases);
    const { data } = await openpgp.decrypt({
      message,
      decryptionKeys,
      format: "binary",
    });

    return {
      info: `Decrypted with in-process OpenPGP using ${decryptionKeys.length} key(s)`,
      payload: normalizeDecryptedPayload(data),
    };
  },
  async encrypt({ plaintext, recipients }) {
    getRecipientFingerprints(recipients);

    return openpgp.encrypt({
      message: await openpgp.createMessage({
        text: plaintext,
      }),
      encryptionKeys: await loadEncryptionKeys(recipients),
      format: "armored",
    });
  },
};

export const defaultCryptoBackend = openPgpCryptoBackend;
