import {
  createMessage,
  decrypt,
  decryptKey,
  encrypt,
  readKey,
  readMessage,
  readPrivateKey,
  type PrivateKey,
  type PublicKey,
} from "node-rpgp";

import type { MSecretsPublicKey } from "./providers/types.ts";

export type EncryptInput = {
  plaintext: string;
  recipients: MSecretsPublicKey[];
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
  decrypt(input: DecryptInput): DecryptResult;
  encrypt(input: EncryptInput): string;
};

function getRecipientFingerprints(recipients: MSecretsPublicKey[]): string[] {
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

function getArmoredPublicKeys(recipients: MSecretsPublicKey[]): string[] {
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

function loadDecryptionKeys(
  armoredPrivateKeys: string[],
  passphrases: string[] = [],
): PrivateKey[] {
  const normalizedPassphrases = passphrases
    .map((passphrase) => passphrase.trim())
    .filter((passphrase) => passphrase.length > 0);

  return normalizeArmoredPrivateKeys(armoredPrivateKeys).map((armoredPrivateKey) => {
    const privateKey = readPrivateKey({
      armoredKey: armoredPrivateKey,
    });

    if (!normalizedPassphrases.length) {
      return privateKey;
    }

    for (const passphrase of normalizedPassphrases) {
      try {
        return decryptKey({
          privateKey,
          passphrase,
        });
      } catch {
        continue;
      }
    }

    throw new Error("Unable to unlock OpenPGP private key with the provided passphrases");
  });
}

function normalizeDecryptedPayload(data: string | Uint8Array): string {
  if (typeof data === "string") {
    return data;
  }

  return new TextDecoder().decode(data);
}

function loadEncryptionKeys(recipients: MSecretsPublicKey[]): PublicKey[] {
  return getArmoredPublicKeys(recipients).map((armoredPublicKey) =>
    readKey({
      armoredKey: armoredPublicKey,
    }),
  );
}

export const openPgpCryptoBackend: CryptoBackend = {
  decrypt({ armoredPrivateKeys, ciphertext, passphrases }) {
    const message = readMessage({
      armoredMessage: ciphertext,
    });
    const decryptionKeys = loadDecryptionKeys(armoredPrivateKeys, passphrases);
    const { data } = decrypt({
      message,
      decryptionKeys,
      format: "binary",
    });

    return {
      info: `Decrypted with in-process OpenPGP using ${decryptionKeys.length} key(s)`,
      payload: normalizeDecryptedPayload(data),
    };
  },
  encrypt({ plaintext, recipients }) {
    getRecipientFingerprints(recipients);

    const res = encrypt({
      message: createMessage({
        text: plaintext,
      }),
      encryptionKeys: loadEncryptionKeys(recipients),
      format: "armored",
    });

    if (typeof res === "string") {
      return res;
    } else {
      return new TextDecoder().decode(res);
    }
  },
};

export const defaultCryptoBackend = openPgpCryptoBackend;
