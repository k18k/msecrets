import * as openpgp from "openpgp";

import type { PublicKey } from "../keys/types.ts";
import { normalizeDecryptedPayload } from "./payload.ts";

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

export async function encryptForRecipients(
  plaintext: string,
  recipients: PublicKey[],
): Promise<string> {
  if (!recipients.length) {
    throw new Error("At least one recipient key is required");
  }

  const encryptionKeys = await Promise.all(
    recipients.map((recipient) => {
      const fingerprint = recipient.fingerprint.trim();
      if (!fingerprint) {
        throw new Error("Recipient fingerprint is required");
      }

      const publicKey = recipient.publicKey.trim();
      if (!publicKey) {
        throw new Error(`Armored public key is required for ${recipient.fingerprint}`);
      }

      return openpgp.readKey({ armoredKey: publicKey });
    }),
  );

  return openpgp.encrypt({
    message: await openpgp.createMessage({ text: plaintext }),
    encryptionKeys,
    format: "armored",
  });
}

export async function decryptWithPrivateKeys(
  ciphertext: string,
  armoredPrivateKeys: string[],
  passphrases: string[] = [],
): Promise<DecryptResult> {
  const keys = armoredPrivateKeys.map((value) => value.trim()).filter(Boolean);
  if (!keys.length) {
    throw new Error("At least one armored private key is required");
  }

  const normalizedPassphrases = passphrases.map((value) => value.trim()).filter(Boolean);

  const decryptionKeys = await Promise.all(
    keys.map(async (armoredPrivateKey) => {
      const privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey });
      if (!normalizedPassphrases.length) {
        return privateKey;
      }

      for (const passphrase of normalizedPassphrases) {
        try {
          return await openpgp.decryptKey({ privateKey, passphrase });
        } catch {
          continue;
        }
      }

      throw new Error("Unable to unlock OpenPGP private key with the provided passphrases");
    }),
  );

  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: ciphertext }),
    decryptionKeys,
    format: "binary",
  });

  return {
    info: `Decrypted with in-process OpenPGP using ${decryptionKeys.length} key(s)`,
    payload: normalizeDecryptedPayload(data),
  };
}

export const openPgpCryptoBackend: CryptoBackend = {
  decrypt: ({ armoredPrivateKeys, ciphertext, passphrases }) =>
    decryptWithPrivateKeys(ciphertext, armoredPrivateKeys, passphrases),
  encrypt: ({ plaintext, recipients }) => encryptForRecipients(plaintext, recipients),
};

export const defaultCryptoBackend = openPgpCryptoBackend;
