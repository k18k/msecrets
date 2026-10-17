/** Native age recipient types: X25519, MLKEM768-X25519 (X-Wing hybrid), and scrypt. */
import {
  type AgeIdentity,
  type AgeRecipient,
  type Stanza,
  ZERO_NONCE,
  headerError,
  requireWrappedFileKey,
  stanzaArgument,
} from "./age.ts";
import { fromBase64, toBase64 } from "./encoding.ts";
import {
  MLKEM768_CIPHERTEXT_SIZE,
  MLKEM768_PUBLIC_KEY_SIZE,
  chachaOpen,
  chachaSeal,
  hkdf,
  hkdfExpand,
  hkdfExtract,
  mlKem768Decapsulate,
  mlKem768Encapsulate,
  mlKem768PublicKey,
  randomBytes,
  scrypt,
  sha3_256,
  shake256,
  x25519,
  x25519Base,
} from "./primitives.ts";

function stanzasOfType(stanzas: readonly Stanza[], type: string, argumentCount: number): Stanza[] {
  return stanzas.filter((stanza) => {
    if (stanza.args[0] !== type) {
      return false;
    }
    if (stanza.args.length !== argumentCount) {
      throw headerError(`${type} stanza must have exactly ${argumentCount} arguments`);
    }
    return true;
  });
}

function decodeFixed(text: string, size: number, what: string): Buffer {
  const bytes = fromBase64(text, "AGE_HEADER", what);
  if (bytes.length !== size) {
    throw headerError(`${what} must be ${size} bytes`);
  }
  return bytes;
}

// X25519

const X25519_INFO = "age-encryption.org/v1/X25519";

export function x25519Recipient(publicKey: Uint8Array): AgeRecipient {
  return {
    wrap(fileKey) {
      const ephemeral = randomBytes(32);
      const share = x25519Base(ephemeral);
      const shared = x25519(ephemeral, publicKey);
      if (!shared) {
        throw headerError("X25519 recipient is a low-order point");
      }
      const wrapKey = hkdf(shared, Buffer.concat([share, publicKey]), X25519_INFO);
      return [
        { args: ["X25519", toBase64(share)], body: chachaSeal(wrapKey, ZERO_NONCE, fileKey) },
      ];
    },
  };
}

export function x25519Identity(secretKey: Uint8Array): AgeIdentity {
  const publicKey = x25519Base(secretKey);
  return {
    unwrap(stanzas) {
      for (const stanza of stanzasOfType(stanzas, "X25519", 2)) {
        const share = decodeFixed(stanzaArgument(stanza, 1), 32, "X25519 share");
        const body = requireWrappedFileKey(stanza);
        const shared = x25519(secretKey, share);
        if (!shared) {
          throw headerError("X25519 share is a low-order point");
        }
        const fileKey = chachaOpen(
          hkdf(shared, Buffer.concat([share, publicKey]), X25519_INFO),
          ZERO_NONCE,
          body,
        );
        if (fileKey) {
          return fileKey;
        }
      }
      return null;
    },
  };
}

// MLKEM768-X25519 (X-Wing) through HPKE base mode, KDF HKDF-SHA256, AEAD ChaCha20Poly1305.

const HYBRID_INFO = Buffer.from("age-encryption.org/mlkem768x25519");
const HPKE_SUITE_ID = Buffer.from([0x48, 0x50, 0x4b, 0x45, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03]);
const HPKE_VERSION = Buffer.from("HPKE-v1");
const XWING_LABEL = Buffer.from([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
export const HYBRID_PUBLIC_KEY_SIZE: number = MLKEM768_PUBLIC_KEY_SIZE + 32;
const HYBRID_ENC_SIZE = MLKEM768_CIPHERTEXT_SIZE + 32;

function xwingExpand(seed: Uint8Array): { mlKemSeed: Buffer; x25519Secret: Buffer } {
  const expanded = shake256(seed, 96);
  return { mlKemSeed: expanded.subarray(0, 64), x25519Secret: expanded.subarray(64, 96) };
}

export function hybridPublicKey(seed: Uint8Array): Buffer {
  const { mlKemSeed, x25519Secret } = xwingExpand(seed);
  return Buffer.concat([mlKem768PublicKey(mlKemSeed), x25519Base(x25519Secret)]);
}

function xwingCombine(
  mlKemShared: Buffer,
  x25519Shared: Buffer,
  x25519Ciphertext: Buffer,
  x25519Public: Buffer,
) {
  return sha3_256(mlKemShared, x25519Shared, x25519Ciphertext, x25519Public, XWING_LABEL);
}

function labeledExtract(salt: Buffer, label: string, ikm: Buffer): Buffer {
  return hkdfExtract(salt, Buffer.concat([HPKE_VERSION, HPKE_SUITE_ID, Buffer.from(label), ikm]));
}

function labeledExpand(prk: Buffer, label: string, info: Buffer, length: number): Buffer {
  return hkdfExpand(
    prk,
    Buffer.concat([
      Uint8Array.of(0, length),
      HPKE_VERSION,
      HPKE_SUITE_ID,
      Buffer.from(label),
      info,
    ]),
    length,
  );
}

function hpkeKeySchedule(sharedSecret: Buffer): { key: Buffer; nonce: Buffer } {
  const empty = Buffer.alloc(0);
  const context = Buffer.concat([
    Uint8Array.of(0),
    labeledExtract(empty, "psk_id_hash", empty),
    labeledExtract(empty, "info_hash", HYBRID_INFO),
  ]);
  const secret = labeledExtract(sharedSecret, "secret", empty);
  return {
    key: labeledExpand(secret, "key", context, 32),
    nonce: labeledExpand(secret, "base_nonce", context, 12),
  };
}

export function hybridRecipient(publicKey: Uint8Array): AgeRecipient {
  if (publicKey.length !== HYBRID_PUBLIC_KEY_SIZE) {
    throw headerError("invalid MLKEM768-X25519 public key length");
  }
  const mlKemPublic = publicKey.subarray(0, MLKEM768_PUBLIC_KEY_SIZE);
  const x25519Public = Buffer.from(publicKey.subarray(MLKEM768_PUBLIC_KEY_SIZE));

  return {
    wrap(fileKey) {
      const { sharedKey, ciphertext } = mlKem768Encapsulate(mlKemPublic);
      const ephemeral = randomBytes(32);
      const x25519Ciphertext = x25519Base(ephemeral);
      const x25519Shared = x25519(ephemeral, x25519Public);
      if (!x25519Shared) {
        throw headerError("MLKEM768-X25519 recipient has a low-order X25519 point");
      }
      const { key, nonce } = hpkeKeySchedule(
        xwingCombine(sharedKey, x25519Shared, x25519Ciphertext, x25519Public),
      );
      return [
        {
          args: ["mlkem768x25519", toBase64(Buffer.concat([ciphertext, x25519Ciphertext]))],
          body: chachaSeal(key, nonce, fileKey),
        },
      ];
    },
  };
}

export function hybridIdentity(seed: Uint8Array): AgeIdentity {
  return {
    unwrap(stanzas) {
      const matching = stanzasOfType(stanzas, "mlkem768x25519", 2);
      if (!matching.length) {
        return null;
      }

      const { mlKemSeed, x25519Secret } = xwingExpand(seed);
      const x25519Public = x25519Base(x25519Secret);

      for (const stanza of matching) {
        const enc = decodeFixed(
          stanzaArgument(stanza, 1),
          HYBRID_ENC_SIZE,
          "MLKEM768-X25519 encapsulated key",
        );
        const body = requireWrappedFileKey(stanza);
        const x25519Ciphertext = enc.subarray(MLKEM768_CIPHERTEXT_SIZE);
        const x25519Shared = x25519(x25519Secret, x25519Ciphertext);
        if (!x25519Shared) {
          throw headerError("MLKEM768-X25519 share is a low-order point");
        }
        const mlKemShared = mlKem768Decapsulate(
          mlKemSeed,
          enc.subarray(0, MLKEM768_CIPHERTEXT_SIZE),
        );
        const { key, nonce } = hpkeKeySchedule(
          xwingCombine(mlKemShared, x25519Shared, x25519Ciphertext, x25519Public),
        );
        const fileKey = chachaOpen(key, nonce, body);
        if (fileKey) {
          return fileKey;
        }
      }
      return null;
    },
  };
}

// scrypt (passphrase)

const SCRYPT_SALT_LABEL = Buffer.from("age-encryption.org/v1/scrypt");
export const DEFAULT_SCRYPT_WORK_FACTOR = 18;
export const MAX_SCRYPT_WORK_FACTOR = 22;

export function scryptRecipient(
  passphrase: string,
  workFactor: number = DEFAULT_SCRYPT_WORK_FACTOR,
): AgeRecipient {
  if (!passphrase) {
    throw headerError("passphrase must not be empty");
  }
  return {
    wrap(fileKey) {
      const salt = randomBytes(16);
      const wrapKey = scrypt(passphrase, Buffer.concat([SCRYPT_SALT_LABEL, salt]), workFactor);
      return [
        {
          args: ["scrypt", toBase64(salt), String(workFactor)],
          body: chachaSeal(wrapKey, ZERO_NONCE, fileKey),
        },
      ];
    },
  };
}

export function scryptIdentity(
  passphrase: string,
  maxWorkFactor: number = MAX_SCRYPT_WORK_FACTOR,
): AgeIdentity {
  return {
    unwrap(stanzas) {
      for (const stanza of stanzasOfType(stanzas, "scrypt", 3)) {
        const salt = decodeFixed(stanzaArgument(stanza, 1), 16, "scrypt salt");
        const workFactorText = stanzaArgument(stanza, 2);
        if (!/^[1-9][0-9]*$/.test(workFactorText)) {
          throw headerError("invalid scrypt work factor");
        }
        const workFactor = Number(workFactorText);
        if (workFactor > maxWorkFactor) {
          throw headerError(
            `scrypt work factor ${workFactor} exceeds the maximum of ${maxWorkFactor}`,
          );
        }
        const body = requireWrappedFileKey(stanza);
        const wrapKey = scrypt(passphrase, Buffer.concat([SCRYPT_SALT_LABEL, salt]), workFactor);
        const fileKey = chachaOpen(wrapKey, ZERO_NONCE, body);
        if (fileKey) {
          return fileKey;
        }
      }
      return null;
    },
  };
}
