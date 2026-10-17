import * as nodeCrypto from "node:crypto";
import {
  type KeyObject,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  scryptSync,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

import { MsecretsError } from "../errors.ts";

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
/** PKCS#8 wrapping of a 64-byte (d || z) ML-KEM-768 seed. */
const MLKEM768_PKCS8_PREFIX = Buffer.from("3054020100300b060960864801650304040204428040", "hex");
const MLKEM768_SPKI_PREFIX = Buffer.from("308204b2300b0609608648016503040402038204a100", "hex");

export const MLKEM768_PUBLIC_KEY_SIZE = 1184;
export const MLKEM768_CIPHERTEXT_SIZE = 1088;

export { randomBytes, timingSafeEqual } from "node:crypto";

function rawPublicKey(key: KeyObject, prefix: Buffer): Buffer {
  return key.export({ format: "der", type: "spki" }).subarray(prefix.length);
}

function x25519PrivateKey(scalar: Uint8Array): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, scalar]),
    format: "der",
    type: "pkcs8",
  });
}

/** X25519(scalar, basepoint). */
export function x25519Base(scalar: Uint8Array): Buffer {
  return rawPublicKey(createPublicKey(x25519PrivateKey(scalar)), X25519_SPKI_PREFIX);
}

/**
 * X25519(scalar, point). Returns null when the result is the all-zero value
 * (low-order or identity input point), which callers must treat as an error.
 */
export function x25519(scalar: Uint8Array, point: Uint8Array): Buffer | null {
  const publicKey = createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, point]),
    format: "der",
    type: "spki",
  });

  let shared: Buffer;
  try {
    shared = diffieHellman({ privateKey: x25519PrivateKey(scalar), publicKey });
  } catch {
    // OpenSSL refuses to return the all-zero shared secret.
    return null;
  }

  return shared.every((byte) => byte === 0) ? null : shared;
}

function ed25519PrivateKey(seed: Uint8Array): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

export function ed25519PublicKey(seed: Uint8Array): Buffer {
  return rawPublicKey(createPublicKey(ed25519PrivateKey(seed)), ED25519_SPKI_PREFIX);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Buffer {
  return sign(null, message, ed25519PrivateKey(seed));
}

export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }

  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
    return verify(null, message, key, signature);
  } catch {
    // An unparsable public key cannot verify anything.
    return false;
  }
}

export function sha256(...parts: Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) {
    hash.update(part);
  }
  return hash.digest();
}

export function sha3_256(...parts: Uint8Array[]): Buffer {
  const hash = createHash("sha3-256");
  for (const part of parts) {
    hash.update(part);
  }
  return hash.digest();
}

export function shake256(input: Uint8Array, length: number): Buffer {
  return createHash("shake256", { outputLength: length }).update(input).digest();
}

export function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Buffer {
  const hmac = createHmac("sha256", key);
  for (const part of parts) {
    hmac.update(part);
  }
  return hmac.digest();
}

export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Buffer {
  return hmacSha256(salt, ikm);
}

export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Buffer {
  const blocks: Buffer[] = [];
  let previous: Buffer = Buffer.alloc(0);
  for (let counter = 1; blocks.length * 32 < length; counter++) {
    previous = hmacSha256(prk, previous, info, Uint8Array.of(counter));
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** HKDF-SHA-256 with 32 bytes of output unless specified otherwise. */
export function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string | Uint8Array,
  length = 32,
): Buffer {
  return hkdfExpand(
    hkdfExtract(salt, ikm),
    typeof info === "string" ? Buffer.from(info) : info,
    length,
  );
}

export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

/** ChaCha20-Poly1305 encryption; returns ciphertext || tag. */
export function chachaSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Buffer {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  if (aad) {
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
  }
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

/** ChaCha20-Poly1305 decryption; returns null when authentication fails. */
export function chachaOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  aad?: Uint8Array,
): Buffer | null {
  if (sealed.length < 16) {
    return null;
  }

  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  if (aad) {
    decipher.setAAD(aad, { plaintextLength: sealed.length - 16 });
  }

  const plaintext = decipher.update(sealed.subarray(0, sealed.length - 16));
  try {
    return Buffer.concat([plaintext, decipher.final()]);
  } catch {
    // Authentication failure is an expected outcome, reported as null.
    plaintext.fill(0);
    return null;
  }
}

export function scrypt(passphrase: string, salt: Uint8Array, logN: number): Buffer {
  const N = 2 ** logN;
  return scryptSync(passphrase, salt, 32, {
    N,
    r: 8,
    p: 1,
    maxmem: 128 * 8 * N + 16 * 1024 * 1024,
  });
}

type MlKemApi = {
  encapsulate(key: KeyObject): { sharedKey: Buffer; ciphertext: Buffer };
  decapsulate(key: KeyObject, ciphertext: Uint8Array): Buffer;
};

let mlKemSupport: boolean | undefined;

/** Whether this runtime implements ML-KEM-768 (Node.js >= 24.7 with OpenSSL >= 3.5). */
export function supportsMlKem(): boolean {
  if (mlKemSupport === undefined) {
    const api = nodeCrypto as unknown as Partial<MlKemApi>;
    try {
      mlKemSupport =
        typeof api.encapsulate === "function" &&
        typeof api.decapsulate === "function" &&
        mlKem768PublicKey(Buffer.alloc(64)).length === MLKEM768_PUBLIC_KEY_SIZE;
    } catch {
      // Older runtimes fail to parse ML-KEM keys at all.
      mlKemSupport = false;
    }
  }
  return mlKemSupport;
}

function mlKemApi(): MlKemApi {
  if (!supportsMlKem()) {
    throw new MsecretsError(
      "UNSUPPORTED",
      `Post-quantum (ML-KEM-768) keys require Node.js >= 24.7 built with OpenSSL >= 3.5; this is Node.js ${process.versions.node} with OpenSSL ${process.versions.openssl ?? "unknown"}`,
    );
  }
  return nodeCrypto as unknown as MlKemApi;
}

function mlKem768PrivateKey(seed: Uint8Array): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([MLKEM768_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

/** ML-KEM-768 encapsulation key for a 64-byte (d || z) seed. */
export function mlKem768PublicKey(seed: Uint8Array): Buffer {
  return rawPublicKey(createPublicKey(mlKem768PrivateKey(seed)), MLKEM768_SPKI_PREFIX);
}

export function mlKem768Encapsulate(publicKey: Uint8Array): {
  sharedKey: Buffer;
  ciphertext: Buffer;
} {
  const api = mlKemApi();
  let key: KeyObject;
  try {
    key = createPublicKey({
      key: Buffer.concat([MLKEM768_SPKI_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
  } catch (error) {
    throw new MsecretsError("INVALID_KEY", "Invalid ML-KEM-768 public key", { cause: error });
  }
  return api.encapsulate(key);
}

export function mlKem768Decapsulate(seed: Uint8Array, ciphertext: Uint8Array): Buffer {
  return mlKemApi().decapsulate(mlKem768PrivateKey(seed), ciphertext);
}
