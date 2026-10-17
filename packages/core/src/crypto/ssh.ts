/**
 * OpenSSH Ed25519 keys: the age `ssh-ed25519` recipient type and the
 * `openssh-key-v1` private key format (plain or passphrase-encrypted).
 */
import { type DecipherGCM, createDecipheriv, createHash } from "node:crypto";

import { MsecretsError } from "../errors.ts";
import {
  type AgeIdentity,
  type AgeRecipient,
  ZERO_NONCE,
  headerError,
  requireWrappedFileKey,
  stanzaArgument,
} from "./age.ts";
import { bcryptPbkdf } from "./bcrypt-pbkdf.ts";
import { fromBase64, toBase64 } from "./encoding.ts";
import {
  chachaOpen,
  chachaSeal,
  hkdf,
  randomBytes,
  sha256,
  x25519,
  x25519Base,
} from "./primitives.ts";

const SSH_ED25519 = "ssh-ed25519";
const SSH_LABEL = "age-encryption.org/v1/ssh-ed25519";
const PRIVATE_KEY_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PRIVATE_KEY_END = "-----END OPENSSH PRIVATE KEY-----";
const PRIVATE_KEY_MAGIC = Buffer.from("openssh-key-v1\0", "latin1");

function wireString(...parts: Uint8Array[]): Buffer {
  return Buffer.concat(
    parts.flatMap((part) => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(part.length);
      return [length, part];
    }),
  );
}

function wireReader(data: Buffer, what: string) {
  let offset = 0;
  const malformed = () => new MsecretsError("INVALID_KEY", `Malformed ${what}`);
  const uint32 = (): number => {
    if (offset + 4 > data.length) {
      throw malformed();
    }
    const value = data.readUInt32BE(offset);
    offset += 4;
    return value;
  };
  return {
    uint32,
    string(): Buffer {
      const length = uint32();
      if (offset + length > data.length) {
        throw malformed();
      }
      const value = data.subarray(offset, offset + length);
      offset += length;
      return value;
    },
    rest(): Buffer {
      return data.subarray(offset);
    },
  };
}

// Edwards25519 -> Curve25519 conversion of public keys (with point validation).

const P = 2n ** 255n - 19n;

function mod(value: bigint): bigint {
  const result = value % P;
  return result >= 0n ? result : result + P;
}

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let current = mod(base);
  for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
    if (remaining & 1n) {
      result = (result * current) % P;
    }
    current = (current * current) % P;
  }
  return result;
}

const D = mod(-121665n * modPow(121666n, P - 2n));

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

function bigIntToLittleEndian(value: bigint): Buffer {
  const bytes = Buffer.alloc(32);
  for (let index = 0; index < 32; index++) {
    bytes[index] = Number((value >> BigInt(8 * index)) & 0xffn);
  }
  return bytes;
}

function invalid(): MsecretsError {
  return new MsecretsError("INVALID_KEY", "Invalid Ed25519 public key");
}

/** Returns the Montgomery u-coordinate for an Ed25519 public key, rejecting invalid encodings. */
export function ed25519ToX25519PublicKey(publicKey: Uint8Array): Buffer {
  if (publicKey.length !== 32) {
    throw invalid();
  }

  const sign = (publicKey[31] ?? 0) >> 7;
  const y = littleEndianToBigInt(publicKey) & ((1n << 255n) - 1n);
  if (y >= P) {
    throw invalid();
  }

  // x^2 = (y^2 - 1) / (d y^2 + 1) must have a square root for the point to be on the curve.
  const ySquared = mod(y * y);
  const xSquared = mod((ySquared - 1n) * modPow(D * ySquared + 1n, P - 2n));
  if (xSquared === 0n ? sign === 1 : modPow(xSquared, (P - 1n) / 2n) !== 1n) {
    throw invalid();
  }

  const u = mod((1n + y) * modPow(1n - y, P - 2n));
  if (u === 0n) {
    throw invalid();
  }
  return bigIntToLittleEndian(u);
}

function ed25519SeedToX25519Secret(seed: Uint8Array): Buffer {
  return createHash("sha512").update(seed).digest().subarray(0, 32);
}

function sshTag(wirePublicKey: Buffer): string {
  return toBase64(sha256(wirePublicKey).subarray(0, 4));
}

function sshSharedSecret(scalar: Uint8Array, point: Uint8Array, wirePublicKey: Buffer): Buffer {
  const shared = x25519(scalar, point);
  if (!shared) {
    throw headerError("ssh-ed25519 share is a low-order point");
  }
  const tweak = hkdf(Buffer.alloc(0), wirePublicKey, SSH_LABEL);
  const tweaked = x25519(tweak, shared);
  if (!tweaked) {
    throw headerError("ssh-ed25519 tweak produced a low-order point");
  }
  return tweaked;
}

export function parseSshEd25519PublicKey(line: string): { publicKey: Buffer; token: string } {
  const [type, encoded] = line.trim().split(/\s+/);
  if (type !== SSH_ED25519 || !encoded) {
    throw new MsecretsError(
      type?.startsWith("ssh-") || type?.startsWith("ecdsa-") ? "UNSUPPORTED" : "INVALID_KEY",
      `Only ssh-ed25519 SSH keys are supported${type ? ` (got ${type})` : ""}`,
    );
  }

  const wire = Buffer.from(encoded, "base64");
  if (wire.toString("base64") !== encoded) {
    throw new MsecretsError("INVALID_KEY", "Malformed ssh-ed25519 public key encoding");
  }

  const reader = wireReader(wire, "ssh-ed25519 public key");
  const keyType = reader.string().toString("latin1");
  const publicKey = Buffer.from(reader.string());
  if (keyType !== SSH_ED25519 || publicKey.length !== 32 || reader.rest().length) {
    throw new MsecretsError("INVALID_KEY", "Malformed ssh-ed25519 public key");
  }

  ed25519ToX25519PublicKey(publicKey);
  return { publicKey, token: `${SSH_ED25519} ${encoded}` };
}

export function sshEd25519Recipient(publicKey: Buffer): AgeRecipient {
  const wirePublicKey = wireString(Buffer.from(SSH_ED25519), publicKey);
  const theirPublicKey = ed25519ToX25519PublicKey(publicKey);

  return {
    wrap(fileKey) {
      const ephemeral = randomBytes(32);
      const share = x25519Base(ephemeral);
      const shared = sshSharedSecret(ephemeral, theirPublicKey, wirePublicKey);
      const wrapKey = hkdf(shared, Buffer.concat([share, theirPublicKey]), SSH_LABEL);
      return [
        {
          args: [SSH_ED25519, sshTag(wirePublicKey), toBase64(share)],
          body: chachaSeal(wrapKey, ZERO_NONCE, fileKey),
        },
      ];
    },
  };
}

export function sshEd25519Identity(seed: Buffer, publicKey: Buffer): AgeIdentity {
  const wirePublicKey = wireString(Buffer.from(SSH_ED25519), publicKey);
  const tag = sshTag(wirePublicKey);
  const secretKey = ed25519SeedToX25519Secret(seed);
  const ourPublicKey = ed25519ToX25519PublicKey(publicKey);

  return {
    unwrap(stanzas) {
      for (const stanza of stanzas) {
        if (stanza.args[0] !== SSH_ED25519) {
          continue;
        }
        if (stanza.args.length !== 3) {
          throw headerError("ssh-ed25519 stanza must have exactly three arguments");
        }
        const share = fromBase64(stanzaArgument(stanza, 2), "AGE_HEADER", "ssh-ed25519 share");
        if (share.length !== 32) {
          throw headerError("ssh-ed25519 share must be 32 bytes");
        }
        if (stanzaArgument(stanza, 1) !== tag) {
          continue;
        }
        const body = requireWrappedFileKey(stanza);
        const shared = sshSharedSecret(secretKey, share, wirePublicKey);
        const fileKey = chachaOpen(
          hkdf(shared, Buffer.concat([share, ourPublicKey]), SSH_LABEL),
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

export function isOpenSshPrivateKey(text: string): boolean {
  return text.startsWith(PRIVATE_KEY_BEGIN);
}

export type OpenSshPrivateKey = {
  seed: Buffer;
  publicKey: Buffer;
  publicKeyLine: string;
  comment: string;
};

const CIPHERS: Record<
  string,
  { algorithm: string; keyLength: number; ivLength: number; tagLength: number }
> = {
  none: { algorithm: "", keyLength: 0, ivLength: 0, tagLength: 0 },
  "aes256-ctr": { algorithm: "aes-256-ctr", keyLength: 32, ivLength: 16, tagLength: 0 },
  "aes256-cbc": { algorithm: "aes-256-cbc", keyLength: 32, ivLength: 16, tagLength: 0 },
  "aes256-gcm@openssh.com": {
    algorithm: "aes-256-gcm",
    keyLength: 32,
    ivLength: 12,
    tagLength: 16,
  },
};

function decryptPrivateSection(
  cipherName: string,
  kdfName: string,
  kdfOptions: Buffer,
  encrypted: Buffer,
  tag: Buffer,
  passphrase: (() => string) | undefined,
): Buffer {
  const cipher = CIPHERS[cipherName];
  if (!cipher) {
    throw new MsecretsError("UNSUPPORTED", `Unsupported OpenSSH private key cipher ${cipherName}`);
  }
  if (cipherName === "none") {
    return encrypted;
  }
  if (kdfName !== "bcrypt") {
    throw new MsecretsError("UNSUPPORTED", `Unsupported OpenSSH private key KDF ${kdfName}`);
  }
  if (!passphrase) {
    throw new MsecretsError(
      "IDENTITY_SOURCE",
      "The SSH private key is passphrase-protected, but no passphrase is available",
    );
  }

  const options = wireReader(kdfOptions, "OpenSSH KDF options");
  const salt = options.string();
  const rounds = options.uint32();
  const derived = bcryptPbkdf(
    Buffer.from(passphrase()),
    salt,
    cipher.keyLength + cipher.ivLength,
    rounds,
  );
  const decipher = createDecipheriv(
    cipher.algorithm,
    derived.subarray(0, cipher.keyLength),
    derived.subarray(cipher.keyLength),
  );
  decipher.setAutoPadding(false);
  if (cipher.tagLength) {
    (decipher as DecipherGCM).setAuthTag(tag);
  }

  try {
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (error) {
    throw new MsecretsError("IDENTITY_SOURCE", "Incorrect passphrase for the SSH private key", {
      cause: error,
    });
  } finally {
    derived.fill(0);
  }
}

export function parseOpenSshPrivateKey(text: string, passphrase?: () => string): OpenSshPrivateKey {
  const lines = text.trim().split(/\r?\n/);
  if (lines[0] !== PRIVATE_KEY_BEGIN || lines[lines.length - 1] !== PRIVATE_KEY_END) {
    throw new MsecretsError("INVALID_KEY", "Malformed OpenSSH private key");
  }

  const data = Buffer.from(lines.slice(1, -1).join(""), "base64");
  if (!data.subarray(0, PRIVATE_KEY_MAGIC.length).equals(PRIVATE_KEY_MAGIC)) {
    throw new MsecretsError("INVALID_KEY", "Malformed OpenSSH private key");
  }

  const reader = wireReader(data.subarray(PRIVATE_KEY_MAGIC.length), "OpenSSH private key");
  const cipherName = reader.string().toString("latin1");
  const kdfName = reader.string().toString("latin1");
  const kdfOptions = reader.string();
  if (reader.uint32() !== 1) {
    throw new MsecretsError(
      "UNSUPPORTED",
      "OpenSSH private key files with multiple keys are not supported",
    );
  }
  const publicWire = Buffer.from(reader.string());
  const encrypted = reader.string();
  const plain = decryptPrivateSection(
    cipherName,
    kdfName,
    kdfOptions,
    encrypted,
    reader.rest(),
    passphrase,
  );

  const section = wireReader(plain, "OpenSSH private key");
  if (section.uint32() !== section.uint32()) {
    throw new MsecretsError("IDENTITY_SOURCE", "Incorrect passphrase for the SSH private key");
  }

  const keyType = section.string().toString("latin1");
  if (keyType !== SSH_ED25519) {
    throw new MsecretsError(
      "UNSUPPORTED",
      `Only ssh-ed25519 SSH keys are supported (got ${keyType})`,
    );
  }

  const publicKey = Buffer.from(section.string());
  const privateKey = section.string();
  const comment = section.string().toString("utf8");
  if (
    publicKey.length !== 32 ||
    privateKey.length !== 64 ||
    !privateKey.subarray(32).equals(publicKey) ||
    !publicWire.equals(wireString(Buffer.from(SSH_ED25519), publicKey))
  ) {
    throw new MsecretsError("INVALID_KEY", "Inconsistent OpenSSH Ed25519 private key");
  }

  const seed = Buffer.from(privateKey.subarray(0, 32));
  plain.fill(0);
  return {
    seed,
    publicKey,
    publicKeyLine: `${SSH_ED25519} ${publicWire.toString("base64")}`,
    comment,
  };
}
