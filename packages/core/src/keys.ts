/**
 * msecrets keys.
 *
 * Identities are standard age identities (`AGE-SECRET-KEY-1…`, `AGE-SECRET-KEY-PQ-1…`)
 * or unencrypted OpenSSH Ed25519 keys. Every identity can also sign: for age
 * identities an Ed25519 signing key is derived from the secret with HKDF.
 *
 * Public keys come in these forms:
 * - `msecrets1…`: encryption key and Ed25519 signing key in one token (read + write)
 * - `age1…` / `age1pq1…`: plain age recipients (read-only, cannot sign values)
 * - `ssh-ed25519 AAAA…`: OpenSSH Ed25519 public keys (read + write)
 */
import { type AgeIdentity, type AgeRecipient, decryptAge } from "./crypto/age.ts";
import {
  HYBRID_PUBLIC_KEY_SIZE,
  hybridIdentity,
  hybridPublicKey,
  hybridRecipient,
  scryptIdentity,
  x25519Identity,
  x25519Recipient,
} from "./crypto/age-recipients.ts";
import { bech32Decode, bech32Encode } from "./crypto/encoding.ts";
import {
  ed25519PublicKey,
  ed25519Sign,
  hkdf,
  randomBytes,
  x25519Base,
} from "./crypto/primitives.ts";
import {
  isOpenSshPrivateKey,
  parseOpenSshPrivateKey,
  parseSshEd25519PublicKey,
  sshEd25519Identity,
  sshEd25519Recipient,
} from "./crypto/ssh.ts";
import { MsecretsError } from "./errors.ts";

export type KeyKind = "x25519" | "mlkem768x25519" | "ssh-ed25519";

export type PublicKey = {
  readonly kind: KeyKind;
  /** Canonical string form, as stored in the secrets file. */
  readonly token: string;
  /** Raw encryption key bytes; equal for every token form of the same key. */
  readonly encryptionKey: Buffer;
  /** Ed25519 verification key, or null for encrypt-only (read-only) recipients. */
  readonly signingKey: Buffer | null;
  readonly postQuantum: boolean;
  readonly recipient: AgeRecipient;
};

export type Identity = {
  readonly kind: KeyKind;
  /** The full public key of this identity, including its signing key. */
  readonly publicKey: PublicKey;
  readonly ageIdentity: AgeIdentity;
  sign(message: Uint8Array): Buffer;
  /** The identity in its portable string form. Handle with care. */
  readonly secret: string;
};

const MSECRETS_HRP = "msecrets";
const X25519_IDENTITY_HRP = "age-secret-key-";
const HYBRID_IDENTITY_HRP = "age-secret-key-pq-";
const X25519_RECIPIENT_HRP = "age";
const HYBRID_RECIPIENT_HRP = "age1pq";
const SIGNING_KEY_INFO = "msecrets/v4/ed25519-signing-key";

const KIND_TAGS: Record<"x25519" | "mlkem768x25519", number> = {
  x25519: 0x01,
  mlkem768x25519: 0x02,
};

function encryptionKeySize(kind: "x25519" | "mlkem768x25519"): number {
  return kind === "x25519" ? 32 : HYBRID_PUBLIC_KEY_SIZE;
}

function ageRecipientFor(kind: "x25519" | "mlkem768x25519", encryptionKey: Buffer): AgeRecipient {
  return kind === "x25519" ? x25519Recipient(encryptionKey) : hybridRecipient(encryptionKey);
}

function agePublicKey(
  kind: "x25519" | "mlkem768x25519",
  encryptionKey: Buffer,
  signingKey: Buffer | null,
): PublicKey {
  const token = signingKey
    ? bech32Encode(
        MSECRETS_HRP,
        Buffer.concat([Uint8Array.of(KIND_TAGS[kind]), signingKey, encryptionKey]),
      )
    : bech32Encode(kind === "x25519" ? X25519_RECIPIENT_HRP : HYBRID_RECIPIENT_HRP, encryptionKey);

  return {
    kind,
    token,
    encryptionKey,
    signingKey,
    postQuantum: kind === "mlkem768x25519",
    recipient: ageRecipientFor(kind, encryptionKey),
  };
}

function ageIdentity(kind: "x25519" | "mlkem768x25519", secretKey: Buffer): Identity {
  const signingSeed = hkdf(secretKey, Buffer.alloc(0), SIGNING_KEY_INFO);
  const encryptionKey = kind === "x25519" ? x25519Base(secretKey) : hybridPublicKey(secretKey);

  return {
    kind,
    publicKey: agePublicKey(kind, encryptionKey, ed25519PublicKey(signingSeed)),
    ageIdentity: kind === "x25519" ? x25519Identity(secretKey) : hybridIdentity(secretKey),
    sign: (message) => ed25519Sign(signingSeed, message),
    secret: bech32Encode(
      kind === "x25519" ? X25519_IDENTITY_HRP : HYBRID_IDENTITY_HRP,
      secretKey,
    ).toUpperCase(),
  };
}

export function generateIdentity(options: { postQuantum?: boolean } = {}): Identity {
  return ageIdentity(options.postQuantum ? "mlkem768x25519" : "x25519", randomBytes(32));
}

export type IdentityFileOptions = {
  /** Returns the passphrase for a passphrase-encrypted identity file or SSH key. */
  passphrase?: () => string;
};

/** Parses a single identity: an age secret key string or an OpenSSH private key. */
export function parseIdentity(text: string, options: IdentityFileOptions = {}): Identity {
  const trimmed = text.trim();

  if (isOpenSshPrivateKey(trimmed)) {
    const key = parseOpenSshPrivateKey(trimmed, options.passphrase);
    const publicKey = sshPublicKey(key.publicKeyLine);
    return {
      kind: "ssh-ed25519",
      publicKey,
      ageIdentity: sshEd25519Identity(key.seed, key.publicKey),
      sign: (message) => ed25519Sign(key.seed, message),
      secret: trimmed,
    };
  }

  if (!/^AGE-SECRET-KEY-/i.test(trimmed)) {
    throw new MsecretsError(
      "INVALID_KEY",
      "Unrecognized identity: expected an AGE-SECRET-KEY-1…, AGE-SECRET-KEY-PQ-1…, or OpenSSH Ed25519 private key",
    );
  }

  const { hrp, bytes } = bech32Decode(trimmed);
  if ((hrp !== X25519_IDENTITY_HRP && hrp !== HYBRID_IDENTITY_HRP) || bytes.length !== 32) {
    throw new MsecretsError("INVALID_KEY", "Malformed age identity");
  }

  return ageIdentity(hrp === X25519_IDENTITY_HRP ? "x25519" : "mlkem768x25519", bytes);
}

/**
 * Parses identity file contents: one identity per line with `#` comments (age
 * format), an OpenSSH private key, or a passphrase-encrypted age file
 * (binary or armored) containing either of those.
 */
export function parseIdentities(
  contents: string | Uint8Array,
  options: IdentityFileOptions = {},
): Identity[] {
  const bytes = typeof contents === "string" ? Buffer.from(contents) : Buffer.from(contents);
  const text = bytes.toString("utf8");

  if (
    text.startsWith("age-encryption.org/") ||
    text.trimStart().startsWith("-----BEGIN AGE ENCRYPTED FILE-----")
  ) {
    if (!options.passphrase) {
      throw new MsecretsError(
        "IDENTITY_SOURCE",
        "The identity file is passphrase-encrypted, but no passphrase is available",
      );
    }
    const decrypted = decryptAge(bytes, [scryptIdentity(options.passphrase())]);
    try {
      return parseIdentities(decrypted.toString("utf8"));
    } finally {
      decrypted.fill(0);
    }
  }

  if (isOpenSshPrivateKey(text.trim())) {
    return [parseIdentity(text, options)];
  }

  const identities = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => parseIdentity(line));

  if (!identities.length) {
    throw new MsecretsError("INVALID_KEY", "No identities found");
  }
  return identities;
}

function sshPublicKey(line: string): PublicKey {
  const { publicKey, token } = parseSshEd25519PublicKey(line);
  return {
    kind: "ssh-ed25519",
    token,
    encryptionKey: publicKey,
    signingKey: publicKey,
    postQuantum: false,
    recipient: sshEd25519Recipient(publicKey),
  };
}

/** Parses a recipient public key in any supported form. */
export function parsePublicKey(text: string): PublicKey {
  const trimmed = text.trim();

  if (trimmed.startsWith("ssh-")) {
    return sshPublicKey(trimmed);
  }

  const { hrp, bytes } = bech32Decode(trimmed);

  if (hrp === MSECRETS_HRP) {
    const kind =
      bytes[0] === KIND_TAGS.x25519
        ? "x25519"
        : bytes[0] === KIND_TAGS.mlkem768x25519
          ? "mlkem768x25519"
          : null;
    if (!kind || bytes.length !== 33 + encryptionKeySize(kind)) {
      throw new MsecretsError("INVALID_KEY", "Malformed msecrets public key");
    }
    return agePublicKey(kind, bytes.subarray(33), bytes.subarray(1, 33));
  }

  if (hrp === X25519_RECIPIENT_HRP && bytes.length === 32) {
    return agePublicKey("x25519", bytes, null);
  }
  if (hrp === HYBRID_RECIPIENT_HRP && bytes.length === HYBRID_PUBLIC_KEY_SIZE) {
    return agePublicKey("mlkem768x25519", bytes, null);
  }

  throw new MsecretsError(
    "INVALID_KEY",
    "Unrecognized public key: expected msecrets1…, age1…, age1pq1…, or ssh-ed25519 AAAA…",
  );
}

/** The encrypt-only form of a public key (`age1…` / `age1pq1…`): its holder can read but never write values. */
export function readOnlyPublicKey(publicKey: PublicKey): PublicKey {
  if (publicKey.kind === "ssh-ed25519") {
    throw new MsecretsError(
      "USAGE",
      "SSH keys always include their signing key; use an age key for read-only access",
    );
  }
  return agePublicKey(publicKey.kind, publicKey.encryptionKey, null);
}

/** Whether an identity holds the private key for a recipient public key. */
export function identityMatches(identity: Identity, publicKey: PublicKey): boolean {
  return (
    identity.kind === publicKey.kind &&
    identity.publicKey.encryptionKey.equals(publicKey.encryptionKey)
  );
}

/** Renders an identity file in the age format. */
export function formatIdentityFile(identity: Identity, comment?: string): string {
  if (identity.kind === "ssh-ed25519") {
    return `${identity.secret}\n`;
  }
  return [
    "# msecrets identity: keep this secret, never commit it",
    ...(comment ? [`# ${comment}`] : []),
    `# public key: ${identity.publicKey.token}`,
    identity.secret,
    "",
  ].join("\n");
}
