/**
 * Sealing and opening of secret values.
 *
 * Every value is age-encrypted to the recipients of its environment and signed
 * by a recipient of that environment. The signature binds the ciphertext to the
 * file id, secret name, environment, and recipient set, so ciphertext cannot be
 * swapped between slots or injected by someone who is not a member.
 */
import { decryptAge, encryptAge } from "./crypto/age.ts";
import { ed25519Verify, sha256 } from "./crypto/primitives.ts";
import { type SealedValue, type SecretsDocument, own } from "./document.ts";
import { MsecretsError } from "./errors.ts";
import { type Identity, type PublicKey, identityMatches, parsePublicKey } from "./keys.ts";

const publicKeyCache = new Map<string, PublicKey>();

/** Parses (and caches) the public key of a named recipient. */
export function recipientKey(document: SecretsDocument, name: string): PublicKey {
  const entry = own(document.recipients, name);
  if (!entry) {
    throw new MsecretsError("NOT_FOUND", `Recipient "${name}" does not exist`);
  }
  let key = publicKeyCache.get(entry.key);
  if (!key) {
    key = parsePublicKey(entry.key);
    publicKeyCache.set(entry.key, key);
  }
  return key;
}

export function environmentRecipients(document: SecretsDocument, environment: string): string[] {
  const entry = own(document.environments, environment);
  if (!entry) {
    throw new MsecretsError("NOT_FOUND", `Environment "${environment}" does not exist`);
  }
  return entry.recipients;
}

/** Digest of a set of recipient keys, independent of order and token form. */
export function recipientDigest(keys: readonly PublicKey[]): string {
  const lines = [
    ...new Set(keys.map((key) => `${key.kind}:${key.encryptionKey.toString("hex")}`)),
  ].toSorted();
  return sha256(Buffer.from(`msecrets/v4/recipients\n${lines.join("\n")}`))
    .subarray(0, 16)
    .toString("hex");
}

export function environmentDigest(document: SecretsDocument, environment: string): string {
  return recipientDigest(
    environmentRecipients(document, environment).map((name) => recipientKey(document, name)),
  );
}

function signatureMessage(
  document: SecretsDocument,
  secret: string,
  environment: string,
  to: string,
  data: string,
): Buffer {
  return Buffer.from(
    [
      "msecrets/v4/value",
      document.id,
      secret,
      environment,
      to,
      sha256(Buffer.from(data)).toString("hex"),
    ].join("\n"),
  );
}

export type Member = { name: string; identity: Identity };

/** Recipients of the document whose private keys are among the given identities. */
export function members(document: SecretsDocument, identities: readonly Identity[]): Member[] {
  return Object.keys(document.recipients).flatMap((name) => {
    const key = recipientKey(document, name);
    const identity = identities.find((candidate) => identityMatches(candidate, key));
    return identity ? [{ name, identity }] : [];
  });
}

/**
 * Picks the member that signs writes to an environment: it must be a recipient
 * of the environment with a signing-capable key.
 */
export function signerFor(
  document: SecretsDocument,
  identities: readonly Identity[],
  environment: string,
  preferred?: string,
): Member {
  const allowed = environmentRecipients(document, environment);
  const candidates = members(document, identities).filter(
    (member) => allowed.includes(member.name) && recipientKey(document, member.name).signingKey,
  );
  const signer = preferred ? candidates.find((member) => member.name === preferred) : candidates[0];

  if (!signer) {
    const loaded = members(document, identities).map((member) => member.name);
    throw new MsecretsError(
      "ACCESS_DENIED",
      `Cannot write to environment "${environment}": ${
        preferred
          ? `"${preferred}" is not`
          : loaded.length
            ? `none of your keys (${loaded.join(", ")}) is`
            : "none of your loaded keys is"
      } a recipient of it with a signing key (msecrets1… or ssh-ed25519). Recipients of "${environment}": ${allowed.join(", ") || "none"}`,
    );
  }
  return signer;
}

export function sealValue(
  document: SecretsDocument,
  secret: string,
  environment: string,
  plaintext: Uint8Array,
  signer: Member,
): SealedValue {
  const keys = environmentRecipients(document, environment).map((name) =>
    recipientKey(document, name),
  );
  if (!keys.length) {
    throw new MsecretsError("ACCESS_DENIED", `Environment "${environment}" has no recipients`);
  }

  const to = recipientDigest(keys);
  const data = encryptAge(
    plaintext,
    keys.map((key) => key.recipient),
  ).toString("base64");
  const sig = signer.identity
    .sign(signatureMessage(document, secret, environment, to, data))
    .toString("base64");
  return { to, by: signer.name, sig, data };
}

/** Signs an existing ciphertext for a (possibly renamed) slot. Callers must verify the previous signature first. */
export function resignValue(
  document: SecretsDocument,
  secret: string,
  environment: string,
  value: SealedValue,
  signer: Member,
): SealedValue {
  const sig = signer.identity
    .sign(signatureMessage(document, secret, environment, value.to, value.data))
    .toString("base64");
  return { to: value.to, by: signer.name, sig, data: value.data };
}

/** Why a sealed value cannot be trusted, or null when its signature is valid. */
export function signatureProblem(
  document: SecretsDocument,
  secret: string,
  environment: string,
  value: SealedValue,
): string | null {
  if (!own(document.recipients, value.by)) {
    return `signed by unknown recipient "${value.by}"`;
  }
  if (!environmentRecipients(document, environment).includes(value.by)) {
    return `signed by "${value.by}", who is not a recipient of "${environment}"`;
  }
  const signingKey = recipientKey(document, value.by).signingKey;
  if (!signingKey) {
    return `signed by "${value.by}", whose key cannot sign`;
  }
  const message = signatureMessage(document, secret, environment, value.to, value.data);
  return ed25519Verify(signingKey, message, Buffer.from(value.sig, "base64"))
    ? null
    : `the signature by "${value.by}" does not match (the value was modified, moved, or the signer's key changed)`;
}

/** Verifies the signature of a value and decrypts it. */
export function openValue(
  document: SecretsDocument,
  secret: string,
  environment: string,
  value: SealedValue,
  identities: readonly Identity[],
): Buffer {
  const problem = signatureProblem(document, secret, environment, value);
  if (problem) {
    throw new MsecretsError(
      "SIGNATURE",
      `Refusing to decrypt ${secret} in "${environment}": ${problem}`,
    );
  }

  try {
    return decryptAge(
      Buffer.from(value.data, "base64"),
      identities.map((identity) => identity.ageIdentity),
    );
  } catch (error) {
    if (error instanceof MsecretsError && error.code === "AGE_NO_MATCH") {
      const loaded = members(document, identities).map((member) => member.name);
      throw new MsecretsError(
        "ACCESS_DENIED",
        `None of your keys can decrypt ${secret} in "${environment}". ${
          loaded.length
            ? `You are: ${loaded.join(", ")}.`
            : "None of your loaded keys belongs to a recipient of this file."
        } Recipients of "${environment}": ${environmentRecipients(document, environment).join(", ") || "none"}.${
          loaded.some((name) => environmentRecipients(document, environment).includes(name))
            ? ` The value is out of date for you; ask a member to run \`msecrets sync\`.`
            : ""
        }`,
        { cause: error },
      );
    }
    throw error;
  }
}
