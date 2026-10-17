/**
 * Mutations of a secrets document. Each operation mutates the document it is
 * given; callers run them on a copy (see `updateDocumentFile`) so a thrown
 * error leaves the file untouched.
 */
import {
  type EnvironmentEntry,
  type RecipientEntry,
  type SealedValue,
  type SecretEntry,
  type SecretsDocument,
  normalizeDescription,
  own,
  requireName,
  secretEnvironments,
} from "./document.ts";
import { MsecretsError } from "./errors.ts";
import { type Identity, parsePublicKey } from "./keys.ts";
import { inspectCell } from "./status.ts";
import {
  openValue,
  recipientKey,
  resignValue,
  sealValue,
  signatureProblem,
  signerFor,
} from "./values.ts";

export type Slot = { secret: string; environment: string };

export type SyncResult = {
  updated: Slot[];
  skipped: (Slot & { reason: string })[];
};

export function requireSecret(document: SecretsDocument, name: string): SecretEntry {
  const secret = own(document.secrets, name);
  if (!secret) {
    throw new MsecretsError("NOT_FOUND", `Secret ${name} does not exist`);
  }
  return secret;
}

export function requireEnvironment(document: SecretsDocument, name: string): EnvironmentEntry {
  const environment = own(document.environments, name);
  if (!environment) {
    const known = Object.keys(document.environments);
    throw new MsecretsError(
      "NOT_FOUND",
      `Environment "${name}" does not exist (environments: ${known.join(", ") || "none"})`,
    );
  }
  return environment;
}

export function requireRecipient(document: SecretsDocument, name: string): RecipientEntry {
  const recipient = own(document.recipients, name);
  if (!recipient) {
    throw new MsecretsError("NOT_FOUND", `Recipient "${name}" does not exist`);
  }
  return recipient;
}

function slots(
  document: SecretsDocument,
  filter: (slot: Slot) => boolean = () => true,
): (Slot & { value: SealedValue })[] {
  return Object.entries(document.secrets).flatMap(([secret, entry]) =>
    Object.entries(entry.values).flatMap(([environment, value]) =>
      filter({ secret, environment }) ? [{ secret, environment, value }] : [],
    ),
  );
}

function requireValidSignatures(
  document: SecretsDocument,
  targets: readonly (Slot & { value: SealedValue })[],
): void {
  for (const { secret, environment, value } of targets) {
    const problem = signatureProblem(document, secret, environment, value);
    if (problem) {
      throw new MsecretsError(
        "SIGNATURE",
        `Refusing to re-sign ${secret} in "${environment}": ${problem}. Set a new value with \`msecrets set ${secret} --env ${environment}\``,
      );
    }
  }
}

/** Renames a key of a record while keeping its position. */
function renameKey<T>(record: Record<string, T>, from: string, to: string): Record<string, T> {
  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => [key === from ? to : key, value]),
  );
}

// Recipients

export function addRecipient(
  document: SecretsDocument,
  name: string,
  key: string,
  description?: string,
): RecipientEntry {
  requireName("recipient", name);
  if (own(document.recipients, name)) {
    throw new MsecretsError("CONFLICT", `Recipient "${name}" already exists`);
  }

  const publicKey = parsePublicKey(key);
  const duplicate = Object.keys(document.recipients).find((other) =>
    recipientKey(document, other).encryptionKey.equals(publicKey.encryptionKey),
  );
  if (duplicate) {
    throw new MsecretsError("CONFLICT", `This key already belongs to recipient "${duplicate}"`);
  }

  const entry: RecipientEntry = { key: publicKey.token };
  const text = normalizeDescription(description);
  if (text) {
    entry.description = text;
  }
  document.recipients[name] = entry;
  return entry;
}

export function describeRecipient(
  document: SecretsDocument,
  name: string,
  description: string | undefined,
): void {
  const entry = requireRecipient(document, name);
  const text = normalizeDescription(description);
  if (text) {
    entry.description = text;
  } else {
    delete entry.description;
  }
}

export function renameRecipient(document: SecretsDocument, from: string, to: string): void {
  requireRecipient(document, from);
  requireName("recipient", to);
  if (from === to) {
    return;
  }
  if (own(document.recipients, to)) {
    throw new MsecretsError("CONFLICT", `Recipient "${to}" already exists`);
  }

  document.recipients = renameKey(document.recipients, from, to);
  for (const environment of Object.values(document.environments)) {
    environment.recipients = environment.recipients.map((name) => (name === from ? to : name));
  }
  for (const { value } of slots(document)) {
    if (value.by === from) {
      value.by = to;
    }
  }
}

/**
 * Grants a recipient access to environments and re-encrypts their values when
 * possible. Values that cannot be re-encrypted yet stay stale (reported).
 */
export function grantAccess(
  document: SecretsDocument,
  identities: readonly Identity[],
  recipient: string,
  environments: readonly string[],
): SyncResult {
  requireRecipient(document, recipient);
  for (const name of environments) {
    const environment = requireEnvironment(document, name);
    if (!environment.recipients.includes(recipient)) {
      environment.recipients.push(recipient);
    }
  }
  return sync(document, identities, { environments });
}

export type RevokeResult = SyncResult & {
  /** Values the recipient could read; rotate them, since copies may exist. */
  rotate: Slot[];
};

/**
 * Revokes access and re-encrypts every affected value without the recipient.
 * Throws when some values cannot be re-encrypted, since the revocation would
 * otherwise not take effect, unless `allowIncomplete` is set.
 */
export function revokeAccess(
  document: SecretsDocument,
  identities: readonly Identity[],
  recipient: string,
  environments: readonly string[],
  options: { allowIncomplete?: boolean } = {},
): RevokeResult {
  requireRecipient(document, recipient);
  const affected = environments.filter((name) =>
    requireEnvironment(document, name).recipients.includes(recipient),
  );

  for (const name of affected) {
    const remaining = requireEnvironment(document, name).recipients.filter(
      (other) => other !== recipient,
    );
    if (!remaining.length && slots(document, (slot) => slot.environment === name).length) {
      throw new MsecretsError(
        "CONFLICT",
        `Cannot revoke the last recipient of "${name}" while it holds values; grant someone else access first`,
      );
    }
  }

  const result = resealSlots(
    document,
    identities,
    slots(document, (slot) => affected.includes(slot.environment)),
    () => {
      for (const name of affected) {
        const environment = requireEnvironment(document, name);
        environment.recipients = environment.recipients.filter((other) => other !== recipient);
      }
    },
  );

  if (result.skipped.length && !options.allowIncomplete) {
    throw new MsecretsError(
      "ACCESS_DENIED",
      `Revoking "${recipient}" requires re-encrypting values you cannot decrypt or sign:\n${result.skipped
        .map((slot) => `  ${slot.secret} in "${slot.environment}": ${slot.reason}`)
        .join("\n")}`,
    );
  }

  return {
    ...result,
    rotate: slots(document, (slot) => affected.includes(slot.environment)).map(
      ({ secret, environment }) => ({
        secret,
        environment,
      }),
    ),
  };
}

/** Removes a recipient from every environment and from the file. */
export function removeRecipient(
  document: SecretsDocument,
  identities: readonly Identity[],
  name: string,
): RevokeResult {
  const result = revokeAccess(document, identities, name, Object.keys(document.environments));
  const signed = slots(document).filter(({ value }) => value.by === name);
  if (signed.length) {
    throw new MsecretsError(
      "ACCESS_DENIED",
      `Cannot remove "${name}": these values are still signed by them and must be set again first:\n${signed
        .map((slot) => `  ${slot.secret} in "${slot.environment}"`)
        .join("\n")}`,
    );
  }
  delete document.recipients[name];
  return result;
}

/**
 * Replaces the key of a recipient (key rotation or recovery). Every value
 * readable by the recipient is decrypted first, then re-encrypted to the new
 * key and re-signed, so it requires access to all of them.
 */
export function replaceRecipientKey(
  document: SecretsDocument,
  identities: readonly Identity[],
  name: string,
  key: string,
): Slot[] {
  const entry = requireRecipient(document, name);
  const publicKey = parsePublicKey(key);
  const duplicate = Object.keys(document.recipients).find(
    (other) =>
      other !== name && recipientKey(document, other).encryptionKey.equals(publicKey.encryptionKey),
  );
  if (duplicate) {
    throw new MsecretsError("CONFLICT", `This key already belongs to recipient "${duplicate}"`);
  }

  const environments = Object.keys(document.environments).filter((environment) =>
    requireEnvironment(document, environment).recipients.includes(name),
  );
  const result = resealSlots(
    document,
    identities,
    slots(document, (slot) => environments.includes(slot.environment)),
    () => {
      entry.key = publicKey.token;
    },
  );
  if (result.skipped.length) {
    throw new MsecretsError(
      "ACCESS_DENIED",
      `Rotating the key of "${name}" requires re-encrypting values you cannot decrypt or sign (to rotate your own key, load the new identity too):\n${result.skipped
        .map((slot) => `  ${slot.secret} in "${slot.environment}": ${slot.reason}`)
        .join("\n")}`,
    );
  }
  return result.updated;
}

// Environments

export function addEnvironment(
  document: SecretsDocument,
  name: string,
  recipients: readonly string[],
): void {
  requireName("environment", name);
  if (own(document.environments, name)) {
    throw new MsecretsError("CONFLICT", `Environment "${name}" already exists`);
  }
  for (const recipient of recipients) {
    requireRecipient(document, recipient);
  }
  document.environments[name] = { recipients: [...new Set(recipients)] };
}

export function renameEnvironment(
  document: SecretsDocument,
  identities: readonly Identity[],
  from: string,
  to: string,
): void {
  requireEnvironment(document, from);
  requireName("environment", to);
  if (from === to) {
    return;
  }
  if (own(document.environments, to)) {
    throw new MsecretsError("CONFLICT", `Environment "${to}" already exists`);
  }

  const affected = slots(document, (slot) => slot.environment === from);
  requireValidSignatures(document, affected);

  document.environments = renameKey(document.environments, from, to);
  for (const secret of Object.values(document.secrets)) {
    if (secret.environments) {
      secret.environments = secret.environments.map((name) => (name === from ? to : name));
    }
    secret.values = renameKey(secret.values, from, to);
  }

  if (affected.length) {
    const signer = signerFor(document, identities, to);
    for (const { secret, value } of affected) {
      requireSecret(document, secret).values[to] = resignValue(document, secret, to, value, signer);
    }
  }
}

export function removeEnvironment(
  document: SecretsDocument,
  name: string,
): { removedValues: Slot[]; removedSecrets: string[] } {
  requireEnvironment(document, name);
  const removedValues = slots(document, (slot) => slot.environment === name).map(
    ({ secret, environment }) => ({
      secret,
      environment,
    }),
  );
  const removedSecrets: string[] = [];

  delete document.environments[name];
  for (const [secretName, secret] of Object.entries(document.secrets)) {
    delete secret.values[name];
    if (secret.environments) {
      secret.environments = secret.environments.filter((environment) => environment !== name);
      if (!secret.environments.length) {
        delete document.secrets[secretName];
        removedSecrets.push(secretName);
      }
    }
  }
  return { removedValues, removedSecrets };
}

// Secrets and values

export type SetValueInput = {
  secret: string;
  environment: string;
  value: string;
  /** Sign as this recipient instead of the first eligible one. */
  as?: string;
};

export function setValue(
  document: SecretsDocument,
  identities: readonly Identity[],
  input: SetValueInput,
): SealedValue {
  requireName("secret", input.secret);
  requireEnvironment(document, input.environment);
  if (input.value.includes("\0")) {
    throw new MsecretsError("USAGE", "Secret values cannot contain NUL characters");
  }

  const existing = own(document.secrets, input.secret);
  if (existing && !secretEnvironments(document, existing).includes(input.environment)) {
    throw new MsecretsError(
      "USAGE",
      `${input.secret} does not apply to "${input.environment}" (it is limited to ${existing.environments?.join(", ")}); change that with \`msecrets scope\``,
    );
  }

  const signer = signerFor(document, identities, input.environment, input.as);
  const sealed = sealValue(
    document,
    input.secret,
    input.environment,
    Buffer.from(input.value, "utf8"),
    signer,
  );
  const secret = existing ?? { values: {} };
  secret.values[input.environment] = sealed;
  document.secrets[input.secret] = secret;
  return sealed;
}

export function revealValue(
  document: SecretsDocument,
  identities: readonly Identity[],
  secret: string,
  environment: string,
): string {
  const entry = requireSecret(document, secret);
  requireEnvironment(document, environment);
  const value = own(entry.values, environment);
  if (!value) {
    throw new MsecretsError("NOT_FOUND", `${secret} has no value in "${environment}"`);
  }
  const plaintext = openValue(document, secret, environment, value, identities);
  try {
    return plaintext.toString("utf8");
  } finally {
    plaintext.fill(0);
  }
}

export function unsetValue(
  document: SecretsDocument,
  secret: string,
  environment: string,
): boolean {
  const entry = requireSecret(document, secret);
  requireEnvironment(document, environment);
  const existed = Object.hasOwn(entry.values, environment);
  delete entry.values[environment];
  return existed;
}

export function createSecret(
  document: SecretsDocument,
  name: string,
  options: { description?: string; environments?: string[] } = {},
): void {
  requireName("secret", name);
  if (own(document.secrets, name)) {
    throw new MsecretsError("CONFLICT", `Secret ${name} already exists`);
  }
  document.secrets[name] = { values: {} };
  describeSecret(document, name, options.description);
  if (options.environments) {
    scopeSecret(document, name, options.environments);
  }
}

export function deleteSecret(document: SecretsDocument, name: string): void {
  requireSecret(document, name);
  delete document.secrets[name];
}

export function describeSecret(
  document: SecretsDocument,
  name: string,
  description: string | undefined,
): void {
  const secret = requireSecret(document, name);
  const text = normalizeDescription(description);
  if (text) {
    secret.description = text;
  } else {
    delete secret.description;
  }
}

/**
 * Limits a secret to some environments (undefined: all environments).
 * Values in environments outside the scope are removed and returned.
 */
export function scopeSecret(
  document: SecretsDocument,
  name: string,
  environments: readonly string[] | undefined,
): string[] {
  const secret = requireSecret(document, name);
  if (environments) {
    if (!environments.length) {
      throw new MsecretsError("USAGE", "A secret must apply to at least one environment");
    }
    environments.forEach((environment) => requireEnvironment(document, environment));
    secret.environments = Object.keys(document.environments).filter((environment) =>
      environments.includes(environment),
    );
  } else {
    delete secret.environments;
  }

  const removed = Object.keys(secret.values).filter(
    (environment) => !secretEnvironments(document, secret).includes(environment),
  );
  for (const environment of removed) {
    delete secret.values[environment];
  }
  return removed;
}

export function renameSecret(
  document: SecretsDocument,
  identities: readonly Identity[],
  from: string,
  to: string,
): void {
  const secret = requireSecret(document, from);
  requireName("secret", to);
  if (from === to) {
    return;
  }
  if (own(document.secrets, to)) {
    throw new MsecretsError("CONFLICT", `Secret ${to} already exists`);
  }

  const affected = slots(document, (slot) => slot.secret === from);
  requireValidSignatures(document, affected);

  delete document.secrets[from];
  document.secrets[to] = secret;
  for (const { environment, value } of affected) {
    secret.values[environment] = resignValue(
      document,
      to,
      environment,
      value,
      signerFor(document, identities, environment),
    );
  }
}

/** Errors that make a single value impossible to re-encrypt, as opposed to bugs. */
function expected(error: unknown): error is MsecretsError {
  return (
    error instanceof MsecretsError && (error.code === "ACCESS_DENIED" || error.code === "SIGNATURE")
  );
}

/**
 * Re-encrypts and re-signs values around a change of recipients. Values are
 * decrypted and verified against the document *before* the change, so values
 * signed by a recipient who loses access are carried over. Values that cannot
 * be decrypted, or whose signatures are invalid, are reported and left as is:
 * re-encrypting them would launder tampered data.
 */
function resealSlots(
  document: SecretsDocument,
  identities: readonly Identity[],
  targets: readonly (Slot & { value: SealedValue })[],
  change: () => void,
): SyncResult {
  const result: SyncResult = { updated: [], skipped: [] };

  const opened = targets.flatMap(({ secret, environment, value }) => {
    try {
      return [
        {
          secret,
          environment,
          plaintext: openValue(document, secret, environment, value, identities),
        },
      ];
    } catch (error) {
      if (!expected(error)) {
        throw error;
      }
      result.skipped.push({ secret, environment, reason: error.message });
      return [];
    }
  });

  try {
    change();
    for (const { secret, environment, plaintext } of opened) {
      try {
        requireSecret(document, secret).values[environment] = sealValue(
          document,
          secret,
          environment,
          plaintext,
          signerFor(document, identities, environment),
        );
        result.updated.push({ secret, environment });
      } catch (error) {
        if (!expected(error)) {
          throw error;
        }
        result.skipped.push({ secret, environment, reason: error.message });
      }
    }
  } finally {
    opened.forEach(({ plaintext }) => plaintext.fill(0));
  }
  return result;
}

/** Re-encrypts values whose recipient set is outdated (stale). */
export function sync(
  document: SecretsDocument,
  identities: readonly Identity[],
  options: { environments?: readonly string[] } = {},
): SyncResult {
  const targets = slots(
    document,
    (slot) =>
      (!options.environments || options.environments.includes(slot.environment)) &&
      inspectCell(document, slot.secret, slot.environment).state === "stale",
  );
  return resealSlots(document, identities, targets, () => {});
}
