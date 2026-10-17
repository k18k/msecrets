/**
 * The `.env.ms.json` v4 file format: the compatibility contract of msecrets.
 *
 * Structural validation lives here. Cryptographic state (signatures,
 * recipient drift, completeness) is evaluated by `status.ts`.
 */
import { randomBytes } from "./crypto/primitives.ts";
import { MsecretsError } from "./errors.ts";
import { parsePublicKey } from "./keys.ts";

export const FORMAT_VERSION = 4;
export const DEFAULT_FILENAME = ".env.ms.json";
export const SCHEMA_URL = "https://cdn.jsdelivr.net/npm/@msecrets/ts-sdk@4/schema/v4.json";

export type RecipientEntry = {
  /** Public key token: msecrets1…, age1…, age1pq1…, or ssh-ed25519 AAAA…. */
  key: string;
  description?: string;
};

export type EnvironmentEntry = {
  /** Names of the recipients that can read (and, if able to sign, write) this environment. */
  recipients: string[];
};

export type SealedValue = {
  /** Digest of the recipient keys the value is encrypted to. */
  to: string;
  /** Name of the recipient that signed the value. */
  by: string;
  /** Ed25519 signature (base64) over the value binding. */
  sig: string;
  /** The age-encrypted value (base64). */
  data: string;
};

export type SecretEntry = {
  description?: string;
  /** Environments this secret applies to. Absent means every environment. */
  environments?: string[];
  values: Record<string, SealedValue>;
};

export type SecretsDocument = {
  version: typeof FORMAT_VERSION;
  /** Random file identifier, bound into every value signature. */
  id: string;
  recipients: Record<string, RecipientEntry>;
  environments: Record<string, EnvironmentEntry>;
  secrets: Record<string, SecretEntry>;
};

export type ValidationIssue = { path: string; message: string };

export type NameKind = "secret" | "environment" | "recipient";

const NAME_RULES: Record<NameKind, { pattern: RegExp; description: string }> = {
  secret: {
    pattern: /^[A-Za-z_][A-Za-z0-9_]{0,127}$/,
    description:
      "letters, digits, and underscores, not starting with a digit (a valid environment variable name)",
  },
  environment: {
    pattern: /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/,
    description:
      "lowercase letters, digits, '.', '_', and '-', starting and ending with a letter or digit",
  },
  recipient: {
    pattern: /^[a-z0-9](?:[a-z0-9._@+-]{0,62}[a-z0-9])?$/,
    description:
      "lowercase letters, digits, '.', '_', '@', '+', and '-', starting and ending with a letter or digit",
  },
};

export function nameProblem(kind: NameKind, name: string): string | null {
  if (name === "__proto__") {
    return `"__proto__" is reserved`;
  }
  const rule = NAME_RULES[kind];
  return rule.pattern.test(name)
    ? null
    : `Invalid ${kind} name ${JSON.stringify(name)}: use ${rule.description}`;
}

/** Control characters in displayed text could rewrite what a terminal shows (escape sequence injection). */
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;
const CONTROL_CHARACTERS_GLOBAL = new RegExp(CONTROL_CHARACTERS.source, "g");

export function descriptionProblem(text: string): string | null {
  if (!text || text !== text.trim() || text.length > 1000) {
    return "Descriptions must be non-empty, trimmed, and at most 1000 characters";
  }
  return CONTROL_CHARACTERS.test(text) ? "Descriptions must not contain control characters" : null;
}

/** Trims a description for storage; empty means none. Throws on invalid text. */
export function normalizeDescription(description: string | undefined): string | undefined {
  const text = description?.trim();
  if (!text) {
    return undefined;
  }
  const problem = descriptionProblem(text);
  if (problem) {
    throw new MsecretsError("USAGE", problem);
  }
  return text;
}

export function requireName(kind: NameKind, name: string): string {
  const problem = nameProblem(kind, name);
  if (problem) {
    throw new MsecretsError("USAGE", problem);
  }
  return name;
}

/** Own-property lookup that is safe for names like "constructor". */
export function own<T>(record: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

export function createDocument(): SecretsDocument {
  return {
    version: FORMAT_VERSION,
    id: randomBytes(16).toString("hex"),
    recipients: {},
    environments: {},
    secrets: {},
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const BASE64_PADDED = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const AGE_PREFIX = Buffer.from("age-encryption.org/v1\n");

class Validator {
  readonly issues: ValidationIssue[] = [];

  issue(path: string, message: string): void {
    this.issues.push({ path, message });
  }

  object(
    value: unknown,
    path: string,
    keys: { required: string[]; optional: string[] },
  ): Record<string, unknown> | null {
    if (!isRecord(value)) {
      this.issue(path, "Expected an object");
      return null;
    }
    for (const key of keys.required) {
      if (!Object.hasOwn(value, key)) {
        this.issue(path, `Missing property "${key}"`);
      }
    }
    for (const key of Object.keys(value)) {
      if (!keys.required.includes(key) && !keys.optional.includes(key)) {
        this.issue(`${path}.${key}`, "Unknown property");
      }
    }
    return value;
  }

  string(value: unknown, path: string): string | null {
    if (typeof value !== "string") {
      this.issue(path, "Expected a string");
      return null;
    }
    return value;
  }

  description(value: unknown, path: string): string | undefined {
    if (value === undefined) {
      return undefined;
    }
    const text = this.string(value, path);
    const problem = text === null ? null : descriptionProblem(text);
    if (problem) {
      this.issue(path, problem);
    }
    return text ?? undefined;
  }

  record(value: unknown, path: string, kind: NameKind): [string, unknown][] {
    if (!isRecord(value)) {
      this.issue(path, "Expected an object");
      return [];
    }
    return Object.entries(value).filter(([name]) => {
      const problem = nameProblem(kind, name);
      if (problem) {
        this.issue(`${path}.${name}`, problem);
      }
      return !problem;
    });
  }

  nameList(value: unknown, path: string, known: ReadonlySet<string>, what: string): string[] {
    if (!Array.isArray(value)) {
      this.issue(path, "Expected an array");
      return [];
    }
    const names: string[] = [];
    value.forEach((entry: unknown, index) => {
      if (typeof entry !== "string" || !known.has(entry)) {
        this.issue(`${path}[${index}]`, `Unknown ${what} ${JSON.stringify(entry)}`);
      } else if (names.includes(entry)) {
        this.issue(`${path}[${index}]`, `Duplicate ${what} "${entry}"`);
      } else {
        names.push(entry);
      }
    });
    return names;
  }
}

function validateRecipient(
  v: Validator,
  value: unknown,
  path: string,
): { entry: RecipientEntry; keyId: string } | null {
  const entry = v.object(value, path, { required: ["key"], optional: ["description"] });
  const key = entry && v.string(entry["key"], `${path}.key`);
  if (!entry || key === null) {
    return null;
  }

  let keyId = key;
  try {
    const parsed = parsePublicKey(key);
    keyId = `${parsed.kind}:${parsed.encryptionKey.toString("hex")}`;
    if (parsed.token !== key) {
      v.issue(`${path}.key`, `Public key is not in canonical form; expected "${parsed.token}"`);
    }
  } catch (error) {
    v.issue(`${path}.key`, error instanceof Error ? error.message : String(error));
  }

  const description = v.description(entry["description"], `${path}.description`);
  return { entry: description === undefined ? { key } : { key, description }, keyId };
}

function validateValue(
  v: Validator,
  value: unknown,
  path: string,
  recipients: ReadonlySet<string>,
): SealedValue | null {
  const entry = v.object(value, path, { required: ["to", "by", "sig", "data"], optional: [] });
  if (!entry) {
    return null;
  }

  const to = v.string(entry["to"], `${path}.to`);
  const by = v.string(entry["by"], `${path}.by`);
  const sig = v.string(entry["sig"], `${path}.sig`);
  const data = v.string(entry["data"], `${path}.data`);

  if (to !== null && !/^[0-9a-f]{32}$/.test(to)) {
    v.issue(`${path}.to`, "Expected a 32 character lowercase hex recipient digest");
  }
  if (by !== null && !recipients.has(by)) {
    v.issue(`${path}.by`, `Unknown recipient "${by}"`);
  }
  if (sig !== null && !(BASE64_PADDED.test(sig) && Buffer.from(sig, "base64").length === 64)) {
    v.issue(`${path}.sig`, "Expected a base64 Ed25519 signature");
  }
  if (
    data !== null &&
    !(
      BASE64_PADDED.test(data) &&
      Buffer.from(data, "base64").subarray(0, AGE_PREFIX.length).equals(AGE_PREFIX)
    )
  ) {
    v.issue(`${path}.data`, "Expected a base64-encoded age file");
  }

  return to !== null && by !== null && sig !== null && data !== null ? { to, by, sig, data } : null;
}

function validateSecret(
  v: Validator,
  value: unknown,
  path: string,
  environments: ReadonlySet<string>,
  recipients: ReadonlySet<string>,
): SecretEntry | null {
  const entry = v.object(value, path, {
    required: ["values"],
    optional: ["description", "environments"],
  });
  if (!entry) {
    return null;
  }

  const secret: SecretEntry = { values: {} };
  const description = v.description(entry["description"], `${path}.description`);
  if (description !== undefined) {
    secret.description = description;
  }
  if (entry["environments"] !== undefined) {
    secret.environments = v.nameList(
      entry["environments"],
      `${path}.environments`,
      environments,
      "environment",
    );
    if (!secret.environments.length) {
      v.issue(
        `${path}.environments`,
        "Must list at least one environment; omit it to apply to all environments",
      );
    }
  }

  for (const [environment, sealed] of v.record(entry["values"], `${path}.values`, "environment")) {
    if (!environments.has(environment)) {
      v.issue(`${path}.values.${environment}`, `Unknown environment "${environment}"`);
      continue;
    }
    const parsed = validateValue(v, sealed, `${path}.values.${environment}`, recipients);
    if (parsed) {
      secret.values[environment] = parsed;
    }
  }

  return secret;
}

/** Validates untrusted input against the v4 format, returning a normalized document when valid. */
export function validateDocument(input: unknown): {
  document: SecretsDocument | null;
  issues: ValidationIssue[];
} {
  const v = new Validator();

  if (isRecord(input) && input["version"] !== FORMAT_VERSION) {
    const version = input["version"];
    v.issue(
      "$.version",
      typeof version === "string" && /^[0-3]\./.test(version)
        ? `This is a msecrets v${version.split(".")[0]} file; msecrets v4 uses a new format. Re-create it with \`msecrets init\` and \`msecrets import\``
        : `Unsupported format version ${JSON.stringify(version)}; expected ${FORMAT_VERSION}`,
    );
    return { document: null, issues: v.issues };
  }

  const root = v.object(input, "$", {
    required: ["version", "id", "recipients", "environments", "secrets"],
    optional: ["$schema"],
  });
  if (!root) {
    return { document: null, issues: v.issues };
  }

  const id = v.string(root["id"], "$.id");
  if (id !== null && !/^[0-9a-f]{32}$/.test(id)) {
    v.issue("$.id", "Expected a 32 character lowercase hex file id");
  }

  const document: SecretsDocument = { ...createDocument(), id: id ?? "" };

  const seenKeys = new Map<string, string>();
  for (const [name, value] of v.record(root["recipients"], "$.recipients", "recipient")) {
    const recipient = validateRecipient(v, value, `$.recipients.${name}`);
    if (!recipient) {
      continue;
    }
    const duplicate = seenKeys.get(recipient.keyId);
    if (duplicate) {
      v.issue(`$.recipients.${name}.key`, `Same key as recipient "${duplicate}"`);
    }
    seenKeys.set(recipient.keyId, name);
    document.recipients[name] = recipient.entry;
  }

  const recipientNames = new Set(Object.keys(document.recipients));
  for (const [name, value] of v.record(root["environments"], "$.environments", "environment")) {
    const entry = v.object(value, `$.environments.${name}`, {
      required: ["recipients"],
      optional: [],
    });
    if (entry) {
      document.environments[name] = {
        recipients: v.nameList(
          entry["recipients"],
          `$.environments.${name}.recipients`,
          recipientNames,
          "recipient",
        ),
      };
    }
  }

  const environmentNames = new Set(Object.keys(document.environments));
  for (const [name, value] of v.record(root["secrets"], "$.secrets", "secret")) {
    const secret = validateSecret(v, value, `$.secrets.${name}`, environmentNames, recipientNames);
    if (secret) {
      document.secrets[name] = secret;
    }
  }

  return { document: v.issues.length ? null : document, issues: v.issues };
}

export function formatIssues(issues: readonly ValidationIssue[]): string {
  return issues
    .map((issue) =>
      `  ${issue.path}: ${issue.message}`.replace(CONTROL_CHARACTERS_GLOBAL, "\ufffd"),
    )
    .join("\n");
}

export function parseDocument(input: unknown, source = "secrets file"): SecretsDocument {
  const { document, issues } = validateDocument(input);
  if (!document) {
    throw new MsecretsError("INVALID_FILE", `Invalid ${source}:\n${formatIssues(issues)}`);
  }
  return document;
}

export function parseDocumentText(text: string, source = "secrets file"): SecretsDocument {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (error) {
    throw new MsecretsError(
      "INVALID_FILE",
      `Invalid ${source}: ${error instanceof Error ? error.message : String(error)}`,
      {
        cause: error,
      },
    );
  }
  return parseDocument(json, source);
}

function sortedRecord<T, R>(record: Record<string, T>, map: (value: T) => R): Record<string, R> {
  return Object.fromEntries(
    Object.keys(record)
      .toSorted()
      .map((key) => [key, map(record[key] as T)]),
  );
}

/** Canonical serialization: deterministic key order keeps diffs and merges minimal. */
export function serializeDocument(document: SecretsDocument): string {
  const environmentOrder = Object.keys(document.environments);
  const ordered = {
    $schema: SCHEMA_URL,
    version: FORMAT_VERSION,
    id: document.id,
    recipients: sortedRecord(document.recipients, ({ key, description }) => ({
      key,
      ...(description === undefined ? {} : { description }),
    })),
    environments: Object.fromEntries(
      environmentOrder.map((name) => [
        name,
        { recipients: (document.environments[name]?.recipients ?? []).toSorted() },
      ]),
    ),
    secrets: sortedRecord(document.secrets, ({ description, environments, values }) => ({
      ...(description === undefined ? {} : { description }),
      ...(environments === undefined
        ? {}
        : { environments: environmentOrder.filter((name) => environments.includes(name)) }),
      values: Object.fromEntries(
        environmentOrder.flatMap((name) => {
          const value = own(values, name);
          return value
            ? [[name, { to: value.to, by: value.by, sig: value.sig, data: value.data }]]
            : [];
        }),
      ),
    })),
  };
  return `${JSON.stringify(ordered, null, 2)}\n`;
}

/** Environments a secret is expected to have a value in. */
export function secretEnvironments(document: SecretsDocument, secret: SecretEntry): string[] {
  return Object.keys(document.environments).filter(
    (name) => !secret.environments || secret.environments.includes(name),
  );
}
