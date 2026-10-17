import { createHash } from "node:crypto";

import {
  type SecretsDocument,
  inspect,
  parseDocumentText,
  recipientKey,
  serializeDocument,
  validateDocument,
} from "../../core/src/index.ts";

const STATE_LABELS = {
  ok: "signed",
  stale: "signed, needs sync",
  invalid: "INVALID SIGNATURE",
  unexpected: "UNEXPECTED",
  missing: "missing",
  absent: "",
} as const;

/**
 * A stable, readable rendering of a secrets file for `git diff` (textconv).
 * Ciphertext is reduced to a short fingerprint, so diffs show what changed:
 * which values, who signed them, and whether the signatures hold.
 */
export function renderForDiff(text: string): string {
  let document: SecretsDocument;
  try {
    document = parseDocumentText(text);
  } catch (error) {
    return `# msecrets: this file is not a valid v4 secrets file\n# ${(error as Error).message.split("\n").join("\n# ")}\n${text}`;
  }

  const lines = [`# msecrets file ${document.id}`, "", "recipients:"];
  for (const name of Object.keys(document.recipients).toSorted()) {
    const key = recipientKey(document, name);
    const fingerprint = createHash("sha256").update(key.token).digest("hex").slice(0, 12);
    const description = document.recipients[name]?.description;
    lines.push(
      `  ${name}: ${key.kind}${key.signingKey ? "" : " (read-only)"} ${fingerprint}${description ? ` # ${description}` : ""}`,
    );
  }

  lines.push("", "environments:");
  for (const [name, environment] of Object.entries(document.environments)) {
    lines.push(`  ${name}: ${environment.recipients.toSorted().join(", ") || "(no recipients)"}`);
  }

  const report = inspect(document);
  lines.push("", "secrets:");
  for (const name of Object.keys(document.secrets).toSorted()) {
    const secret = document.secrets[name];
    lines.push(`  ${name}:${secret?.description ? ` # ${secret.description}` : ""}`);
    if (secret?.environments) {
      lines.push(`    only: ${secret.environments.join(", ")}`);
    }
    for (const cell of report.cells.filter(
      (entry) => entry.secret === name && entry.state !== "absent",
    )) {
      const value = secret?.values[cell.environment];
      const fingerprint = value
        ? createHash("sha256").update(value.data).digest("hex").slice(0, 12)
        : "";
      lines.push(
        `    ${cell.environment}: ${STATE_LABELS[cell.state]}${cell.signer ? ` by ${cell.signer}` : ""}${fingerprint ? ` ${fingerprint}` : ""}`,
      );
    }
  }
  return `${lines.join("\n")}\n`;
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function same(left: Json | undefined, right: Json | undefined): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isObject(value: Json | undefined): value is { [key: string]: Json } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Paths merged as sets of names rather than atomically. */
function isNameSet(path: readonly string[]): boolean {
  return (
    (path.length === 3 && path[0] === "environments" && path[2] === "recipients") ||
    (path.length === 3 && path[0] === "secrets" && path[2] === "environments")
  );
}

/** Paths whose values must never be merged field by field. */
function isAtomic(path: readonly string[]): boolean {
  return (
    (path.length === 2 && path[0] === "recipients") ||
    (path.length === 4 && path[0] === "secrets" && path[2] === "values")
  );
}

function mergeNameSets(
  base: Json | undefined,
  ours: Json | undefined,
  theirs: Json | undefined,
): Json {
  const list = (value: Json | undefined) =>
    Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
  // Union of both sides, minus names that either side removed.
  const removed = new Set(
    list(base).filter((name) => !list(ours).includes(name) || !list(theirs).includes(name)),
  );
  return [...new Set([...list(ours), ...list(theirs)])].filter((name) => !removed.has(name));
}

function merge3(
  base: Json | undefined,
  ours: Json | undefined,
  theirs: Json | undefined,
  path: string[],
  conflicts: string[],
): Json | undefined {
  if (same(ours, theirs)) {
    return ours;
  }
  if (same(base, ours)) {
    return theirs;
  }
  if (same(base, theirs)) {
    return ours;
  }
  if (isNameSet(path)) {
    // A secret without "environments" applies to every environment; that is not a list to merge.
    if (path[0] === "secrets" && ![base, ours, theirs].every(Array.isArray)) {
      conflicts.push(path.join("."));
      return ours;
    }
    return mergeNameSets(base, ours, theirs);
  }
  if (!isAtomic(path) && isObject(ours) && isObject(theirs)) {
    const baseObject = isObject(base) ? base : {};
    // No prototype: keys come from untrusted files and may include "__proto__".
    const result = Object.create(null) as { [key: string]: Json };
    for (const key of new Set([...Object.keys(ours), ...Object.keys(theirs)])) {
      const merged = merge3(baseObject[key], ours[key], theirs[key], [...path, key], conflicts);
      if (merged !== undefined) {
        result[key] = merged;
      }
    }
    return result;
  }
  conflicts.push(path.join(".") || "(file)");
  return ours;
}

export type MergeResult = { text: string; conflicts: string[] };

/**
 * Three-way structural merge of secrets files. Independent changes merge
 * cleanly; changes to the same value conflict and keep "ours".
 */
function parseJson(text: string): Json | undefined {
  try {
    return JSON.parse(text) as Json;
  } catch {
    // An unparsable side (e.g. an empty base for a newly added file) merges as absent.
    return undefined;
  }
}

export function mergeDocuments(
  baseText: string,
  oursText: string,
  theirsText: string,
): MergeResult {
  const conflicts: string[] = [];
  const merged = merge3(
    parseJson(baseText),
    parseJson(oursText),
    parseJson(theirsText),
    [],
    conflicts,
  );
  const { document, issues } = validateDocument(merged);

  if (!document) {
    return {
      text: oursText,
      conflicts: [...conflicts, ...issues.map((issue) => `${issue.path}: ${issue.message}`)],
    };
  }
  return { text: serializeDocument(document), conflicts };
}
