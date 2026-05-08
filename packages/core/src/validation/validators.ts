import { pushError, type SecretsFileValidationIssue } from "./issues.ts";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parsePlainObject(
  value: unknown,
  path: string,
  issues: SecretsFileValidationIssue[],
  code: string,
  message: string,
): Record<string, unknown> | null {
  if (!isRecord(value)) {
    pushError(issues, code, path, message);
    return null;
  }

  return value;
}

export function validateStringArray(
  value: unknown,
  path: string,
  issues: SecretsFileValidationIssue[],
): string[] {
  if (!Array.isArray(value)) {
    pushError(issues, "array_required", path, "Expected an array");
    return [];
  }

  const values: string[] = [];

  value.forEach((entry, index) => {
    const entryPath = `${path}[${index}]`;

    if (typeof entry !== "string") {
      pushError(issues, "string_required", entryPath, "Expected a string");
      return;
    }

    const normalizedEntry = entry.trim();

    if (!normalizedEntry) {
      pushError(issues, "string_empty", entryPath, "String must not be empty");
      return;
    }

    if (normalizedEntry !== entry) {
      pushError(issues, "string_not_trimmed", entryPath, "String must be trimmed");
      return;
    }

    values.push(normalizedEntry);
  });

  return values;
}
