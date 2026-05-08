import type { SecretsFile } from "../model.ts";
import {
  formatIssue,
  pushError,
  pushWarning,
  type SecretsFileValidationIssue,
  type SecretsFileValidationResult,
  type SecretsFileValidationSeverity,
} from "./issues.ts";
import {
  CURRENT_SECRETS_FILE_VERSION,
  getIncompatibleVersionMessage,
  parseSemverVersion,
  SUPPORTED_SECRETS_FILE_MAJOR,
} from "./version.ts";
import { isRecord, parsePlainObject, validateStringArray } from "./validators.ts";

export {
  CURRENT_SECRETS_FILE_VERSION,
  type SecretsFileValidationIssue,
  type SecretsFileValidationResult,
  type SecretsFileValidationSeverity,
};


export function formatValidationIssues(
  issues: SecretsFileValidationIssue[],
  limit = issues.length,
): string {
  if (!issues.length) {
    return "No validation issues";
  }

  const shownIssues = issues.slice(0, limit);
  const remainingCount = issues.length - shownIssues.length;
  const summary = `${issues.length} validation issue${issues.length === 1 ? "" : "s"} found`;

  return [
    summary,
    ...shownIssues.map(formatIssue),
    remainingCount > 0 ? `...and ${remainingCount} more` : null,
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");
}

export class SecretsFileValidationError extends Error {
  readonly issues: SecretsFileValidationIssue[];

  constructor(issues: SecretsFileValidationIssue[]) {
    super(formatValidationIssues(issues, 10));
    this.name = "SecretsFileValidationError";
    this.issues = issues;
  }
}

export class SecretsFileVersionError extends Error {
  readonly version: string;

  constructor(version: string) {
    super(getIncompatibleVersionMessage(version));
    this.name = "SecretsFileVersionError";
    this.version = version;
  }
}

export function validateSecretsFile(value: unknown): SecretsFileValidationResult {
  const issues: SecretsFileValidationIssue[] = [];
  const root = parsePlainObject(
    value,
    "$",
    issues,
    "file_invalid",
    "Secrets file must be a JSON object",
  );

  if (!root) {
    return { issues, valid: false };
  }

  const versionValue = root["version"];
  const environmentsValue = root["environments"];
  const keysValue = root["keys"];
  const secretsValue = root["secrets"];

  if (versionValue === undefined) {
    pushError(issues, "version_missing", "$.version", "Secrets file version is required");
  } else if (typeof versionValue !== "string") {
    pushError(issues, "version_invalid", "$.version", "Secrets file version must be a string");
  } else if (!versionValue.trim()) {
    pushError(issues, "version_empty", "$.version", "Secrets file version is required");
  } else if (versionValue.trim() !== versionValue) {
    pushError(issues, "version_not_trimmed", "$.version", "Secrets file version must be trimmed");
  } else {
    const parsedVersion = parseSemverVersion(versionValue);

    if (!parsedVersion) {
      pushError(
        issues,
        "version_not_semver",
        "$.version",
        "Secrets file version must be valid semver",
      );
    } else if (parsedVersion.major !== SUPPORTED_SECRETS_FILE_MAJOR) {
      pushError(
        issues,
        "version_incompatible",
        "$.version",
        getIncompatibleVersionMessage(versionValue),
      );
    }
  }

  const environments = validateStringArray(environmentsValue, "$.environments", issues);
  const uniqueEnvironments = new Set<string>();

  environments.forEach((environment, index) => {
    if (uniqueEnvironments.has(environment)) {
      pushError(
        issues,
        "environment_duplicate",
        `$.environments[${index}]`,
        `Duplicate environment ${environment}`,
      );
      return;
    }

    uniqueEnvironments.add(environment);
  });

  if (!uniqueEnvironments.size) {
    pushWarning(
      issues,
      "environment_missing_all",
      "$.environments",
      "No environments are configured",
    );
  }

  const configuredFingerprints = new Set<string>();

  if (!Array.isArray(keysValue)) {
    pushError(issues, "keys_invalid", "$.keys", "Keys must be an array");
  } else {
    keysValue.forEach((key, index) => {
      const keyPath = `$.keys[${index}]`;
      const parsedKey = parsePlainObject(
        key,
        keyPath,
        issues,
        "key_invalid",
        "Key entry must be an object",
      );

      if (!parsedKey) {
        return;
      }

      const fingerprint = parsedKey["fingerprint"];
      const publicKey = parsedKey["publicKey"];
      const userIds = validateStringArray(parsedKey["userIds"], `${keyPath}.userIds`, issues);

      if (typeof fingerprint !== "string" || !fingerprint.trim()) {
        pushError(
          issues,
          "key_fingerprint_missing",
          `${keyPath}.fingerprint`,
          "Key fingerprint is required",
        );
      } else if (fingerprint.trim() !== fingerprint) {
        pushError(
          issues,
          "key_fingerprint_not_trimmed",
          `${keyPath}.fingerprint`,
          "Key fingerprint must be trimmed",
        );
      } else if (configuredFingerprints.has(fingerprint)) {
        pushError(
          issues,
          "key_fingerprint_duplicate",
          `${keyPath}.fingerprint`,
          `Duplicate key fingerprint ${fingerprint}`,
        );
      } else {
        configuredFingerprints.add(fingerprint);
      }

      if (typeof publicKey !== "string" || !publicKey.trim()) {
        pushError(
          issues,
          "key_public_key_missing",
          `${keyPath}.publicKey`,
          "Armored public key is required",
        );
      }

      if (!userIds.length) {
        pushWarning(issues, "key_user_ids_empty", `${keyPath}.userIds`, "Key has no user IDs");
      }
    });
  }

  if (!configuredFingerprints.size) {
    pushWarning(issues, "keys_missing_all", "$.keys", "No recipient keys are configured");
  }

  const parsedSecrets = parsePlainObject(
    secretsValue,
    "$.secrets",
    issues,
    "secrets_invalid",
    "Secrets must be an object",
  );

  if (!parsedSecrets) {
    return { issues, valid: !issues.some((issue) => issue.severity === "error") };
  }

  const environmentUsage = new Map<string, number>();
  uniqueEnvironments.forEach((environment) => {
    environmentUsage.set(environment, 0);
  });

  const secretNames = Object.keys(parsedSecrets);

  if (!secretNames.length) {
    pushWarning(issues, "secrets_missing_all", "$.secrets", "No secrets are configured");
  }

  secretNames.forEach((secretName) => {
    const secretPath = `$.secrets.${JSON.stringify(secretName)}`;
    const secretValue = parsedSecrets[secretName];

    if (!secretName.trim()) {
      pushError(issues, "secret_name_empty", secretPath, "Secret name must not be empty");
    } else if (secretName.trim() !== secretName) {
      pushError(issues, "secret_name_not_trimmed", secretPath, "Secret name must be trimmed");
    }

    const parsedSecret = parsePlainObject(
      secretValue,
      secretPath,
      issues,
      "secret_invalid",
      "Secret entry must be an object",
    );

    if (!parsedSecret) {
      return;
    }

    const description = parsedSecret["description"];
    const values = parsedSecret["values"];

    if (description !== undefined && typeof description !== "string") {
      pushError(
        issues,
        "secret_description_invalid",
        `${secretPath}.description`,
        "Secret description must be a string when provided",
      );
    }

    const parsedValues = parsePlainObject(
      values,
      `${secretPath}.values`,
      issues,
      "secret_values_invalid",
      "Secret values must be an object",
    );

    if (!parsedValues) {
      return;
    }

    const valueEntries = Object.entries(parsedValues);

    if (!valueEntries.length) {
      pushWarning(
        issues,
        "secret_values_empty",
        `${secretPath}.values`,
        `Secret ${secretName} has no values`,
      );
    }

    valueEntries.forEach(([environmentName, valueEntry]) => {
      const valuePath = `${secretPath}.values.${JSON.stringify(environmentName)}`;

      if (!uniqueEnvironments.has(environmentName)) {
        pushError(
          issues,
          "secret_environment_unknown",
          valuePath,
          `Environment ${environmentName} is not declared in $.environments`,
        );
      } else {
        environmentUsage.set(environmentName, (environmentUsage.get(environmentName) ?? 0) + 1);
      }

      const parsedValueEntry = parsePlainObject(
        valueEntry,
        valuePath,
        issues,
        "secret_value_invalid",
        "Secret value must be an object",
      );

      if (!parsedValueEntry) {
        return;
      }

      const encryptedValue = parsedValueEntry["encryptedValue"];
      const owners = parsedValueEntry["owners"];

      if (typeof encryptedValue !== "string" || !encryptedValue.trim()) {
        pushError(
          issues,
          "secret_value_encrypted_missing",
          `${valuePath}.encryptedValue`,
          "Encrypted value is required",
        );
      }

      if (owners === undefined) {
        pushError(
          issues,
          "secret_value_owners_missing",
          `${valuePath}.owners`,
          "Secret value does not declare owners",
        );
        return;
      }

      const ownerValues = validateStringArray(owners, `${valuePath}.owners`, issues);
      const seenOwners = new Set<string>();

      if (!ownerValues.length) {
        pushError(
          issues,
          "secret_value_owners_empty",
          `${valuePath}.owners`,
          "Secret value has an empty owner list",
        );
      }

      ownerValues.forEach((owner, index) => {
        const ownerPath = `${valuePath}.owners[${index}]`;

        if (seenOwners.has(owner)) {
          pushError(issues, "secret_value_owner_duplicate", ownerPath, `Duplicate owner ${owner}`);
          return;
        }

        seenOwners.add(owner);

        if (!configuredFingerprints.has(owner)) {
          pushError(
            issues,
            "secret_value_owner_unknown",
            ownerPath,
            `Owner ${owner} is not present in $.keys`,
          );
        }
      });
    });
  });

  environmentUsage.forEach((usageCount, environment) => {
    if (!usageCount) {
      pushWarning(
        issues,
        "environment_unused",
        `$.environments.${JSON.stringify(environment)}`,
        `Environment ${environment} has no secret values`,
      );
    }
  });

  return {
    issues,
    valid: !issues.some((issue) => issue.severity === "error"),
  };
}

export function assertValidSecretsFile(value: unknown): asserts value is SecretsFile {
  const result = validateSecretsFile(value);
  const incompatibleVersionIssue = result.issues.find(
    (issue) => issue.code === "version_incompatible",
  );
  const parsedRoot = isRecord(value) ? value : null;

  if (
    incompatibleVersionIssue &&
    parsedRoot &&
    typeof parsedRoot["version"] === "string"
  ) {
    throw new SecretsFileVersionError(parsedRoot["version"]);
  }

  const errors = result.issues.filter((issue) => issue.severity === "error");

  if (errors.length) {
    throw new SecretsFileValidationError(errors);
  }
}
