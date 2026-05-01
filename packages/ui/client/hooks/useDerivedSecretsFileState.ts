import { useMemo } from "react";

import type { WorkspaceAudit, WorkspaceFile } from "../../server/lib/types.ts";

export type SecretValueStatus =
  | "encrypted"
  | "missing"
  | "unknown-owner"
  | "duplicate-owner"
  | "empty-owners"
  | "warning"
  | "error";

export type SecretMatrixCell = {
  encryptedValuePreview?: string;
  environment: string;
  ownerLabels: string[];
  owners: string[];
  secretName: string;
  status: SecretValueStatus;
};

export type Diagnostic = {
  action?: "add-environment" | "create-secret" | "import-public-key" | "set-values";
  group: "file/root" | "environments" | "keys" | "owners" | "runtime/private keys" | "secrets";
  message: string;
  path: string;
  severity: "error" | "warning";
};

export type DerivedSecretsFileState = {
  diagnostics: Diagnostic[];
  duplicateOwnerValues: SecretMatrixCell[];
  encryptedValueCount: number;
  environmentCount: number;
  environmentsWithNoValues: string[];
  errorCount: number;
  keyOwnershipCounts: Map<string, number>;
  keysCount: number;
  matrixCells: SecretMatrixCell[];
  missingValueCount: number;
  missingValuesByEnvironment: Map<string, number>;
  secretCount: number;
  secretNames: string[];
  secretsWithNoValues: string[];
  soleOwnerValues: SecretMatrixCell[];
  unknownOwnerValues: SecretMatrixCell[];
  valuesByOwner: Map<string, SecretMatrixCell[]>;
  warningCount: number;
};

function getOwnerLabel(file: WorkspaceFile, fingerprint: string): string {
  const key = file.keys.find((candidate) => candidate.fingerprint === fingerprint);
  return key?.userIds[0] ?? fingerprint.slice(-12);
}

function getValueStatus(file: WorkspaceFile, owners: string[]): SecretValueStatus {
  if (!owners.length) {
    return "empty-owners";
  }

  if (new Set(owners).size !== owners.length) {
    return "duplicate-owner";
  }

  const configured = new Set(file.keys.map((key) => key.fingerprint));
  if (owners.some((owner) => !configured.has(owner))) {
    return "unknown-owner";
  }

  return "encrypted";
}

function classifyPath(path: string, message: string): Diagnostic["group"] {
  if (path.includes(".environments") || message.toLowerCase().includes("environment")) {
    return "environments";
  }

  if (path.includes(".keys") || message.toLowerCase().includes("key")) {
    if (message.toLowerCase().includes("private") || message.toLowerCase().includes("runtime")) {
      return "runtime/private keys";
    }

    return "keys";
  }

  if (message.toLowerCase().includes("owner")) {
    return "owners";
  }

  if (path.includes(".secrets") || message.toLowerCase().includes("secret")) {
    return "secrets";
  }

  return "file/root";
}

function getAction(message: string): Diagnostic["action"] | undefined {
  const normalized = message.toLowerCase();

  if (normalized.includes("no environments")) {
    return "add-environment";
  }

  if (normalized.includes("no recipient") || normalized.includes("no configured")) {
    return "import-public-key";
  }

  if (normalized.includes("no secrets")) {
    return "create-secret";
  }

  if (normalized.includes("no secret values") || normalized.includes("has no values")) {
    return "set-values";
  }

  return undefined;
}

export function deriveSecretsFileState(
  file: WorkspaceFile | null,
  audit: WorkspaceAudit,
): DerivedSecretsFileState {
  const auditDiagnostics: Diagnostic[] = audit.findings.map((finding) => ({
    action: getAction(finding.message),
    group: classifyPath(finding.path, finding.message),
    message: finding.message,
    path: finding.path,
    severity: finding.severity,
  }));

  if (!file) {
    return {
      diagnostics: auditDiagnostics,
      duplicateOwnerValues: [],
      encryptedValueCount: 0,
      environmentCount: 0,
      environmentsWithNoValues: [],
      errorCount: auditDiagnostics.filter((item) => item.severity === "error").length,
      keyOwnershipCounts: new Map(),
      keysCount: 0,
      matrixCells: [],
      missingValueCount: 0,
      missingValuesByEnvironment: new Map(),
      secretCount: 0,
      secretNames: [],
      secretsWithNoValues: [],
      soleOwnerValues: [],
      unknownOwnerValues: [],
      valuesByOwner: new Map(),
      warningCount: auditDiagnostics.filter((item) => item.severity === "warning").length,
    };
  }

  const secretNames = Object.keys(file.secrets).sort();
  const matrixCells: SecretMatrixCell[] = [];
  const valuesByOwner = new Map<string, SecretMatrixCell[]>();
  const keyOwnershipCounts = new Map(file.keys.map((key) => [key.fingerprint, 0]));
  const missingValuesByEnvironment = new Map(
    file.environments.map((environment) => [environment, 0]),
  );
  const environmentValueCounts = new Map(file.environments.map((environment) => [environment, 0]));

  for (const secretName of secretNames) {
    const secret = file.secrets[secretName];

    for (const environment of file.environments) {
      const value = secret?.values[environment];
      const cell: SecretMatrixCell = value
        ? {
            encryptedValuePreview: value.encryptedValue.slice(0, 38),
            environment,
            ownerLabels: value.owners.map((owner) => getOwnerLabel(file, owner)),
            owners: value.owners,
            secretName,
            status: getValueStatus(file, value.owners),
          }
        : {
            environment,
            ownerLabels: [],
            owners: [],
            secretName,
            status: "missing",
          };

      if (cell.status === "missing") {
        missingValuesByEnvironment.set(
          environment,
          (missingValuesByEnvironment.get(environment) ?? 0) + 1,
        );
      } else {
        environmentValueCounts.set(environment, (environmentValueCounts.get(environment) ?? 0) + 1);
        for (const owner of cell.owners) {
          const current = valuesByOwner.get(owner) ?? [];
          current.push(cell);
          valuesByOwner.set(owner, current);
          keyOwnershipCounts.set(owner, (keyOwnershipCounts.get(owner) ?? 0) + 1);
        }
      }

      matrixCells.push(cell);
    }
  }

  const encryptedValueCount = matrixCells.filter((cell) => cell.status !== "missing").length;
  const missingValueCount = matrixCells.filter((cell) => cell.status === "missing").length;
  const secretsWithNoValues = secretNames.filter(
    (secretName) => Object.keys(file.secrets[secretName]?.values ?? {}).length === 0,
  );
  const environmentsWithNoValues = file.environments.filter(
    (environment) => (environmentValueCounts.get(environment) ?? 0) === 0,
  );
  const unknownOwnerValues = matrixCells.filter((cell) => cell.status === "unknown-owner");
  const duplicateOwnerValues = matrixCells.filter((cell) => cell.status === "duplicate-owner");
  const soleOwnerValues = matrixCells.filter(
    (cell) => cell.status !== "missing" && cell.owners.length === 1,
  );

  const derivedDiagnostics: Diagnostic[] = [
    ...secretsWithNoValues.map((secretName) => ({
      action: "set-values" as const,
      group: "secrets" as const,
      message: `Secret ${secretName} has no values`,
      path: `$.secrets.${secretName}.values`,
      severity: "warning" as const,
    })),
    ...environmentsWithNoValues.map((environment) => ({
      action: "set-values" as const,
      group: "environments" as const,
      message: `Declared environment ${environment} has no secret values`,
      path: `$.environments.${environment}`,
      severity: "warning" as const,
    })),
  ];

  const diagnostics = [...auditDiagnostics, ...derivedDiagnostics];

  return {
    diagnostics,
    duplicateOwnerValues,
    encryptedValueCount,
    environmentCount: file.environments.length,
    environmentsWithNoValues,
    errorCount: diagnostics.filter((item) => item.severity === "error").length,
    keyOwnershipCounts,
    keysCount: file.keys.length,
    matrixCells,
    missingValueCount,
    missingValuesByEnvironment,
    secretCount: secretNames.length,
    secretNames,
    secretsWithNoValues,
    soleOwnerValues,
    unknownOwnerValues,
    valuesByOwner,
    warningCount: diagnostics.filter((item) => item.severity === "warning").length,
  };
}

export function useDerivedSecretsFileState(file: WorkspaceFile | null, audit: WorkspaceAudit) {
  return useMemo(() => deriveSecretsFileState(file, audit), [audit, file]);
}
