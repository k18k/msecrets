import { getConfiguredKeyFingerprints } from "../domain/keys.ts";
import { getSecretNames } from "../domain/secrets.ts";
import {
  getSecretsFile,
  hasSecretsFile,
  readSecretsFileData,
  writeSecretsFile,
} from "../file-store.ts";
import type { SecretsFile } from "../model.ts";
import {
  assertValidSecretsFile,
  type SecretsFileValidationIssue,
  type SecretsFileValidationResult,
  validateSecretsFile,
} from "../validation/index.ts";
import {
  getEnvironmentUsageReports,
  type EnvironmentUsageReport,
} from "../domain/environments.ts";
import {
  createEmptySecretsFile,
  resolveWorkflowDependencies,
  type WorkflowDependencyOverrides,
} from "./deps.ts";
import type { KeyIdentity } from "../keys/types.ts";

export type WorkspaceSnapshot = {
  exists: boolean;
  file: SecretsFile | null;
  importableKeys: KeyIdentity[];
  localKeys: KeyIdentity[];
};

export type WorkspaceAuditFinding = SecretsFileValidationIssue & {
  source: "file" | "workspace";
};

export type WorkspaceAuditReport = {
  exists: boolean;
  file: SecretsFile | null;
  findings: WorkspaceAuditFinding[];
  importableKeys: KeyIdentity[];
  localKeys: KeyIdentity[];
  path: string;
  summary: {
    configuredKeyCount: number;
    emptySecrets: string[];
    environmentCount: number;
    environmentUsage: EnvironmentUsageReport[];
    importableKeyCount: number;
    localKeyCount: number;
    secretCount: number;
    valueCount: number;
  };
  valid: boolean;
};

function createWorkspaceFinding(
  finding: Omit<WorkspaceAuditFinding, "source">,
  source: WorkspaceAuditFinding["source"],
): WorkspaceAuditFinding {
  return {
    ...finding,
    source,
  };
}

function countSecretValues(file: SecretsFile): number {
  return Object.values(file.secrets).reduce(
    (count, secret) => count + Object.keys(secret.values).length,
    0,
  );
}

function getEmptySecrets(file: SecretsFile): string[] {
  return getSecretNames(file).filter((secretName) => {
    const secret = file.secrets[secretName];
    return secret ? Object.keys(secret.values).length === 0 : false;
  });
}

export async function getWorkspaceSnapshot(
  path: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<WorkspaceSnapshot> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const localKeys = await keyAccess.listAllKeys();

  if (!hasSecretsFile(path)) {
    return {
      exists: false,
      file: null,
      importableKeys: localKeys,
      localKeys,
    };
  }

  const file = getSecretsFile(path);
  const configuredFingerprints = getConfiguredKeyFingerprints(file);

  return {
    exists: true,
    file,
    importableKeys: localKeys.filter((key) => !configuredFingerprints.has(key.fingerprint)),
    localKeys,
  };
}

export async function auditWorkspace(
  path: string,
  dependencies?: WorkflowDependencyOverrides,
): Promise<WorkspaceAuditReport> {
  const { keyAccess } = resolveWorkflowDependencies(dependencies);
  const localKeys = await keyAccess.listAllKeys();

  if (!hasSecretsFile(path)) {
    return {
      exists: false,
      file: null,
      findings: [
        createWorkspaceFinding(
          {
            code: "workspace_missing",
            message: `Secrets file not found at ${path}`,
            path: "$",
            severity: "warning",
          },
          "workspace",
        ),
      ],
      importableKeys: localKeys,
      localKeys,
      path,
      summary: {
        configuredKeyCount: 0,
        emptySecrets: [],
        environmentCount: 0,
        environmentUsage: [],
        importableKeyCount: localKeys.length,
        localKeyCount: localKeys.length,
        secretCount: 0,
        valueCount: 0,
      },
      valid: false,
    };
  }

  let validation: SecretsFileValidationResult;
  let file: SecretsFile | null = null;

  try {
    const rawFile = readSecretsFileData(path);
    validation = validateSecretsFile(rawFile);

    if (validation.valid) {
      assertValidSecretsFile(rawFile);
      file = rawFile;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to parse secrets file";

    validation = {
      issues: [
        {
          code: "file_parse_failed",
          message,
          path: "$",
          severity: "error",
        },
      ],
      valid: false,
    };
  }

  const findings = validation.issues.map((issue) => createWorkspaceFinding(issue, "file"));

  if (!localKeys.length) {
    findings.push(
      createWorkspaceFinding(
        {
          code: "local_keys_missing_all",
          message: "No private keys are available through the current runtime key sources",
          path: "$.keys",
          severity: "warning",
        },
        "workspace",
      ),
    );
  }

  if (!file) {
    return {
      exists: true,
      file: null,
      findings,
      importableKeys: localKeys,
      localKeys,
      path,
      summary: {
        configuredKeyCount: 0,
        emptySecrets: [],
        environmentCount: 0,
        environmentUsage: [],
        importableKeyCount: localKeys.length,
        localKeyCount: localKeys.length,
        secretCount: 0,
        valueCount: 0,
      },
      valid: false,
    };
  }

  const configuredFingerprints = getConfiguredKeyFingerprints(file);
  const localFingerprints = new Set(localKeys.map((key) => key.fingerprint));

  file.keys.forEach((key) => {
    if (!localFingerprints.has(key.fingerprint)) {
      findings.push(
        createWorkspaceFinding(
          {
            code: "configured_key_missing_locally",
            message: `Configured key ${key.fingerprint} is not available through the current runtime key sources`,
            path: "$.keys",
            severity: "warning",
          },
          "workspace",
        ),
      );
    }
  });

  return {
    exists: true,
    file,
    findings,
    importableKeys: localKeys.filter((key) => !configuredFingerprints.has(key.fingerprint)),
    localKeys,
    path,
    summary: {
      configuredKeyCount: file.keys.length,
      emptySecrets: getEmptySecrets(file),
      environmentCount: file.environments.length,
      environmentUsage: getEnvironmentUsageReports(file),
      importableKeyCount: localKeys.filter((key) => !configuredFingerprints.has(key.fingerprint))
        .length,
      localKeyCount: localKeys.length,
      secretCount: getSecretNames(file).length,
      valueCount: countSecretValues(file),
    },
    valid: validation.valid,
  };
}

export function initializeSecretsFile(path: string): { created: boolean } {
  if (hasSecretsFile(path)) {
    return { created: false };
  }

  writeSecretsFile(path, createEmptySecretsFile());
  return { created: true };
}
