import { auditWorkspace, getWorkspaceSnapshot, peekSecretValue } from "@msecrets/core/workflows";

import { getConfigPath } from "./config-path.server.ts";
import { listRuntimePrivateKeyIdentities } from "./runtime-private-keys.server.ts";
import { getNotice, getPanelState } from "./routing.ts";
import type { DashboardPageData, WorkspacePageData } from "./types.ts";
import { hasOptionalGpgImport, listOptionalGpgKeys, uiKeyAccess } from "./ui-key-access.server.ts";

export async function getWorkspacePageData(
  searchParams: URLSearchParams,
): Promise<WorkspacePageData> {
  const configPath = getConfigPath();
  const [audit, snapshot, gpgImportKeys] = await Promise.all([
    auditWorkspace(configPath, { keyAccess: uiKeyAccess }),
    getWorkspaceSnapshot(configPath, { keyAccess: uiKeyAccess }),
    listOptionalGpgKeys(),
  ]);
  const notice = getNotice(searchParams);

  return {
    audit,
    configPath,
    keyManagement: {
      gpgImportAvailable: hasOptionalGpgImport(),
      gpgImportKeys: snapshot.file
        ? gpgImportKeys.filter(
            (key) =>
              !snapshot.file?.keys.some((configured) => configured.fingerprint === key.fingerprint),
          )
        : gpgImportKeys,
      runtimePrivateKeys: listRuntimePrivateKeyIdentities(),
    },
    notice,
    snapshot,
  };
}

export async function getSecretsPageData(
  searchParams: URLSearchParams,
): Promise<DashboardPageData> {
  const { audit, configPath, keyManagement, notice, snapshot } =
    await getWorkspacePageData(searchParams);
  const panel = getPanelState(searchParams);

  let peekError: string | null = null;
  let peekResult: Awaited<ReturnType<typeof peekSecretValue>> | null = null;

  if (snapshot.exists && panel.kind === "peek-secret") {
    try {
      peekResult = await peekSecretValue(
        configPath,
        {
          environment: panel.environment,
          name: panel.secret,
        },
        { keyAccess: uiKeyAccess },
      );
    } catch (error) {
      peekError = error instanceof Error ? error.message : "Failed to decrypt secret";
    }
  }

  return {
    audit,
    configPath,
    keyManagement,
    notice,
    panel,
    peekError,
    peekResult,
    snapshot,
  };
}
