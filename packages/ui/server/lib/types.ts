import type { KeyIdentity } from "@msecrets/core/providers";
import type { WorkspaceAuditReport, WorkspaceSnapshot } from "@msecrets/core/workflows";

export type Notice = {
  message: string;
  tone: "error" | "success";
};

export type PanelState =
  | { kind: "none" }
  | { kind: "create-secret" }
  | { kind: "rename-secret"; secret: string }
  | { environment: string; kind: "peek-secret"; secret: string }
  | { environment: string; kind: "revoke-secret"; secret: string }
  | { environment: string; kind: "set-secret"; secret: string }
  | { environment: string; kind: "share-secret"; secret: string };

export type PeekResult = {
  environment: string;
  info: string;
  name: string;
  payload: string;
};

export type WorkspaceFile = NonNullable<WorkspaceSnapshot["file"]>;
export type WorkspaceAudit = WorkspaceAuditReport;

export type KeyManagementState = {
  gpgImportAvailable: boolean;
  gpgImportKeys: KeyIdentity[];
  runtimePrivateKeys: KeyIdentity[];
};

export type WorkspacePageData = {
  audit: WorkspaceAuditReport;
  configPath: string;
  keyManagement: KeyManagementState;
  notice: Notice | null;
  snapshot: WorkspaceSnapshot;
};

export type DashboardPageData = {
  audit: WorkspaceAuditReport;
  configPath: string;
  keyManagement: KeyManagementState;
  notice: Notice | null;
  panel: PanelState;
  peekError: string | null;
  peekResult: PeekResult | null;
  snapshot: WorkspaceSnapshot;
};
