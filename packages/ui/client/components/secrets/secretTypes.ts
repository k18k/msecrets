import type { WorkspaceFile } from "../../../server/lib/types.ts";

export type SecretValueTarget = {
  environment: string;
  secretName: string;
};

export type SecretTarget = {
  secretName: string;
};

export type SecretDetailPanel =
  | { type: "none" }
  | { environment?: string; type: "set-value" }
  | { environment: string; type: "peek" }
  | { environment: string; type: "share" }
  | { environment: string; type: "revoke" }
  | { environment: string; type: "remove-value" };

export function getSecretDescription(file: WorkspaceFile, secretName: string): string {
  return file.secrets[secretName]?.description ?? "";
}

export function getSecretValues(file: WorkspaceFile, secretName: string) {
  return file.secrets[secretName]?.values ?? {};
}
