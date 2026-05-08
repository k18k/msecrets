export type SecretsFileValidationSeverity = "error" | "warning";

export type SecretsFileValidationIssue = {
  code: string;
  message: string;
  path: string;
  severity: SecretsFileValidationSeverity;
};

export type SecretsFileValidationResult = {
  issues: SecretsFileValidationIssue[];
  valid: boolean;
};

export function pushError(
  issues: SecretsFileValidationIssue[],
  code: string,
  path: string,
  message: string,
) {
  issues.push({ code, message, path, severity: "error" });
}

export function pushWarning(
  issues: SecretsFileValidationIssue[],
  code: string,
  path: string,
  message: string,
) {
  issues.push({ code, message, path, severity: "warning" });
}

export function formatIssue(issue: SecretsFileValidationIssue): string {
  return `[${issue.severity}] ${issue.path}: ${issue.message}`;
}
