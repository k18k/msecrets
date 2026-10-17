/**
 * Inspection of a secrets document: completeness, recipient drift, signatures,
 * and access configuration. Needs public data only, so it runs anywhere (CI).
 */
import { type SecretsDocument, own, secretEnvironments } from "./document.ts";
import { environmentDigest, recipientKey, signatureProblem } from "./values.ts";

export type CellState =
  /** Signed, current, and encrypted to the environment's current recipients. */
  | "ok"
  /** Valid, but encrypted to an outdated recipient set; `msecrets sync` fixes it. */
  | "stale"
  /** The secret applies to the environment but has no value there. */
  | "missing"
  /** The signature does not verify; the value must not be trusted. */
  | "invalid"
  /** A value exists in an environment the secret does not apply to. */
  | "unexpected"
  /** No value, and none expected. */
  | "absent";

export type Cell = {
  secret: string;
  environment: string;
  state: CellState;
  /** Recipient that signed the value. */
  signer?: string;
  detail?: string;
};

export type Finding = {
  level: "error" | "warning";
  message: string;
  secret?: string;
  environment?: string;
  recipient?: string;
};

export type Report = {
  cells: Cell[];
  findings: Finding[];
  /** True when there are no errors: every value is present, current, and signed. */
  ok: boolean;
};

export function inspectCell(
  document: SecretsDocument,
  secretName: string,
  environment: string,
): Cell {
  const secret = own(document.secrets, secretName);
  const value = secret && own(secret.values, environment);
  const expected =
    secret !== undefined && secretEnvironments(document, secret).includes(environment);

  if (!value) {
    return { secret: secretName, environment, state: expected ? "missing" : "absent" };
  }
  if (!expected) {
    return { secret: secretName, environment, state: "unexpected", signer: value.by };
  }

  const problem = signatureProblem(document, secretName, environment, value);
  if (problem) {
    return { secret: secretName, environment, state: "invalid", signer: value.by, detail: problem };
  }
  return {
    secret: secretName,
    environment,
    state: value.to === environmentDigest(document, environment) ? "ok" : "stale",
    signer: value.by,
  };
}

const CELL_FINDINGS: Partial<Record<CellState, (cell: Cell) => string>> = {
  missing: (cell) => `${cell.secret} has no value in "${cell.environment}"`,
  stale: (cell) =>
    `${cell.secret} in "${cell.environment}" is encrypted to an outdated recipient set; run \`msecrets sync\``,
  invalid: (cell) =>
    `${cell.secret} in "${cell.environment}" has an invalid signature: ${cell.detail ?? ""}`,
  unexpected: (cell) =>
    `${cell.secret} has a value in "${cell.environment}", which it does not apply to; remove it with \`msecrets unset ${cell.secret} --env ${cell.environment}\``,
};

export function inspect(document: SecretsDocument): Report {
  const environments = Object.keys(document.environments);
  const cells = Object.keys(document.secrets).flatMap((secret) =>
    environments.map((environment) => inspectCell(document, secret, environment)),
  );

  const findings: Finding[] = cells.flatMap((cell) => {
    const describe = CELL_FINDINGS[cell.state];
    return describe
      ? [
          {
            level: "error" as const,
            message: describe(cell),
            secret: cell.secret,
            environment: cell.environment,
          },
        ]
      : [];
  });

  for (const environment of environments) {
    const keys = (own(document.environments, environment)?.recipients ?? []).map((name) =>
      recipientKey(document, name),
    );
    if (!keys.length) {
      findings.push({
        level: "warning",
        environment,
        message: `Environment "${environment}" has no recipients, so it cannot hold values`,
      });
    } else if (!keys.some((key) => key.signingKey)) {
      findings.push({
        level: "warning",
        environment,
        message: `Nobody can write to "${environment}": none of its recipients has a signing key (msecrets1… or ssh-ed25519)`,
      });
    }
    if (keys.some((key) => key.postQuantum) && keys.some((key) => !key.postQuantum)) {
      findings.push({
        level: "warning",
        environment,
        message: `"${environment}" mixes post-quantum and classical recipients, so its values are only as strong as classical X25519`,
      });
    }
  }

  const used = new Set(Object.values(document.environments).flatMap((entry) => entry.recipients));
  for (const recipient of Object.keys(document.recipients).filter((name) => !used.has(name))) {
    findings.push({
      level: "warning",
      recipient,
      message: `Recipient "${recipient}" has no access to any environment`,
    });
  }

  return { cells, findings, ok: !findings.some((finding) => finding.level === "error") };
}
