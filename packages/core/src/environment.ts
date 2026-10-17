import { type SecretsDocument, own } from "./document.ts";
import { MsecretsError } from "./errors.ts";

export const ENVIRONMENT_VARIABLE = "MSECRETS_ENV";
export const DEFAULT_ENVIRONMENT = "development";

export type EnvironmentChoice = {
  name: string;
  reason: "explicit" | "variable" | "default" | "only";
};

/**
 * Chooses the environment: explicit name, then MSECRETS_ENV, then
 * "development" when it exists, then the only environment of the file.
 */
export function chooseEnvironment(
  document: SecretsDocument,
  explicit?: string,
  env: NodeJS.ProcessEnv = process.env,
): EnvironmentChoice {
  const environments = Object.keys(document.environments);
  const requested = explicit ?? env[ENVIRONMENT_VARIABLE];

  if (requested) {
    if (!own(document.environments, requested)) {
      throw new MsecretsError(
        "NOT_FOUND",
        `Environment "${requested}" does not exist${suggest(requested, environments)} (environments: ${environments.join(", ") || "none"})`,
      );
    }
    return { name: requested, reason: explicit ? "explicit" : "variable" };
  }
  if (own(document.environments, DEFAULT_ENVIRONMENT)) {
    return { name: DEFAULT_ENVIRONMENT, reason: "default" };
  }
  const [only] = environments;
  if (only !== undefined && environments.length === 1) {
    return { name: only, reason: "only" };
  }
  throw new MsecretsError(
    "USAGE",
    `Choose an environment with --env or ${ENVIRONMENT_VARIABLE} (environments: ${environments.join(", ") || "none"})`,
  );
}

function distance(left: string, right: string): number {
  const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i++) {
    let diagonal = previous[0] ?? 0;
    previous[0] = i;
    for (let j = 1; j <= right.length; j++) {
      const above = previous[j] ?? 0;
      previous[j] = Math.min(
        above + 1,
        (previous[j - 1] ?? 0) + 1,
        diagonal + (left[i - 1] === right[j - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return previous[right.length] ?? 0;
}

/** Returns ` (did you mean "X"?)` for the closest candidate, or an empty string. */
export function suggest(name: string, candidates: readonly string[]): string {
  const scored = candidates
    .map((candidate) => ({
      candidate,
      score: distance(name.toLowerCase(), candidate.toLowerCase()),
    }))
    .filter(({ score }) => score <= Math.max(2, Math.floor(name.length / 3)))
    .toSorted((left, right) => left.score - right.score);
  return scored[0] ? ` (did you mean "${scored[0].candidate}"?)` : "";
}
