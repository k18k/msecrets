/**
 * Drives the TypeScript core for the Go differential tests (differential_test.go).
 * Usage: node differential.ts <command> <file> < plan.json
 *   create: builds a new file from the plan
 *   modify: applies the plan's changes to an existing file
 *   check:  re-serializes the file and reveals every value
 * Prints a JSON report on stdout.
 */
import { readFileSync } from "node:fs";

import * as core from "../../../packages/core/src/index.ts";

type Plan = {
  identityFiles: string[];
  recipients: { name: string; key: string; description?: string }[];
  environments: { name: string; recipients: string[] }[];
  secrets: {
    name: string;
    description?: string;
    environments?: string[];
    values: Record<string, string>;
  }[];
};

const [command, file] = process.argv.slice(2);
const plan = JSON.parse(readFileSync(0, "utf8")) as Plan;
const identities = plan.identityFiles.flatMap((path) => core.parseIdentities(readFileSync(path)));

function apply(document: core.SecretsDocument): void {
  for (const { name, key, description } of plan.recipients) {
    core.addRecipient(document, name, key, description);
  }
  for (const { name, recipients } of plan.environments) {
    core.addEnvironment(document, name, recipients);
  }
  for (const secret of plan.secrets) {
    core.createSecret(document, secret.name, {
      ...(secret.description === undefined ? {} : { description: secret.description }),
      ...(secret.environments === undefined ? {} : { environments: secret.environments }),
    });
    for (const [environment, value] of Object.entries(secret.values)) {
      core.setValue(document, identities, { secret: secret.name, environment, value });
    }
  }
}

function revealAll(document: core.SecretsDocument): Record<string, string> {
  const values: Record<string, string> = {};
  for (const [secret, entry] of Object.entries(document.secrets)) {
    for (const environment of Object.keys(entry.values)) {
      try {
        values[`${secret}@${environment}`] = core.revealValue(document, identities, secret, environment);
      } catch (error) {
        values[`${secret}@${environment}`] = `ERROR ${core.isMsecretsError(error) ? error.code : String(error)}`;
      }
    }
  }
  return values;
}

if (command === "create") {
  const document = core.createDocument();
  apply(document);
  core.createDocumentFile(file, document);
} else if (command === "modify") {
  core.updateDocumentFile(file, apply);
}

const text = readFileSync(file, "utf8");
const document = core.parseDocumentText(text);
process.stdout.write(
  JSON.stringify({
    canonical: core.serializeDocument(document) === text,
    environments: Object.keys(document.environments),
    ok: core.inspect(document).ok,
    values: revealAll(document),
  }),
);
