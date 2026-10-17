import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestContext } from "node:test";

import {
  type Identity,
  type SecretsDocument,
  addEnvironment,
  addRecipient,
  createDocument,
  generateIdentity,
  readOnlyPublicKey,
  scopeSecret,
  setValue,
} from "../src/index.ts";

export function tempDir(t: TestContext): string {
  const directory = mkdtempSync(join(tmpdir(), "msecrets-test-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

export type Team = { alice: Identity; bob: Identity; carol: Identity; ci: Identity };

export function team(): Team {
  return {
    alice: generateIdentity(),
    bob: generateIdentity(),
    carol: generateIdentity(),
    ci: generateIdentity(),
  };
}

/** The plain, encrypt-only `age1…` form of an X25519 identity's public key. */
export function readOnlyToken(identity: Identity): string {
  return readOnlyPublicKey(identity.publicKey).token;
}

/**
 * - development: alice, bob
 * - production: alice, ci (read-only age1 key)
 * - DATABASE_URL in both environments, DEBUG only in development
 */
export function sampleDocument(people: Team = team()): { document: SecretsDocument; people: Team } {
  const document = createDocument();
  addRecipient(document, "alice", people.alice.publicKey.token);
  addRecipient(document, "bob", people.bob.publicKey.token);
  addRecipient(document, "ci", readOnlyToken(people.ci));
  addEnvironment(document, "development", ["alice", "bob"]);
  addEnvironment(document, "production", ["alice", "ci"]);
  setValue(document, [people.alice], {
    secret: "DATABASE_URL",
    environment: "development",
    value: "postgres://dev",
  });
  setValue(document, [people.alice], {
    secret: "DATABASE_URL",
    environment: "production",
    value: "postgres://prod",
  });
  setValue(document, [people.bob], { secret: "DEBUG", environment: "development", value: "true" });
  scopeSecret(document, "DEBUG", ["development"]);
  return { document, people };
}
