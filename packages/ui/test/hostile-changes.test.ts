/**
 * Hostile pull requests: an attacker controls the whole msecrets.json, including who
 * may read and sign. Each scenario pins down what signatures prevent and what only
 * review prevents, and that review can see it in `git diff` (msecrets git setup).
 */
import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  type SecretsDocument,
  generateIdentity,
  inspect,
  inspectCell,
  isMsecretsError,
  parseDocumentText,
  revealValue,
  serializeDocument,
  setValue,
  sync,
} from "../../core/src/index.ts";
import { sampleDocument } from "../../core/test/helpers.ts";
import { renderForDiff } from "../src/git.ts";

const fork = (document: SecretsDocument) => parseDocumentText(serializeDocument(document));
const diff = (before: SecretsDocument, after: SecretsDocument) => {
  const old = new Set(renderForDiff(serializeDocument(before)).split("\n"));
  return renderForDiff(serializeDocument(after))
    .split("\n")
    .filter((line) => !old.has(line));
};

describe("hostile pull requests", () => {
  test("A: adding yourself as a recipient reveals nothing, fails check, and shows in the diff", () => {
    const { document, people } = sampleDocument();
    const mallory = generateIdentity();
    const attack = fork(document);
    attack.recipients["mallory"] = { key: mallory.publicKey.token };
    attack.environments["production"]?.recipients.push("mallory");

    assert.throws(
      () => revealValue(attack, [mallory], "DATABASE_URL", "production"),
      (error: unknown) => isMsecretsError(error, "ACCESS_DENIED"),
    );
    assert.equal(inspectCell(attack, "DATABASE_URL", "production").state, "stale");
    assert.equal(inspect(attack).ok, false, "msecrets check fails until a member syncs");
    const changes = diff(document, attack);
    assert.deepEqual(changes.slice(0, 2), [
      `  mallory: x25519 ${diffFingerprint(attack, "mallory")}`,
      "  production: alice, ci, mallory",
    ]);
    assert.match(changes[2] ?? "", /^ {4}production: signed, needs sync by alice [0-9a-f]{12}$/);
    assert.equal(changes.length, 3);

    // The only step that grants access: a member re-encrypts for the new list. Review must stop it first.
    sync(attack, [people.alice]);
    assert.equal(revealValue(attack, [mallory], "DATABASE_URL", "production"), "postgres://prod");
  });

  test("B: replacing a member's key breaks every value they signed, and shows in the diff", () => {
    const { document } = sampleDocument();
    const mallory = generateIdentity();
    const attack = fork(document);
    const alice = attack.recipients["alice"];
    assert.ok(alice);
    alice.key = mallory.publicKey.token;

    assert.equal(inspectCell(attack, "DATABASE_URL", "development").state, "invalid");
    assert.equal(inspect(attack).ok, false);

    // Values written with the replaced key verify: the file cannot tell who "alice" really is.
    setValue(attack, [mallory], {
      secret: "DATABASE_URL",
      environment: "production",
      value: "postgres://attacker",
    });
    assert.equal(inspectCell(attack, "DATABASE_URL", "production").state, "ok");
    assert.ok(
      diff(document, attack).includes(`  alice: x25519 ${diffFingerprint(attack, "alice")}`),
      "the key change is a visible diff line",
    );
  });

  test("C: restoring an older signed value verifies, and shows in the diff", () => {
    const { document, people } = sampleDocument();
    const old = fork(document);
    setValue(document, [people.alice], {
      secret: "DATABASE_URL",
      environment: "production",
      value: "postgres://rotated",
    });
    const attack = fork(document);
    const restored = old.secrets["DATABASE_URL"]?.values["production"];
    assert.ok(restored && attack.secrets["DATABASE_URL"]);
    attack.secrets["DATABASE_URL"].values["production"] = restored;

    assert.equal(inspectCell(attack, "DATABASE_URL", "production").state, "ok");
    assert.equal(
      revealValue(attack, [people.alice], "DATABASE_URL", "production"),
      "postgres://prod",
    );
    assert.equal(diff(document, attack).length, 1);
    assert.match(diff(document, attack)[0] ?? "", /^ {4}production: signed by alice [0-9a-f]{12}$/);
  });

  test("values cannot be forged, moved, or written by read-only keys, whatever else changes", () => {
    const { document, people } = sampleDocument();
    const attack = fork(document);
    const secret = attack.secrets["DATABASE_URL"];
    const production = secret?.values["production"];
    assert.ok(secret && production);

    // Move the production value to development, then claim another signer.
    secret.values["development"] = { ...production };
    production.by = "bob";
    assert.equal(inspectCell(attack, "DATABASE_URL", "development").state, "invalid");
    assert.equal(inspectCell(attack, "DATABASE_URL", "production").state, "invalid");
    assert.throws(() => revealValue(attack, [people.alice], "DATABASE_URL", "development"));

    assert.throws(
      () => setValue(attack, [people.ci], { secret: "X", environment: "production", value: "x" }),
      (error: unknown) => isMsecretsError(error, "ACCESS_DENIED"),
    );
  });
});

/** The fingerprint the diff shows for a recipient, read from the rendering itself. */
function diffFingerprint(document: SecretsDocument, name: string): string {
  const line = renderForDiff(serializeDocument(document))
    .split("\n")
    .find((entry) => entry.startsWith(`  ${name}: `));
  return line?.split(" ").pop() ?? "";
}
