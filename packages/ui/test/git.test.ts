import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  type SecretsDocument,
  addRecipient,
  grantAccess,
  inspect,
  parseDocumentText,
  revealValue,
  serializeDocument,
  setValue,
} from "../../core/src/index.ts";
import { sampleDocument } from "../../core/test/helpers.ts";
import { mergeDocuments, renderForDiff } from "../src/git.ts";

const text = (document: SecretsDocument) => serializeDocument(document);
const fork = (document: SecretsDocument) => parseDocumentText(serializeDocument(document));

describe("textconv", () => {
  test("renders recipients, access, and per-value signers without ciphertext", () => {
    const { document } = sampleDocument();
    const rendered = renderForDiff(text(document));
    assert.match(rendered, /^# msecrets file [0-9a-f]{32}$/m);
    assert.match(rendered, /^ {2}ci: x25519 \(read-only\) [0-9a-f]{12}$/m);
    assert.match(rendered, /^ {2}production: alice, ci$/m);
    assert.match(rendered, /^ {4}production: signed by alice [0-9a-f]{12}$/m);
    assert.match(rendered, /^ {4}only: development$/m);
    assert.ok(!rendered.includes("YWdl"), "no ciphertext");
  });

  test("a changed value changes exactly one line; a forged one is flagged", () => {
    const { document, people } = sampleDocument();
    const before = renderForDiff(text(document));
    const changed = fork(document);
    setValue(changed, [people.alice], {
      secret: "DATABASE_URL",
      environment: "production",
      value: "postgres://new",
    });
    const after = renderForDiff(text(changed));
    const differences = after
      .split("\n")
      .filter((line, index) => line !== before.split("\n")[index]);
    assert.equal(differences.length, 1);
    assert.match(differences[0] ?? "", /production: signed by alice/);

    const forged = fork(document);
    const value = forged.secrets["DATABASE_URL"]?.values["production"];
    assert.ok(value);
    value.by = "ci";
    assert.match(renderForDiff(text(forged)), /production: INVALID SIGNATURE by ci/);
  });

  test("invalid files are shown as-is with the reason", () => {
    assert.match(renderForDiff("{}"), /^# msecrets: this file is not a valid v4 secrets file/);
  });
});

describe("merge driver", () => {
  test("independent changes on both branches merge cleanly", () => {
    const { document: base, people } = sampleDocument();
    const ours = fork(base);
    const theirs = fork(base);
    setValue(ours, [people.alice], { secret: "OURS", environment: "development", value: "a" });
    setValue(theirs, [people.bob], { secret: "THEIRS", environment: "development", value: "b" });
    setValue(theirs, [people.alice], {
      secret: "DATABASE_URL",
      environment: "production",
      value: "changed",
    });

    const result = mergeDocuments(text(base), text(ours), text(theirs));
    assert.deepEqual(result.conflicts, []);
    const merged = parseDocumentText(result.text);
    assert.equal(revealValue(merged, [people.alice], "OURS", "development"), "a");
    assert.equal(revealValue(merged, [people.alice], "THEIRS", "development"), "b");
    assert.equal(revealValue(merged, [people.alice], "DATABASE_URL", "production"), "changed");
    assert.ok(
      inspect(merged).cells.every((cell) => cell.state !== "invalid" && cell.state !== "stale"),
    );
  });

  test("access lists merge as sets; values sealed for the old set become stale, not lost", () => {
    const { document: base, people } = sampleDocument();
    const ours = fork(base);
    const theirs = fork(base);
    addRecipient(ours, "carol", people.carol.publicKey.token);
    grantAccess(ours, [people.alice], "carol", ["development"]);
    setValue(theirs, [people.bob], { secret: "NEW", environment: "development", value: "x" });

    const result = mergeDocuments(text(base), text(ours), text(theirs));
    assert.deepEqual(result.conflicts, []);
    const merged = parseDocumentText(result.text);
    assert.deepEqual(merged.environments["development"]?.recipients, ["alice", "bob", "carol"]);
    assert.ok(
      inspect(merged).cells.some((cell) => cell.secret === "NEW" && cell.state === "stale"),
    );
  });

  test("the same value changed on both sides conflicts and keeps ours", () => {
    const { document: base, people } = sampleDocument();
    const ours = fork(base);
    const theirs = fork(base);
    setValue(ours, [people.alice], {
      secret: "DATABASE_URL",
      environment: "development",
      value: "ours",
    });
    setValue(theirs, [people.bob], {
      secret: "DATABASE_URL",
      environment: "development",
      value: "theirs",
    });

    const result = mergeDocuments(text(base), text(ours), text(theirs));
    assert.deepEqual(result.conflicts, ["secrets.DATABASE_URL.values.development"]);
    assert.equal(
      revealValue(parseDocumentText(result.text), [people.alice], "DATABASE_URL", "development"),
      "ours",
    );
  });

  test("a merge that would produce an invalid file is reported", () => {
    const { document: base, people } = sampleDocument();
    const ours = fork(base);
    const theirs = fork(base);
    // Ours removes bob entirely; theirs adds a value signed by bob.
    delete ours.recipients["bob"];
    ours.environments["development"] = { recipients: ["alice"] };
    delete ours.secrets["DEBUG"];
    setValue(theirs, [people.bob], { secret: "BY_BOB", environment: "development", value: "x" });

    const result = mergeDocuments(text(base), text(ours), text(theirs));
    assert.ok(
      result.conflicts.some((conflict) => /Unknown recipient "bob"/.test(conflict)),
      result.conflicts.join("\n"),
    );
    assert.equal(result.text, text(ours));
  });

  test("hostile keys such as __proto__ cannot pollute the merge", () => {
    const { document: base } = sampleDocument();
    const theirs = JSON.parse(text(base)) as Record<string, unknown>;
    theirs["secrets"] = JSON.parse(
      `{"__proto__": {"polluted": true}, ${JSON.stringify(theirs["secrets"]).slice(1)}`,
    );
    const result = mergeDocuments(text(base), text(base), JSON.stringify(theirs));
    assert.ok(result.conflicts.some((conflict) => conflict.includes("__proto__")));
    assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
  });

  test("two unrelated files (different ids) conflict", () => {
    const left = sampleDocument().document;
    const right = sampleDocument().document;
    assert.ok(mergeDocuments("", text(left), text(right)).conflicts.includes("id"));
  });
});
