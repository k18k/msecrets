import assert from "node:assert/strict";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import {
  DEFAULT_FILENAME,
  chooseEnvironment,
  createDocumentFile,
  findDocumentFile,
  isMsecretsError,
  readDocumentFile,
  resolveDocumentFile,
  serializeDocument,
  suggest,
  updateDocumentFile,
} from "../src/index.ts";
import { sampleDocument, tempDir } from "./helpers.ts";

describe("store", () => {
  test("finds the secrets file in the closest parent directory", (t) => {
    const root = tempDir(t);
    const nested = join(root, "a", "b", "c");
    mkdirSync(nested, { recursive: true });
    assert.equal(findDocumentFile(nested), null);
    writeFileSync(join(root, "a", DEFAULT_FILENAME), "{}");
    assert.equal(findDocumentFile(nested), join(root, "a", DEFAULT_FILENAME));
  });

  test("resolves an explicit path, then MSECRETS_FILE, then the search", (t) => {
    const root = tempDir(t);
    writeFileSync(join(root, DEFAULT_FILENAME), "{}");
    assert.equal(resolveDocumentFile({ cwd: root, env: {} }), join(root, DEFAULT_FILENAME));
    assert.equal(
      resolveDocumentFile({ cwd: root, env: { MSECRETS_FILE: "other.json" } }),
      join(root, "other.json"),
    );
    assert.equal(
      resolveDocumentFile({ cwd: root, file: "x.json", env: { MSECRETS_FILE: "other.json" } }),
      join(root, "x.json"),
    );
    const empty = tempDir(t);
    assert.throws(
      () => resolveDocumentFile({ cwd: empty, env: {} }),
      (error: unknown) =>
        isMsecretsError(error, "NOT_FOUND") && /msecrets init/.test(error.message),
    );
  });

  test("creates files exclusively and reads them back", (t) => {
    const path = join(tempDir(t), DEFAULT_FILENAME);
    const { document } = sampleDocument();
    createDocumentFile(path, document);
    assert.equal(readFileSync(path, "utf8"), serializeDocument(document));
    assert.throws(
      () => createDocumentFile(path, document),
      (error: unknown) => isMsecretsError(error, "CONFLICT"),
    );
    assert.deepEqual(readDocumentFile(path), document);
  });

  test("updates atomically, skips no-op writes, and leaves no temporary files", (t) => {
    const directory = tempDir(t);
    const path = join(directory, DEFAULT_FILENAME);
    createDocumentFile(path, sampleDocument().document);
    const before = statSync(path).mtimeMs;

    assert.equal(
      updateDocumentFile(path, () => 42),
      42,
    );
    assert.equal(statSync(path).mtimeMs, before);

    updateDocumentFile(path, (document) => {
      document.secrets["NEW"] = { values: {} };
    });
    assert.ok(readDocumentFile(path).secrets["NEW"]);
    assert.deepEqual(readdirSync(directory), [DEFAULT_FILENAME]);
  });

  test("a failing mutation or an invalid result never reaches the disk", (t) => {
    const path = join(tempDir(t), DEFAULT_FILENAME);
    createDocumentFile(path, sampleDocument().document);
    const original = readFileSync(path, "utf8");

    assert.throws(() =>
      updateDocumentFile(path, (document) => {
        delete document.secrets["DATABASE_URL"];
        throw new Error("boom");
      }),
    );
    assert.throws(
      () =>
        updateDocumentFile(path, (document) => {
          document.environments["development"]?.recipients.push("ghost");
        }),
      (error: unknown) => isMsecretsError(error, "INVALID_FILE"),
    );
    assert.equal(readFileSync(path, "utf8"), original);
  });

  test("detects concurrent modification", (t) => {
    const path = join(tempDir(t), DEFAULT_FILENAME);
    createDocumentFile(path, sampleDocument().document);
    assert.throws(
      () =>
        updateDocumentFile(path, (document) => {
          writeFileSync(path, `${readFileSync(path, "utf8")} `);
          delete document.secrets["DEBUG"];
        }),
      (error: unknown) => isMsecretsError(error, "CONFLICT"),
    );
  });

  test("a missing file is reported with guidance", (t) => {
    assert.throws(
      () => readDocumentFile(join(tempDir(t), "missing.json")),
      (error: unknown) => isMsecretsError(error, "NOT_FOUND"),
    );
  });
});

describe("environment selection", () => {
  const { document } = sampleDocument();

  test("explicit, then MSECRETS_ENV, then development, then the only environment", () => {
    assert.deepEqual(chooseEnvironment(document, "production", {}), {
      name: "production",
      reason: "explicit",
    });
    assert.deepEqual(chooseEnvironment(document, undefined, { MSECRETS_ENV: "production" }), {
      name: "production",
      reason: "variable",
    });
    assert.deepEqual(chooseEnvironment(document, undefined, {}), {
      name: "development",
      reason: "default",
    });

    const single = structuredClone(document);
    delete single.environments["development"];
    assert.deepEqual(chooseEnvironment(single, undefined, {}), {
      name: "production",
      reason: "only",
    });

    const many = structuredClone(single);
    many.environments["staging"] = { recipients: [] };
    assert.throws(
      () => chooseEnvironment(many, undefined, {}),
      /Choose an environment with --env or MSECRETS_ENV/,
    );
  });

  test("unknown environments get a suggestion", () => {
    assert.throws(() => chooseEnvironment(document, "prodution", {}), /did you mean "production"/);
  });

  test("suggestions only for close matches", () => {
    assert.equal(
      suggest("DATABSE_URL", ["DATABASE_URL", "DEBUG"]),
      ' (did you mean "DATABASE_URL"?)',
    );
    assert.equal(suggest("ZZZ", ["DATABASE_URL"]), "");
  });
});
