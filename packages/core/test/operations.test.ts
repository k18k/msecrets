import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  type SecretsDocument,
  addEnvironment,
  addRecipient,
  createDocument,
  createSecret,
  deleteSecret,
  describeSecret,
  generateIdentity,
  grantAccess,
  inspect,
  inspectCell,
  isMsecretsError,
  parseDocumentText,
  removeEnvironment,
  removeRecipient,
  renameEnvironment,
  renameRecipient,
  renameSecret,
  replaceRecipientKey,
  revealValue,
  revokeAccess,
  scopeSecret,
  serializeDocument,
  setValue,
  supportsMlKem,
  sync,
  unsetValue,
} from "../src/index.ts";
import { readOnlyToken, sampleDocument } from "./helpers.ts";

function copy(document: SecretsDocument): SecretsDocument {
  return parseDocumentText(serializeDocument(document));
}

const code = (expected: string) => (error: unknown) =>
  isMsecretsError(error) && error.code === expected;

describe("values", () => {
  test("members read the environments they belong to, and nothing else", () => {
    const { document, people } = sampleDocument();
    assert.equal(
      revealValue(document, [people.alice], "DATABASE_URL", "production"),
      "postgres://prod",
    );
    assert.equal(
      revealValue(document, [people.bob], "DATABASE_URL", "development"),
      "postgres://dev",
    );
    assert.equal(
      revealValue(document, [people.ci], "DATABASE_URL", "production"),
      "postgres://prod",
    );
    assert.throws(
      () => revealValue(document, [people.bob], "DATABASE_URL", "production"),
      code("ACCESS_DENIED"),
    );
    assert.throws(
      () => revealValue(document, [people.carol], "DATABASE_URL", "development"),
      /None of your loaded keys belongs/,
    );
  });

  test("values keep exact bytes: unicode, whitespace, newlines, empty", () => {
    const { document, people } = sampleDocument();
    for (const value of ["", " padded ", "line1\nline2\r\n", "zażółć 🔐", "x".repeat(200_000)]) {
      setValue(document, [people.alice], { secret: "EXACT", environment: "development", value });
      assert.equal(revealValue(copy(document), [people.bob], "EXACT", "development"), value);
    }
    assert.throws(
      () =>
        setValue(document, [people.alice], {
          secret: "NUL",
          environment: "development",
          value: "a\0b",
        }),
      /NUL/,
    );
  });

  test("read-only recipients cannot write, and only members of an environment can", () => {
    const { document, people } = sampleDocument();
    assert.throws(
      () => setValue(document, [people.ci], { secret: "X", environment: "production", value: "1" }),
      (error: unknown) =>
        isMsecretsError(error, "ACCESS_DENIED") && /signing key/.test(error.message),
    );
    assert.throws(
      () =>
        setValue(document, [people.bob], { secret: "X", environment: "production", value: "1" }),
      code("ACCESS_DENIED"),
    );
    assert.throws(
      () =>
        setValue(document, [people.alice], {
          secret: "X",
          environment: "production",
          value: "1",
          as: "bob",
        }),
      /"bob" is not/,
    );
  });

  test("a value moved to another secret, environment, or file fails verification", () => {
    const { document, people } = sampleDocument();
    const production = document.secrets["DATABASE_URL"]?.values["production"];
    assert.ok(production);

    const moved = copy(document);
    setValue(moved, [people.alice], { secret: "OTHER", environment: "production", value: "x" });
    (moved.secrets["OTHER"] as { values: Record<string, unknown> }).values["production"] =
      production;
    assert.equal(inspectCell(moved, "OTHER", "production").state, "invalid");
    assert.throws(
      () => revealValue(moved, [people.alice], "OTHER", "production"),
      code("SIGNATURE"),
    );

    const crossEnvironment = copy(document);
    addEnvironment(crossEnvironment, "staging", ["alice", "ci"]);
    (crossEnvironment.secrets["DATABASE_URL"] as { values: Record<string, unknown> }).values[
      "staging"
    ] = production;
    assert.equal(inspectCell(crossEnvironment, "DATABASE_URL", "staging").state, "invalid");

    const otherFile = copy(document);
    otherFile.id = "0".repeat(32);
    assert.equal(inspectCell(otherFile, "DATABASE_URL", "production").state, "invalid");
  });

  test("tampered ciphertext or a forged signer is rejected before decryption", () => {
    const { document, people } = sampleDocument();
    const tampered = copy(document);
    const value = tampered.secrets["DATABASE_URL"]?.values["development"];
    assert.ok(value);
    const data = Buffer.from(value.data, "base64");
    data[data.length - 1] = (data[data.length - 1] ?? 0) ^ 1;
    value.data = data.toString("base64");
    assert.throws(
      () => revealValue(tampered, [people.alice], "DATABASE_URL", "development"),
      code("SIGNATURE"),
    );

    const forged = copy(document);
    const forgedValue = forged.secrets["DATABASE_URL"]?.values["production"];
    assert.ok(forgedValue);
    forgedValue.by = "bob";
    assert.match(
      inspectCell(forged, "DATABASE_URL", "production").detail ?? "",
      /not a recipient of "production"/,
    );
  });

  test("an outsider who can encrypt to the public keys still cannot inject values", () => {
    const { document, people } = sampleDocument();
    const attacker = generateIdentity();
    const injected = copy(document);
    // The attacker signs as an existing member, but without that member's key.
    addRecipient(injected, "mallory", attacker.publicKey.token);
    injected.environments["production"]?.recipients.push("mallory");
    setValue(injected, [attacker], {
      secret: "DATABASE_URL",
      environment: "production",
      value: "postgres://evil",
    });
    const value = injected.secrets["DATABASE_URL"]?.values["production"];
    assert.ok(value);
    value.by = "alice";
    assert.equal(inspectCell(injected, "DATABASE_URL", "production").state, "invalid");
    assert.throws(
      () => revealValue(injected, [people.alice], "DATABASE_URL", "production"),
      code("SIGNATURE"),
    );
  });
});

describe("access", () => {
  test("grant re-encrypts what the granter can read; the rest stays stale until a member syncs", () => {
    const { document, people } = sampleDocument();
    addRecipient(document, "carol", people.carol.publicKey.token);

    // bob cannot read production, so he can only record the grant there.
    const byBob = grantAccess(document, [people.bob], "carol", ["development", "production"]);
    assert.deepEqual(byBob.updated.map((slot) => `${slot.secret}@${slot.environment}`).toSorted(), [
      "DATABASE_URL@development",
      "DEBUG@development",
    ]);
    assert.deepEqual(
      byBob.skipped.map((slot) => slot.environment),
      ["production"],
    );
    assert.equal(inspectCell(document, "DATABASE_URL", "production").state, "stale");
    assert.equal(inspect(document).ok, false);

    const byAlice = sync(document, [people.alice]);
    assert.equal(byAlice.updated.length, 1);
    assert.equal(inspect(document).ok, true);
    assert.equal(
      revealValue(document, [people.carol], "DATABASE_URL", "production"),
      "postgres://prod",
    );
  });

  test("revoke re-encrypts without the recipient and lists values to rotate", () => {
    const { document, people } = sampleDocument();
    const result = revokeAccess(document, [people.alice], "bob", ["development"]);
    assert.deepEqual(result.updated.map((slot) => slot.secret).toSorted(), [
      "DATABASE_URL",
      "DEBUG",
    ]);
    assert.deepEqual(result.rotate.map((slot) => slot.secret).toSorted(), [
      "DATABASE_URL",
      "DEBUG",
    ]);
    assert.throws(
      () => revealValue(document, [people.bob], "DATABASE_URL", "development"),
      code("ACCESS_DENIED"),
    );
    assert.equal(
      document.secrets["DEBUG"]?.values["development"]?.by,
      "alice",
      "values are re-signed by the revoker",
    );
    assert.ok(inspect(document).ok);
  });

  test("revoke refuses to pretend: it fails when values cannot be re-encrypted", () => {
    const { document, people } = sampleDocument();
    const before = serializeDocument(document);
    assert.throws(
      () => revokeAccess(document, [people.bob], "ci", ["production"]),
      /requires re-encrypting values you cannot decrypt/,
    );
    void before;

    const incomplete = parseDocumentText(before);
    const result = revokeAccess(incomplete, [people.bob], "ci", ["production"], {
      allowIncomplete: true,
    });
    assert.equal(result.skipped.length, 1);
    assert.equal(inspectCell(incomplete, "DATABASE_URL", "production").state, "stale");
  });

  test("the last recipient of an environment with values cannot be revoked", () => {
    const { document, people } = sampleDocument();
    revokeAccess(document, [people.alice], "ci", ["production"]);
    assert.throws(
      () => revokeAccess(document, [people.alice], "alice", ["production"]),
      /last recipient/,
    );
  });

  test("removing a recipient revokes everything and keeps the file valid", () => {
    const { document, people } = sampleDocument();
    removeRecipient(document, [people.alice], "bob");
    assert.equal(document.recipients["bob"], undefined);
    assert.ok(!document.environments["development"]?.recipients.includes("bob"));
    assert.ok(inspect(copy(document)).ok);
  });

  test("key rotation re-encrypts to the new key and keeps the history signed", () => {
    const { document, people } = sampleDocument();
    const replacement = generateIdentity();
    const before = copy(document);
    assert.throws(
      () => replaceRecipientKey(before, [people.alice], "alice", replacement.publicKey.token),
      /load the new identity too/,
    );
    const updated = replaceRecipientKey(
      document,
      [people.alice, replacement],
      "alice",
      replacement.publicKey.token,
    );
    assert.equal(updated.length, 3);
    assert.ok(inspect(document).ok);
    assert.equal(
      revealValue(document, [replacement], "DATABASE_URL", "production"),
      "postgres://prod",
    );
    assert.throws(
      () => revealValue(document, [people.alice], "DATABASE_URL", "production"),
      code("ACCESS_DENIED"),
    );
    assert.throws(
      () => replaceRecipientKey(document, [replacement], "bob", replacement.publicKey.token),
      /already belongs to recipient "alice"/,
    );

    // A machine key can be rotated by any member who can read its environments.
    const machine = generateIdentity();
    replaceRecipientKey(document, [replacement], "ci", readOnlyToken(machine));
    assert.equal(revealValue(document, [machine], "DATABASE_URL", "production"), "postgres://prod");
  });

  test("renaming a recipient keeps signatures valid", () => {
    const { document, people } = sampleDocument();
    renameRecipient(document, "alice", "alice.smith");
    assert.ok(inspect(copy(document)).ok);
    assert.equal(document.secrets["DATABASE_URL"]?.values["production"]?.by, "alice.smith");
    assert.equal(
      revealValue(document, [people.alice], "DATABASE_URL", "production"),
      "postgres://prod",
    );
    assert.throws(() => renameRecipient(document, "bob", "ci"), code("CONFLICT"));
  });

  test("duplicate keys and invalid names are rejected", () => {
    const { document, people } = sampleDocument();
    assert.throws(
      () => addRecipient(document, "alice2", readOnlyToken(people.alice)),
      /already belongs to recipient "alice"/,
    );
    assert.throws(
      () => addRecipient(document, "Alice", people.carol.publicKey.token),
      code("USAGE"),
    );
    assert.throws(
      () => addRecipient(document, "alice", people.carol.publicKey.token),
      code("CONFLICT"),
    );
  });

  test(
    "post-quantum environments work end to end and mixing is reported",
    { skip: supportsMlKem() ? false : "ML-KEM unsupported" },
    () => {
      const pq = generateIdentity({ postQuantum: true });
      const document = createDocument();
      addRecipient(document, "quantum", pq.publicKey.token);
      addEnvironment(document, "production", ["quantum"]);
      setValue(document, [pq], { secret: "KEY", environment: "production", value: "safe" });
      assert.equal(revealValue(copy(document), [pq], "KEY", "production"), "safe");
      assert.ok(inspect(document).ok);

      const classic = generateIdentity();
      addRecipient(document, "classic", classic.publicKey.token);
      grantAccess(document, [pq], "classic", ["production"]);
      assert.ok(
        inspect(document).findings.some((finding) =>
          /mixes post-quantum and classical/.test(finding.message),
        ),
      );
    },
  );
});

describe("secrets and environments", () => {
  test("renaming a secret verifies, then re-signs; tampered values block the rename", () => {
    const { document, people } = sampleDocument();
    renameSecret(document, [people.alice], "DATABASE_URL", "DB_URL");
    assert.equal(revealValue(document, [people.ci], "DB_URL", "production"), "postgres://prod");
    assert.ok(inspect(document).ok);

    const tampered = copy(document);
    const value = tampered.secrets["DB_URL"]?.values["production"];
    assert.ok(value);
    value.to = "f".repeat(32);
    assert.throws(
      () => renameSecret(tampered, [people.alice], "DB_URL", "DATABASE_URL"),
      /Refusing to re-sign/,
    );
  });

  test("renaming an environment re-signs its values and keeps its position", () => {
    const { document, people } = sampleDocument();
    renameEnvironment(document, [people.alice], "development", "dev");
    assert.deepEqual(Object.keys(document.environments), ["dev", "production"]);
    assert.deepEqual(document.secrets["DEBUG"]?.environments, ["dev"]);
    assert.ok(inspect(copy(document)).ok);
    assert.equal(revealValue(document, [people.bob], "DEBUG", "dev"), "true");
  });

  test("renaming an environment needs a member who can sign there", () => {
    const { document, people } = sampleDocument();
    assert.throws(
      () => renameEnvironment(document, [people.ci], "production", "prod"),
      code("ACCESS_DENIED"),
    );
  });

  test("scopes: completeness is measured per applicable environment", () => {
    const { document, people } = sampleDocument();
    assert.equal(inspectCell(document, "DEBUG", "production").state, "absent");
    createSecret(document, "SENTRY_DSN", {
      environments: ["production"],
      description: "Error reporting",
    });
    assert.equal(inspectCell(document, "SENTRY_DSN", "production").state, "missing");
    assert.equal(inspectCell(document, "SENTRY_DSN", "development").state, "absent");
    assert.throws(
      () =>
        setValue(document, [people.alice], {
          secret: "SENTRY_DSN",
          environment: "development",
          value: "x",
        }),
      /does not apply/,
    );

    const removed = scopeSecret(document, "DATABASE_URL", ["production"]);
    assert.deepEqual(removed, ["development"]);
    scopeSecret(document, "DEBUG", undefined);
    assert.equal(inspectCell(document, "DEBUG", "production").state, "missing");
    assert.throws(() => scopeSecret(document, "DEBUG", []), /at least one environment/);
  });

  test("adding an environment makes every unscoped secret missing there", () => {
    const { document } = sampleDocument();
    addEnvironment(document, "staging", ["alice"]);
    assert.equal(inspectCell(document, "DATABASE_URL", "staging").state, "missing");
    assert.equal(inspect(document).ok, false);
  });

  test("removing an environment deletes its values and secrets scoped only to it", () => {
    const { document } = sampleDocument();
    const result = removeEnvironment(document, "development");
    assert.deepEqual(result.removedSecrets, ["DEBUG"]);
    assert.equal(result.removedValues.length, 2);
    assert.ok(inspect(copy(document)).ok);
  });

  test("unset, delete, describe", () => {
    const { document } = sampleDocument();
    assert.equal(unsetValue(document, "DATABASE_URL", "development"), true);
    assert.equal(unsetValue(document, "DATABASE_URL", "development"), false);
    describeSecret(document, "DATABASE_URL", "  Primary database  ");
    assert.equal(document.secrets["DATABASE_URL"]?.description, "Primary database");
    describeSecret(document, "DATABASE_URL", "");
    assert.equal(document.secrets["DATABASE_URL"]?.description, undefined);
    deleteSecret(document, "DATABASE_URL");
    assert.throws(() => deleteSecret(document, "DATABASE_URL"), code("NOT_FOUND"));
  });

  test("sync never re-encrypts invalid values", () => {
    const { document, people } = sampleDocument();
    addRecipient(document, "carol", people.carol.publicKey.token);
    document.environments["development"]?.recipients.push("carol");
    const value = document.secrets["DATABASE_URL"]?.values["development"];
    assert.ok(value);
    value.sig = Buffer.alloc(64).toString("base64");
    const result = sync(document, [people.alice]);
    assert.deepEqual(
      result.updated.map((slot) => slot.secret),
      ["DEBUG"],
    );
    assert.equal(inspectCell(document, "DATABASE_URL", "development").state, "invalid");
  });

  test("environment warnings: no recipients, nobody can write, unused recipients", () => {
    const document = createDocument();
    const machine = generateIdentity();
    addRecipient(document, "machine", readOnlyToken(machine));
    addRecipient(document, "idle", generateIdentity().publicKey.token);
    addEnvironment(document, "empty", []);
    addEnvironment(document, "readonly", ["machine"]);
    const messages = inspect(document).findings.map((finding) => finding.message);
    assert.ok(messages.some((message) => /"empty" has no recipients/.test(message)));
    assert.ok(messages.some((message) => /Nobody can write to "readonly"/.test(message)));
    assert.ok(messages.some((message) => /"idle" has no access/.test(message)));
    assert.ok(inspect(document).ok, "warnings do not fail the check");
  });
});
