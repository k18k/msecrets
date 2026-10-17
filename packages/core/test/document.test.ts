import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import {
  FORMAT_VERSION,
  describeRecipient,
  describeSecret,
  SCHEMA_URL,
  isMsecretsError,
  nameProblem,
  own,
  parseDocument,
  parseDocumentText,
  serializeDocument,
  validateDocument,
} from "../src/index.ts";
import { readOnlyToken, sampleDocument } from "./helpers.ts";

function issuesOf(input: unknown): string[] {
  return validateDocument(input).issues.map((issue) => `${issue.path}: ${issue.message}`);
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe("validation", () => {
  test("a document produced by operations is valid and round-trips exactly", () => {
    const { document } = sampleDocument();
    const text = serializeDocument(document);
    assert.deepEqual(issuesOf(JSON.parse(text)), []);
    assert.equal(serializeDocument(parseDocumentText(text)), text);
  });

  test("serialization is canonical: sorted names, fixed field order, $schema, trailing newline", () => {
    const { document } = sampleDocument();
    const shuffled = JSON.parse(serializeDocument(document)) as Record<string, unknown>;
    const reordered = {
      secrets: shuffled["secrets"],
      environments: shuffled["environments"],
      id: shuffled["id"],
      recipients: shuffled["recipients"],
      version: 4,
    };
    const text = serializeDocument(parseDocument(reordered));
    assert.equal(text, serializeDocument(document));
    assert.ok(text.endsWith("}\n"));
    assert.deepEqual(Object.keys(JSON.parse(text) as object), [
      "$schema",
      "version",
      "id",
      "recipients",
      "environments",
      "secrets",
    ]);
    assert.equal((JSON.parse(text) as { $schema: string }).$schema, SCHEMA_URL);
  });

  test("reports v3 files with migration guidance", () => {
    const issues = issuesOf({ version: "2.0.0", environments: [], keys: [], secrets: {} });
    assert.equal(issues.length, 1);
    assert.match(issues[0] ?? "", /msecrets v2 file; msecrets v4 uses a new format/);
    assert.match(issuesOf({ version: 5 })[0] ?? "", /Unsupported format version 5/);
  });

  test("reports every structural problem with its path", () => {
    const { document, people } = sampleDocument();
    const input = clone(document) as unknown as Record<string, any>;
    input["id"] = "nope";
    input["extra"] = true;
    input["recipients"]["Bad Name"] = { key: people.carol.publicKey.token };
    input["recipients"]["dup"] = { key: people.alice.publicKey.token };
    input["recipients"]["upper"] = { key: readOnlyToken(people.carol).toUpperCase() };
    input["environments"]["development"]["recipients"].push("ghost", "alice");
    input["secrets"]["DATABASE_URL"]["values"]["staging"] =
      input["secrets"]["DATABASE_URL"]["values"]["development"];
    input["secrets"]["DATABASE_URL"]["values"]["production"]["sig"] = "short";
    input["secrets"]["DATABASE_URL"]["values"]["production"]["by"] = "nobody";
    input["secrets"]["DATABASE_URL"]["values"]["development"]["data"] =
      Buffer.from("not age").toString("base64");
    input["secrets"]["DATABASE_URL"]["values"]["development"]["to"] = "ABC";
    input["secrets"]["DEBUG"]["environments"] = [];
    input["secrets"]["DEBUG"]["description"] = " padded ";
    input["secrets"]["1BAD"] = { values: {} };

    const issues = issuesOf(input);
    for (const expected of [
      /^\$\.id: Expected a 32 character lowercase hex file id/,
      /^\$\.extra: Unknown property/,
      /^\$\.recipients\.Bad Name: Invalid recipient name/,
      /^\$\.recipients\.dup\.key: Same key as recipient "alice"/,
      /^\$\.recipients\.upper\.key: Public key is not in canonical form/,
      /^\$\.environments\.development\.recipients\[2\]: Unknown recipient "ghost"/,
      /^\$\.environments\.development\.recipients\[3\]: Duplicate recipient "alice"/,
      /^\$\.secrets\.DATABASE_URL\.values\.staging: Unknown environment "staging"/,
      /^\$\.secrets\.DATABASE_URL\.values\.production\.sig: Expected a base64 Ed25519 signature/,
      /^\$\.secrets\.DATABASE_URL\.values\.production\.by: Unknown recipient "nobody"/,
      /^\$\.secrets\.DATABASE_URL\.values\.development\.data: Expected a base64-encoded age file/,
      /^\$\.secrets\.DATABASE_URL\.values\.development\.to: Expected a 32 character/,
      /^\$\.secrets\.DEBUG\.environments: Must list at least one environment/,
      /^\$\.secrets\.DEBUG\.description: Descriptions must be non-empty, trimmed/,
      /^\$\.secrets\.1BAD: Invalid secret name/,
    ]) {
      assert.ok(
        issues.some((issue) => expected.test(issue)),
        `missing issue ${expected}\n${issues.join("\n")}`,
      );
    }
  });

  test("rejects non-objects and wrong types", () => {
    assert.match(issuesOf(null)[0] ?? "", /\$: Expected an object/);
    assert.match(issuesOf([])[0] ?? "", /\$: Expected an object/);
    assert.ok(
      issuesOf({ version: FORMAT_VERSION, id: 1, recipients: [], environments: "x", secrets: {} })
        .length >= 3,
    );
  });

  test("parse errors carry the code INVALID_FILE and the source", () => {
    assert.throws(
      () => parseDocumentText("{", "x.json"),
      (error: unknown) =>
        isMsecretsError(error, "INVALID_FILE") && /Invalid x\.json/.test(error.message),
    );
    assert.throws(
      () => parseDocument({ version: 4 }),
      (error: unknown) => isMsecretsError(error, "INVALID_FILE"),
    );
  });

  test("prototype-related names are handled safely", () => {
    assert.equal(nameProblem("secret", "__proto__"), `"__proto__" is reserved`);
    assert.equal(nameProblem("secret", "constructor"), null);
    const { document } = sampleDocument();
    assert.equal(own(document.secrets, "constructor"), undefined);
    assert.equal(own(document.secrets, "toString"), undefined);
    const text = serializeDocument(document).replace(
      '"secrets": {',
      '"secrets": {\n    "__proto__": { "values": {} },',
    );
    assert.match(issuesOf(JSON.parse(text)).join("\n"), /__proto__/);
  });
});

describe("names", () => {
  test("secrets are environment variable names", () => {
    for (const valid of ["A", "_X", "DATABASE_URL", "lower_case", "A1"]) {
      assert.equal(nameProblem("secret", valid), null, valid);
    }
    for (const invalid of ["", "1A", "A-B", "A.B", "A B", "Ä", "X".repeat(129)]) {
      assert.notEqual(nameProblem("secret", invalid), null, invalid);
    }
  });

  test("environments and recipients", () => {
    assert.equal(nameProblem("environment", "us-east-1.prod"), null);
    assert.notEqual(nameProblem("environment", "Production"), null);
    assert.notEqual(nameProblem("environment", "-dev"), null);
    assert.equal(nameProblem("recipient", "alice@example.com"), null);
    assert.equal(nameProblem("recipient", "ci+deploy"), null);
    assert.notEqual(nameProblem("recipient", "Alice"), null);
  });
});

describe("JSON schema", () => {
  type Schema = {
    properties: Record<
      string,
      {
        propertyNames?: { pattern: string };
        additionalProperties?: { properties?: Record<string, { pattern?: string }> };
      }
    >;
  };
  const schema = JSON.parse(
    readFileSync(join(import.meta.dirname, "..", "..", "ts-sdk", "schema", "v4.json"), "utf8"),
  ) as Schema;
  const pattern = (section: string) =>
    new RegExp(schema.properties[section]?.propertyNames?.pattern ?? "^$");

  test("name patterns agree with the validator", () => {
    const kinds = {
      secrets: "secret",
      environments: "environment",
      recipients: "recipient",
    } as const;
    const samples = [
      "A",
      "_X",
      "DATABASE_URL",
      "a",
      "dev",
      "us-east-1.prod",
      "alice@example.com",
      "ci+deploy",
      "-x",
      "1A",
      "A-B",
      "Alice",
      "x.",
      "",
    ];
    for (const [section, kind] of Object.entries(kinds)) {
      for (const sample of samples) {
        assert.equal(
          pattern(section).test(sample),
          nameProblem(kind, sample) === null,
          `${kind} ${JSON.stringify(sample)}`,
        );
      }
    }
  });

  test("key pattern accepts every key form", () => {
    const key = new RegExp(
      schema.properties["recipients"]?.additionalProperties?.properties?.["key"]?.pattern ?? "^$",
    );
    const { document } = sampleDocument();
    for (const entry of Object.values(document.recipients)) {
      assert.match(entry.key, key);
    }
    assert.match(
      readFileSync(join(import.meta.dirname, "fixtures", "ssh", "plain.pub"), "utf8")
        .split(" ")
        .slice(0, 2)
        .join(" "),
      key,
    );
  });
});

describe("terminal escape injection", () => {
  const escape = "\u001b]52;c;cHduZWQ=\u0007\u001b[2K";

  test("descriptions with control characters are rejected", () => {
    const { document } = sampleDocument();
    const input = JSON.parse(serializeDocument(document)) as {
      secrets: Record<string, { description?: string }>;
    };
    const secret = input.secrets["DATABASE_URL"];
    assert.ok(secret);
    secret.description = `Primary${escape}`;
    assert.match(issuesOf(input).join("\n"), /must not contain control characters/);
    assert.throws(
      () => describeSecret(document, "DATABASE_URL", `x${escape}`),
      /must not contain control characters/,
    );
    assert.throws(
      () => describeRecipient(document, "alice", "tab\there"),
      /must not contain control characters/,
    );
  });

  test("validation errors never echo raw control characters", () => {
    const { document } = sampleDocument();
    const input = JSON.parse(serializeDocument(document)) as { secrets: Record<string, unknown> };
    input.secrets[`EVIL${escape}`] = { values: {} };
    assert.throws(
      () => parseDocument(input),
      (error: unknown) =>
        error instanceof Error && !/[\u0000-\u001f]/.test(error.message.replace(/\n/g, "")),
    );
  });
});
