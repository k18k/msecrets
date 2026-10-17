import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { inspect } from "node:util";

import { tempDir } from "../../core/test/helpers.ts";
import { type IdentitySource, createClient, injectEnv, isMsecretsError } from "../src/index.ts";
import fixture from "./fixtures/app.ms.json" with { type: "json" };

const FIXTURES = join(import.meta.dirname, "fixtures");
const DEVELOPER = readFileSync(join(FIXTURES, "developer.identity.txt"), "utf8");
const PRODUCTION = readFileSync(join(FIXTURES, "production.identity.txt"), "utf8");
const developer = DEVELOPER.split("\n").find((line) => line.startsWith("AGE-")) ?? "";
const production = PRODUCTION.split("\n").find((line) => line.startsWith("AGE-")) ?? "";

const code = (expected: string, pattern?: RegExp) => (error: unknown) =>
  isMsecretsError(error) && error.code === expected && (!pattern || pattern.test(error.message));

describe("createClient", () => {
  test("returns the environment shaped like the imported file", () => {
    const secrets = createClient(fixture, { env: "production", identities: [production] });
    const url: string = secrets.DATABASE_URL;
    assert.equal(url, "postgres://db.internal/prod");
    assert.equal(secrets.API_TOKEN, 'prod-token with spaces & "quotes"\nand a second line');
    // Limited to some environments, so possibly absent.
    const dsn: string | undefined = secrets.SENTRY_DSN;
    assert.equal(dsn, "https://sentry.example/1");
    // @ts-expect-error: a secret limited to some environments is not always a string
    const required: string = secrets.SENTRY_DSN;
    assert.ok(required);
    // @ts-expect-error: unknown secret names are type errors
    assert.equal(secrets.DATABSE_URL, undefined);
    assert.deepEqual(Object.keys(secrets).toSorted(), ["API_TOKEN", "DATABASE_URL", "SENTRY_DSN"]);
    assert.ok(Object.isFrozen(secrets));
  });

  test("leaves out secrets of other environments", () => {
    const secrets = createClient(fixture, { env: "development", identities: [developer] });
    assert.deepEqual(
      { ...secrets },
      { API_TOKEN: "dev-token", DATABASE_URL: "postgres://localhost/dev" },
    );
    assert.equal(secrets.SENTRY_DSN, undefined);
  });

  test("console.log shows names, never values", () => {
    const secrets = createClient(fixture, { env: "production", identities: [production] });
    const shown = inspect(secrets);
    assert.equal(shown, "Secrets (production) { API_TOKEN, DATABASE_URL, SENTRY_DSN }");
    assert.doesNotMatch(shown, /postgres/);
  });

  test("environment: MSECRETS_ENV, then development", () => {
    const previous = process.env["MSECRETS_ENV"];
    try {
      delete process.env["MSECRETS_ENV"];
      assert.equal(createClient(fixture, { identities: [developer] }).API_TOKEN, "dev-token");
      process.env["MSECRETS_ENV"] = "production";
      assert.equal(
        createClient(fixture, { identities: [production] }).SENTRY_DSN,
        "https://sentry.example/1",
      );
    } finally {
      if (previous === undefined) {
        delete process.env["MSECRETS_ENV"];
      } else {
        process.env["MSECRETS_ENV"] = previous;
      }
    }
  });

  test("identity strings can be raw keys or source specs", (t) => {
    const directory = tempDir(t);
    writeFileSync(join(directory, "key.txt"), PRODUCTION);
    const secrets = createClient(fixture, {
      env: "production",
      identities: [`file:${join(directory, "key.txt")}`],
    });
    assert.equal(secrets.SENTRY_DSN, "https://sentry.example/1");
  });

  test("identity source errors surface", () => {
    const locked: IdentitySource = {
      label: "locked",
      load: () => {
        throw new Error("password manager locked");
      },
    };
    assert.throws(
      () => createClient(fixture, { env: "production", identities: [locked] }),
      /password manager locked/,
    );
  });

  test("refuses an incomplete environment", () => {
    const incomplete = structuredClone(fixture);
    delete (incomplete.secrets.API_TOKEN.values as Record<string, unknown>)["production"];
    assert.throws(
      () => createClient(incomplete, { env: "production", identities: [production] }),
      code("NOT_FOUND", /incomplete; these secrets have no value: API_TOKEN/),
    );
  });

  test("tampered values and wrong keys fail loudly", () => {
    const tampered = structuredClone(fixture);
    const value = tampered.secrets.DATABASE_URL.values.production;
    const bytes = Buffer.from(value.data, "base64");
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
    value.data = bytes.toString("base64");
    assert.throws(
      () => createClient(tampered, { env: "production", identities: [production] }),
      code("SIGNATURE"),
    );

    assert.throws(
      () => createClient(fixture, { env: "development", identities: [production] }),
      code("ACCESS_DENIED", /You are: production-runtime/),
    );
  });

  test("invalid files and environments are rejected", () => {
    assert.throws(
      () => createClient({ secrets: {} }, { identities: [developer] }),
      code("INVALID_FILE"),
    );
    assert.throws(
      () => createClient(fixture, { env: "staging", identities: [developer] }),
      code("NOT_FOUND"),
    );
  });

  test("no identity at all explains how to provide one", () => {
    const empty: IdentitySource = { label: "empty", load: () => [] };
    assert.throws(
      () => createClient(fixture, { identities: [empty] }),
      code("IDENTITY_SOURCE", /Set MSECRETS_IDENTITY/),
    );
  });
});

describe("injectEnv", () => {
  test("explicit environment variables win unless override is set", () => {
    const target: NodeJS.ProcessEnv = { DATABASE_URL: "explicit" };
    const injected = injectEnv(fixture, { env: "production", identities: [production], target });
    assert.deepEqual(injected.toSorted(), ["API_TOKEN", "SENTRY_DSN"]);
    assert.equal(target["DATABASE_URL"], "explicit");
    injectEnv(fixture, { env: "production", identities: [production], target, override: true });
    assert.equal(target["DATABASE_URL"], "postgres://db.internal/prod");
  });
});
