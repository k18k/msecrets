import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, test } from "node:test";

import { tempDir } from "../../core/test/helpers.ts";
import {
  type IdentitySource,
  createClient,
  injectEnv,
  isMsecretsError,
  load,
} from "../src/index.ts";
import fixture from "./fixtures/app.ms.json" with { type: "json" };

const FIXTURES = join(import.meta.dirname, "fixtures");
// --import takes a URL; absolute Windows paths are not valid specifiers.
const REGISTER = pathToFileURL(join(import.meta.dirname, "..", "src", "register.ts")).href;
const DEVELOPER = readFileSync(join(FIXTURES, "developer.identity.txt"), "utf8");
const PRODUCTION = readFileSync(join(FIXTURES, "production.identity.txt"), "utf8");
const developer = DEVELOPER.split("\n").find((line) => line.startsWith("AGE-")) ?? "";
const production = PRODUCTION.split("\n").find((line) => line.startsWith("AGE-")) ?? "";

const code = (expected: string, pattern?: RegExp) => (error: unknown) =>
  isMsecretsError(error) && error.code === expected && (!pattern || pattern.test(error.message));

describe("createClient", () => {
  test("reads a typed JSON import", () => {
    const client = createClient({ file: fixture, env: "production", identities: [production] });
    assert.equal(client.environment, "production");
    const url: string = client.get("DATABASE_URL");
    assert.equal(url, "postgres://db.internal/prod");
    assert.equal(client.get("API_TOKEN"), 'prod-token with spaces & "quotes"\nand a second line');
    assert.deepEqual(client.keys().toSorted(), ["API_TOKEN", "DATABASE_URL", "SENTRY_DSN"]);
    assert.throws(
      // @ts-expect-error: unknown secret names are type errors with a JSON import
      () => client.get("DATABSE_URL"),
      code("NOT_FOUND", /did you mean "DATABASE_URL"/),
    );
  });

  test("defaults: file discovery from cwd, MSECRETS_ENV, then development", (t) => {
    const directory = tempDir(t);
    copyFileSync(join(FIXTURES, "app.ms.json"), join(directory, ".env.ms.json"));

    const client = createClient({ cwd: directory, identities: [developer] });
    assert.equal(client.environment, "development");
    assert.equal(client.get("DATABASE_URL"), "postgres://localhost/dev");
    assert.equal(client.has("SENTRY_DSN"), false);
    assert.throws(() => client.get("SENTRY_DSN"), /does not apply to environment "development"/);

    const previous = process.env["MSECRETS_ENV"];
    process.env["MSECRETS_ENV"] = "production";
    try {
      assert.equal(
        createClient({ cwd: directory, identities: [developer] }).environment,
        "production",
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
    const client = createClient({
      file: fixture,
      env: "production",
      identities: ["file:key.txt"],
      cwd: directory,
    });
    assert.equal(client.get("SENTRY_DSN"), "https://sentry.example/1");
    assert.deepEqual(client.identities(), [`file ${join(directory, "key.txt")}`]);
  });

  test("identities load lazily, only when a value is decrypted", () => {
    let loads = 0;
    const source: IdentitySource = {
      label: "counting",
      load: () => {
        loads++;
        throw new Error("password manager locked");
      },
    };
    const client = createClient({ file: fixture, env: "production", identities: [source] });
    assert.equal(client.has("DATABASE_URL"), true);
    assert.equal(client.keys().length, 3);
    assert.equal(loads, 0);
    assert.throws(() => client.get("DATABASE_URL"), /password manager locked/);
  });

  test("all() returns the complete, frozen environment", () => {
    const secrets = load({ file: fixture, env: "production", identities: [production] });
    assert.deepEqual(Object.keys(secrets).toSorted(), ["API_TOKEN", "DATABASE_URL", "SENTRY_DSN"]);
    assert.ok(Object.isFrozen(secrets));
  });

  test("all() refuses an incomplete environment", () => {
    const incomplete = structuredClone(fixture);
    delete (incomplete.secrets.API_TOKEN.values as Record<string, unknown>)["production"];
    assert.throws(
      () => load({ file: incomplete, env: "production", identities: [production] }),
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
      () =>
        createClient({ file: tampered, env: "production", identities: [production] }).get(
          "DATABASE_URL",
        ),
      code("SIGNATURE"),
    );

    assert.throws(
      () =>
        createClient({ file: fixture, env: "development", identities: [production] }).get(
          "DATABASE_URL",
        ),
      code("ACCESS_DENIED", /You are: production-runtime/),
    );
  });

  test("invalid files and environments are rejected up front", () => {
    assert.throws(
      () => createClient({ file: { secrets: {} }, identities: [developer] }),
      code("INVALID_FILE"),
    );
    assert.throws(
      () => createClient({ file: fixture, env: "staging", identities: [developer] }),
      code("NOT_FOUND"),
    );
  });

  test("no identity at all explains how to provide one", () => {
    const empty: IdentitySource = { label: "empty", load: () => [] };
    assert.throws(
      () => createClient({ file: fixture, identities: [empty] }).get("DATABASE_URL"),
      /Set MSECRETS_IDENTITY/,
    );
  });
});

describe("injectEnv and register", () => {
  test("explicit environment variables win unless override is set", () => {
    const target: NodeJS.ProcessEnv = { DATABASE_URL: "explicit" };
    const injected = injectEnv({
      file: fixture,
      env: "production",
      identities: [production],
      target,
    });
    assert.deepEqual(injected.toSorted(), ["API_TOKEN", "SENTRY_DSN"]);
    assert.equal(target["DATABASE_URL"], "explicit");
    injectEnv({
      file: fixture,
      env: "production",
      identities: [production],
      target,
      override: true,
    });
    assert.equal(target["DATABASE_URL"], "postgres://db.internal/prod");
  });

  test("node --import register populates process.env and scrubs the identity", () => {
    const output = execFileSync(
      process.execPath,
      [
        "--import",
        REGISTER,
        "-e",
        "console.log(JSON.stringify([process.env.DATABASE_URL, process.env.SENTRY_DSN, process.env.MSECRETS_IDENTITY ?? null]))",
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          MSECRETS_FILE: join(FIXTURES, "app.ms.json"),
          MSECRETS_ENV: "production",
          MSECRETS_IDENTITY: production,
        },
      },
    );
    assert.deepEqual(JSON.parse(output), [
      "postgres://db.internal/prod",
      "https://sentry.example/1",
      null,
    ]);
  });

  test("register fails startup with a clear message", () => {
    assert.throws(
      () =>
        execFileSync(process.execPath, ["--import", REGISTER, "-e", "0"], {
          encoding: "utf8",
          stdio: "pipe",
          env: {
            ...process.env,
            MSECRETS_FILE: join(FIXTURES, "app.ms.json"),
            MSECRETS_ENV: "production",
            MSECRETS_IDENTITY: developer.replace(/.$/, ""),
          },
        }),
      /env MSECRETS_IDENTITY/,
    );
  });
});
