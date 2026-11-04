// Runs against the built package: MSECRETS_PLATFORMS= scripts/build-dist.sh && node --test sdk/test/
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { inspect } from "node:util";

import {
  createClient,
  fromFile,
  fromString,
  injectEnv,
  isMsecretsError,
  parseSourceSpec,
} from "../../dist/ts-sdk/index.mjs";
import fixture from "./fixtures/app.ms.json" with { type: "json" };

const FIXTURES = join(import.meta.dirname, "fixtures");
const DIST = join(import.meta.dirname, "..", "..", "dist", "ts-sdk");
const PRODUCTION = readFileSync(join(FIXTURES, "production.identity.txt"), "utf8");
const key = (name) =>
  readFileSync(join(FIXTURES, `${name}.identity.txt`), "utf8")
    .split("\n")
    .find((line) => line.startsWith("AGE-"));
const developer = key("developer");
const production = key("production");

const code = (expected, pattern) => (error) =>
  isMsecretsError(error) && error.code === expected && (!pattern || pattern.test(error.message));

function tempDir(t) {
  const directory = mkdtempSync(join(tmpdir(), "msecrets-sdk-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// Sets environment variables for one test and restores them afterwards.
function withEnv(t, variables) {
  const previous = Object.fromEntries(Object.keys(variables).map((name) => [name, process.env[name]]));
  const assign = (values) => {
    for (const [name, value] of Object.entries(values)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  };
  assign(variables);
  t.after(() => assign(previous));
}

describe("createClient", () => {
  test("returns the environment shaped like the imported file", () => {
    const secrets = createClient(fixture, { env: "production", identities: [production] });
    assert.equal(secrets.DATABASE_URL, "postgres://db.internal/prod");
    assert.equal(secrets.API_TOKEN, 'prod-token with spaces & "quotes"\nand a second line');
    assert.equal(secrets.SENTRY_DSN, "https://sentry.example/1");
    assert.equal(secrets.DATABSE_URL, undefined);
    assert.deepEqual(Object.keys(secrets).toSorted(), ["API_TOKEN", "DATABASE_URL", "SENTRY_DSN"]);
    assert.ok(Object.isFrozen(secrets));
  });

  test("leaves out secrets of other environments", () => {
    const secrets = createClient(fixture, { env: "development", identities: [developer] });
    assert.deepEqual({ ...secrets }, { API_TOKEN: "dev-token", DATABASE_URL: "postgres://localhost/dev" });
    assert.equal(secrets.SENTRY_DSN, undefined);
  });

  test("console.log shows names, never values", () => {
    const secrets = createClient(fixture, { env: "production", identities: [production] });
    const shown = inspect(secrets);
    assert.equal(shown, "Secrets (production) { API_TOKEN, DATABASE_URL, SENTRY_DSN }");
    assert.doesNotMatch(shown, /postgres/);
  });

  test("environment: MSECRETS_ENV, then development", (t) => {
    withEnv(t, { MSECRETS_ENV: undefined });
    assert.equal(createClient(fixture, { identities: [developer] }).API_TOKEN, "dev-token");
    process.env["MSECRETS_ENV"] = "production";
    assert.equal(createClient(fixture, { identities: [production] }).SENTRY_DSN, "https://sentry.example/1");
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

  test("explicit sources unlock encrypted identity files with MSECRETS_PASSPHRASE", (t) => {
    withEnv(t, { MSECRETS_PASSPHRASE: "pw" });
    const path = join(FIXTURES, "production.identity.age");
    const secrets = createClient(fixture, { env: "production", identities: [`file:${path}`] });
    assert.equal(secrets.SENTRY_DSN, "https://sentry.example/1");
    assert.equal(process.env["MSECRETS_PASSPHRASE"], undefined, "read once, then scrubbed");
  });

  test("identity source errors surface", () => {
    const failure = new Error("password manager locked");
    const locked = {
      label: "locked",
      load: () => {
        throw failure;
      },
    };
    assert.throws(() => createClient(fixture, { env: "production", identities: [locked] }), (error) => error === failure);
  });

  test("refuses an incomplete environment", () => {
    const incomplete = structuredClone(fixture);
    delete incomplete.secrets.API_TOKEN.values["production"];
    assert.throws(
      () => createClient(incomplete, { env: "production", identities: [production] }),
      code("NOT_FOUND", /^Environment "production" is incomplete; these secrets have no value: API_TOKEN$/),
    );
  });

  test("tampered values and wrong keys fail loudly", () => {
    const tampered = structuredClone(fixture);
    const value = tampered.secrets.DATABASE_URL.values.production;
    const bytes = Buffer.from(value.data, "base64");
    bytes[bytes.length - 1] ^= 1;
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
    assert.throws(() => createClient({ secrets: {} }, { identities: [developer] }), code("INVALID_FILE"));
    assert.throws(() => createClient(fixture, { env: "staging", identities: [developer] }), code("NOT_FOUND"));
    assert.throws(() => createClient(fixture, { identities: ["nope:x"] }), code("USAGE", /Unknown identity source/));
  });

  test("no identity at all explains how to provide one", () => {
    const empty = { label: "empty", load: () => [] };
    assert.throws(() => createClient(fixture, { identities: [empty] }), code("IDENTITY_SOURCE", /Set MSECRETS_IDENTITY/));
  });
});

describe("identity sources", () => {
  test("built-in sources have labels, load identities, and validate eagerly", (t) => {
    const directory = tempDir(t);
    writeFileSync(join(directory, "key.txt"), PRODUCTION);
    const source = fromFile(join(directory, "key.txt"));
    assert.equal(source.label, `file ${join(directory, "key.txt")}`);
    const [loaded] = source.load();
    assert.equal(loaded.identity, production);
    assert.equal(loaded.source, source.label);
    assert.equal(fromString(developer).label, "inline identity");
    assert.throws(() => parseSourceSpec("nope:x"), code("USAGE"));
  });

  test("custom sources return identity strings", () => {
    const custom = { label: "vault", load: () => [{ identity: production, source: "vault" }] };
    assert.equal(createClient(fixture, { env: "production", identities: [custom] }).SENTRY_DSN, "https://sentry.example/1");
  });

  test("a passphrase function unlocks encrypted identity files", () => {
    const labels = [];
    const source = fromFile(join(FIXTURES, "production.identity.age"), {
      passphrase: (label) => (labels.push(label), "pw"),
    });
    assert.equal(createClient(fixture, { env: "production", identities: [source] }).SENTRY_DSN, "https://sentry.example/1");
    assert.equal(labels.length, 1);
    const failure = new Error("cancelled");
    const cancelled = fromFile(join(FIXTURES, "production.identity.age"), {
      passphrase: () => {
        throw failure;
      },
    });
    assert.throws(() => createClient(fixture, { env: "production", identities: [cancelled] }), (error) => error === failure);
  });

  test("cmd: runs a command synchronously and reads its output", (t) => {
    const script = join(tempDir(t), "print.cjs");
    writeFileSync(script, `process.stdout.write(${JSON.stringify(PRODUCTION)})`);
    const secrets = createClient(fixture, {
      env: "production",
      identities: [`cmd:"${process.execPath}" "${script}"`],
    });
    assert.equal(secrets.SENTRY_DSN, "https://sentry.example/1");
    assert.throws(
      () => createClient(fixture, { env: "production", identities: ["cmd:msecrets-no-such-command"] }),
      code("IDENTITY_SOURCE", /is not installed or not on PATH/),
    );
  });

  test("the default chain reads MSECRETS_IDENTITY and scrubs the identity variables", (t) => {
    withEnv(t, {
      MSECRETS_IDENTITY: PRODUCTION,
      MSECRETS_PASSPHRASE: "unused",
      MSECRETS_IDENTITY_FILE: undefined,
      MSECRETS_IDENTITY_SOURCE: undefined,
      CREDENTIALS_DIRECTORY: undefined,
      MSECRETS_CONFIG_DIR: tempDir(t),
    });
    assert.equal(createClient(fixture, { env: "production" }).SENTRY_DSN, "https://sentry.example/1");
    assert.equal(process.env["MSECRETS_IDENTITY"], undefined);
    assert.equal(process.env["MSECRETS_PASSPHRASE"], undefined);
  });

  test("the default chain reads MSECRETS_IDENTITY_FILE", (t) => {
    withEnv(t, {
      MSECRETS_IDENTITY: undefined,
      MSECRETS_IDENTITY_FILE: join(FIXTURES, "developer.identity.txt"),
      MSECRETS_CONFIG_DIR: tempDir(t),
    });
    assert.equal(createClient(fixture, { env: "development" }).API_TOKEN, "dev-token");
  });
});

describe("injectEnv", () => {
  test("explicit environment variables win unless override is set", () => {
    const target = { DATABASE_URL: "explicit" };
    const injected = injectEnv(fixture, { env: "production", identities: [production], target });
    assert.deepEqual(injected.toSorted(), ["API_TOKEN", "SENTRY_DSN"]);
    assert.equal(target["DATABASE_URL"], "explicit");
    injectEnv(fixture, { env: "production", identities: [production], target, override: true });
    assert.equal(target["DATABASE_URL"], "postgres://db.internal/prod");
  });
});

describe("runtime", () => {
  test("no globals leak from the Go runtime", () => {
    for (const name of ["Go", "fs", "path", "__msecrets"]) {
      assert.equal(name in globalThis, false, name);
    }
  });

  test("size and cold start", (t) => {
    const size = statSync(join(DIST, "msecrets.wasm")).size;
    t.diagnostic(`msecrets.wasm: ${(size / 1024 / 1024).toFixed(2)} MiB`);
    assert.ok(size < 16 * 1024 * 1024);
    const measure = `
      const start = performance.now();
      const { createClient } = require(${JSON.stringify(join(DIST, "index.cjs"))});
      createClient(require(${JSON.stringify(join(FIXTURES, "app.ms.json"))}), { env: "development", identities: [${JSON.stringify(developer)}] });
      process.stdout.write(String(performance.now() - start));`;
    const cold = Number(execFileSync(process.execPath, ["-e", measure], { encoding: "utf8" }));
    t.diagnostic(`first createClient (cold start): ${cold.toFixed(0)} ms`);
    assert.ok(cold > 0);
  });
});
