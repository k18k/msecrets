// Runs against the built package (dist) on every supported Node.js version.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";

import { createClient, injectEnv, isMsecretsError } from "../dist/index.mjs";
// The documented way to use the SDK, on every supported Node.js version.
import file from "../test/fixtures/app.ms.json" with { type: "json" };

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "test", "fixtures");
const key = (name) =>
  readFileSync(join(fixtures, `${name}.identity.txt`), "utf8")
    .split("\n")
    .find((line) => line.startsWith("AGE-"));

test("ESM build decrypts and verifies", () => {
  const secrets = createClient(file, { env: "development", identities: [key("developer")] });
  assert.deepEqual(
    { ...secrets },
    { API_TOKEN: "dev-token", DATABASE_URL: "postgres://localhost/dev" },
  );
  assert.equal(inspect(secrets), "Secrets (development) { API_TOKEN, DATABASE_URL }");
  assert.equal(
    createClient(file, { env: "production", identities: [key("production")] }).SENTRY_DSN,
    "https://sentry.example/1",
  );
});

test("ESM build rejects tampering", () => {
  const tampered = structuredClone(file);
  const value = tampered.secrets.DATABASE_URL.values.production;
  const bytes = Buffer.from(value.data, "base64");
  bytes[bytes.length - 1] ^= 1;
  value.data = bytes.toString("base64");
  assert.throws(
    () => createClient(tampered, { env: "production", identities: [key("production")] }),
    (error) => isMsecretsError(error, "SIGNATURE"),
  );
});

test("injectEnv respects existing variables", () => {
  const target = { DATABASE_URL: "explicit" };
  injectEnv(file, { env: "production", identities: [key("production")], target });
  assert.equal(target.DATABASE_URL, "explicit");
  assert.equal(target.API_TOKEN, 'prod-token with spaces & "quotes"\nand a second line');
});
