// CommonJS consumers: require() the built package and the secrets file.
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");

const { createClient, MsecretsError } = require("../../dist/ts-sdk/index.cjs");

const fixtures = join(__dirname, "fixtures");
const file = require("./fixtures/app.ms.json");
const key = readFileSync(join(fixtures, "developer.identity.txt"), "utf8");

test("CommonJS build decrypts", () => {
  const secrets = createClient(file, {
    env: "development",
    identities: [key.split("\n").find((line) => line.startsWith("AGE-"))],
  });
  assert.equal(secrets.API_TOKEN, "dev-token");
  assert.throws(() => createClient(file, { env: "staging" }), MsecretsError);
});

test("ESM and CommonJS share one module and one MsecretsError", async () => {
  const esm = await import("../../dist/ts-sdk/index.mjs");
  assert.equal(esm.MsecretsError, MsecretsError);
  assert.equal(esm.createClient, createClient);
});
