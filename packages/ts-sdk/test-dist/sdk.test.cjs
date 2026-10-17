// CommonJS consumers: require() the built package and the secrets file.
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");

const { createClient, MsecretsError } = require("../dist/index.cjs");

const fixtures = join(__dirname, "..", "test", "fixtures");
const file = require("../test/fixtures/app.ms.json");
const key = readFileSync(join(fixtures, "developer.identity.txt"), "utf8");

test("CommonJS build decrypts", () => {
  const secrets = createClient(file, {
    env: "development",
    identities: [key.split("\n").find((line) => line.startsWith("AGE-"))],
  });
  assert.equal(secrets.API_TOKEN, "dev-token");
  assert.throws(() => createClient(file, { env: "staging" }), MsecretsError);
});
