// CommonJS consumers: require() the built package.
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");

const { createClient, MsecretsError } = require("../dist/index.cjs");

const fixtures = join(__dirname, "..", "test", "fixtures");
const file = JSON.parse(readFileSync(join(fixtures, "app.ms.json"), "utf8"));
const key = readFileSync(join(fixtures, "developer.identity.txt"), "utf8");

test("CommonJS build decrypts", () => {
  const client = createClient({
    file,
    env: "development",
    identities: [key.split("\n").find((line) => line.startsWith("AGE-"))],
  });
  assert.equal(client.get("API_TOKEN"), "dev-token");
  assert.throws(() => client.get("NOPE"), MsecretsError);
});
