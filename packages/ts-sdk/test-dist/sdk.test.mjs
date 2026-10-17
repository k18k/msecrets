// Runs against the built package (dist) on every supported Node.js version.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createClient, injectEnv, isMsecretsError, load } from "../dist/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "test", "fixtures");
const file = JSON.parse(readFileSync(join(fixtures, "app.ms.json"), "utf8"));
const key = (name) =>
  readFileSync(join(fixtures, `${name}.identity.txt`), "utf8")
    .split("\n")
    .find((line) => line.startsWith("AGE-"));

test("ESM build decrypts and verifies", () => {
  assert.deepEqual(load({ file, env: "development", identities: [key("developer")] }), {
    API_TOKEN: "dev-token",
    DATABASE_URL: "postgres://localhost/dev",
  });
  const client = createClient({ file, env: "production", identities: [key("production")] });
  assert.equal(client.get("SENTRY_DSN"), "https://sentry.example/1");
});

test("ESM build rejects tampering", () => {
  const tampered = structuredClone(file);
  const value = tampered.secrets.DATABASE_URL.values.production;
  const bytes = Buffer.from(value.data, "base64");
  bytes[bytes.length - 1] ^= 1;
  value.data = bytes.toString("base64");
  assert.throws(
    () =>
      createClient({ file: tampered, env: "production", identities: [key("production")] }).get(
        "DATABASE_URL",
      ),
    (error) => isMsecretsError(error, "SIGNATURE"),
  );
});

test("injectEnv respects existing variables", () => {
  const target = { DATABASE_URL: "explicit" };
  injectEnv({ file, env: "production", identities: [key("production")], target });
  assert.equal(target.DATABASE_URL, "explicit");
  assert.equal(target.API_TOKEN, 'prod-token with spaces & "quotes"\nand a second line');
});

for (const [flag, entry] of [
  ["--import", "register.mjs"],
  ["--require", "register.cjs"],
]) {
  test(`node ${flag} register`, () => {
    const output = execFileSync(
      process.execPath,
      [
        flag,
        // --import takes a URL (absolute Windows paths are not valid specifiers); --require takes a path.
        flag === "--import"
          ? pathToFileURL(join(here, "..", "dist", entry)).href
          : join(here, "..", "dist", entry),
        "-e",
        "console.log(process.env.DATABASE_URL + '|' + (process.env.MSECRETS_IDENTITY || 'scrubbed'))",
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          MSECRETS_FILE: join(fixtures, "app.ms.json"),
          MSECRETS_ENV: "production",
          MSECRETS_IDENTITY: key("production"),
        },
      },
    );
    assert.equal(output.trim(), "postgres://db.internal/prod|scrubbed");
  });
}
