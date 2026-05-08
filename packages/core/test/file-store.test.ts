import assert from "node:assert";
import { test } from "node:test";

import {
  getSecretsFile,
  modifySecretsFile,
  writeSecretsFile,
} from "../src/file-store.ts";
import { createFixtureFile, createTempSecretsPath } from "./helpers.ts";

test("writeSecretsFile validates before write and preserves existing valid file", () => {
  const secretsPath = createTempSecretsPath();
  const fixture = createFixtureFile();

  writeSecretsFile(secretsPath, fixture);

  assert.throws(
    () =>
      writeSecretsFile(secretsPath, {
        ...fixture,
        secrets: {
          BAD_SECRET: {
            values: {
              development: {
                encryptedValue: "ciphertext",
                owners: ["missing-owner"],
              },
            },
          },
        },
      }),
    /Owner missing-owner is not present in \$\.keys/,
  );

  assert.deepEqual(getSecretsFile(secretsPath), fixture);
});

test("modifySecretsFile does not persist partial changes when callback throws", async () => {
  const secretsPath = createTempSecretsPath();
  const fixture = createFixtureFile();
  writeSecretsFile(secretsPath, fixture);

  await assert.rejects(
    () =>
      modifySecretsFile(secretsPath, async (draft) => {
        draft.environments.push("preview");
        draft.secrets.API_KEY!.values.preview = {
          encryptedValue: "ciphertext-preview",
          owners: ["owner-1"],
        };

        throw new Error("boom");
      }),
    /boom/,
  );

  assert.deepEqual(getSecretsFile(secretsPath), fixture);
});
