import assert from "node:assert";
import { test } from "node:test";

import {
  SecretsFileVersionError,
  validateSecretsFile,
  assertValidSecretsFile,
} from "../src/validation.ts";

test("validateSecretsFile rejects missing owners", () => {
  const result = validateSecretsFile({
    version: "2.0.0",
    environments: ["development"],
    keys: [
      {
        fingerprint: "abc",
        publicKey: "public-key",
        userIds: ["Test User"],
      },
    ],
    secrets: {
      API_KEY: {
        values: {
          development: {
            encryptedValue: "ciphertext",
          },
        },
      },
    },
  });

  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === "secret_value_owners_missing"));
});

test("assertValidSecretsFile throws a hard version error on major mismatch", () => {
  assert.throws(
    () => {
      assertValidSecretsFile({
        version: "3.0.0",
        environments: ["development"],
        keys: [],
        secrets: {},
      });
    },
    (error) =>
      error instanceof SecretsFileVersionError &&
      error.message === "Incompatible msecrets file version: expected 2.x.x, got 3.0.0",
  );
});

test("validateSecretsFile rejects unknown environments and unknown owners", () => {
  const result = validateSecretsFile({
    version: "2.0.0",
    environments: ["development"],
    keys: [
      {
        fingerprint: "owner-1",
        publicKey: "public-key",
        userIds: ["Test User"],
      },
    ],
    secrets: {
      API_KEY: {
        values: {
          staging: {
            encryptedValue: "ciphertext",
            owners: ["owner-2"],
          },
        },
      },
    },
  });

  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === "secret_environment_unknown"));
  assert.ok(result.issues.some((issue) => issue.code === "secret_value_owner_unknown"));
});

test("validateSecretsFile rejects empty and duplicate owners", () => {
  const result = validateSecretsFile({
    version: "2.0.0",
    environments: ["development"],
    keys: [
      {
        fingerprint: "owner-1",
        publicKey: "public-key",
        userIds: ["Test User"],
      },
    ],
    secrets: {
      API_KEY: {
        values: {
          development: {
            encryptedValue: "ciphertext",
            owners: ["owner-1", "owner-1", " "],
          },
        },
      },
    },
  });

  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === "secret_value_owner_duplicate"));
  assert.ok(result.issues.some((issue) => issue.code === "string_empty"));
});
