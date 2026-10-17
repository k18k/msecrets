import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { inflateSync } from "node:zlib";

import { type AgeIdentity, armor, decryptAge, dearmor } from "../src/crypto/age.ts";
import { hybridIdentity, scryptIdentity, x25519Identity } from "../src/crypto/age-recipients.ts";
import { bech32Decode } from "../src/crypto/encoding.ts";
import { sha256, supportsMlKem } from "../src/crypto/primitives.ts";
import { type ErrorCode, isMsecretsError } from "../src/errors.ts";

const VECTORS = join(import.meta.dirname, "vectors");

const EXPECTED_CODES: Record<string, ErrorCode> = {
  "header failure": "AGE_HEADER",
  "no match": "AGE_NO_MATCH",
  "HMAC failure": "AGE_HMAC",
  "payload failure": "AGE_PAYLOAD",
  "armor failure": "AGE_ARMOR",
};

function parseVector(raw: Buffer) {
  const separator = raw.indexOf("\n\n");
  const fields = raw.subarray(0, separator).toString("utf8").split("\n");
  const values = (key: string) =>
    fields.filter((line) => line.startsWith(`${key}: `)).map((line) => line.slice(key.length + 2));
  const body = raw.subarray(separator + 2);

  return {
    expect: values("expect")[0] ?? "",
    payload: values("payload")[0],
    identities: values("identity"),
    passphrases: values("passphrase"),
    data: values("compressed")[0] === "zlib" ? inflateSync(body) : body,
  };
}

function identityFromString(text: string): AgeIdentity {
  const { hrp, bytes } = bech32Decode(text);
  if (hrp === "age-secret-key-") {
    return x25519Identity(bytes);
  }
  if (hrp === "age-secret-key-pq-") {
    return hybridIdentity(bytes);
  }
  throw new Error(`Unexpected identity type ${hrp}`);
}

for (const name of readdirSync(VECTORS)
  .filter((file) => !file.endsWith(".md"))
  .toSorted()) {
  const vector = parseVector(readFileSync(join(VECTORS, name)));
  const needsMlKem = vector.identities.some((identity) =>
    identity.startsWith("AGE-SECRET-KEY-PQ-"),
  );

  test(
    `age vector ${name}`,
    { skip: needsMlKem && !supportsMlKem() ? "ML-KEM unsupported" : false },
    () => {
      const identities = [
        ...vector.identities.map(identityFromString),
        ...vector.passphrases.map((passphrase) => scryptIdentity(passphrase)),
      ];

      if (vector.expect === "success") {
        const plaintext = decryptAge(vector.data, identities);
        assert.equal(sha256(plaintext).toString("hex"), vector.payload);
        return;
      }

      const code = EXPECTED_CODES[vector.expect];
      assert.ok(code, `unknown expectation ${vector.expect}`);
      assert.throws(
        () => decryptAge(vector.data, identities),
        (error: unknown) => isMsecretsError(error, code),
      );
    },
  );
}

test("armor round-trips binary data", () => {
  for (const size of [0, 1, 47, 48, 49, 200]) {
    const data = Buffer.alloc(size, 7);
    assert.deepEqual(dearmor(armor(data)), data);
  }
});
