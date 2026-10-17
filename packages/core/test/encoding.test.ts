import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { bech32Decode, bech32Encode, fromBase64, toBase64 } from "../src/crypto/encoding.ts";
import { isMsecretsError } from "../src/errors.ts";

describe("bech32", () => {
  test("accepts the BIP173 valid test vectors", () => {
    for (const valid of [
      "A12UEL5L",
      "a12uel5l",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      `11${"q".repeat(82)}c8247j`,
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    ]) {
      const { hrp } = bech32Decode(valid);
      assert.equal(hrp, valid.toLowerCase().slice(0, valid.lastIndexOf("1")));
    }
  });

  test("rejects the BIP173 invalid test vectors", () => {
    for (const invalid of [
      "pzry9x0s0muk",
      "1pzry9x0s0muk",
      "x1b4n0q5v",
      "li1dgmt3",
      "A1G7SGD8",
      "10a06t8",
      "1qzzfhee",
      "A12uEL5L",
    ]) {
      assert.throws(
        () => bech32Decode(invalid),
        (error: unknown) => isMsecretsError(error, "INVALID_KEY"),
        invalid,
      );
    }
  });

  test("round-trips arbitrary data and long payloads", () => {
    for (const length of [0, 1, 31, 32, 33, 1216]) {
      const bytes = Buffer.alloc(length, length % 251);
      const encoded = bech32Encode("age", bytes);
      assert.deepEqual(bech32Decode(encoded).bytes, bytes);
      assert.deepEqual(bech32Decode(encoded.toUpperCase()).bytes, bytes);
    }
  });

  test("detects a single changed character", () => {
    const encoded = bech32Encode("age", Buffer.alloc(32, 7));
    const tampered = `${encoded.slice(0, -1)}${encoded.endsWith("q") ? "p" : "q"}`;
    assert.throws(() => bech32Decode(tampered), /checksum/);
  });
});

describe("base64", () => {
  test("encodes without padding and round-trips", () => {
    assert.equal(toBase64(Buffer.from("a")), "YQ");
    assert.deepEqual(fromBase64("YQ", "AGE_HEADER", "test"), Buffer.from("a"));
  });

  test("rejects padding, bad characters, and non-canonical encodings", () => {
    for (const bad of ["YQ==", "Y", "YR", "Y Q", "YQ\n", "ab-_"]) {
      assert.throws(
        () => fromBase64(bad, "AGE_HEADER", "test"),
        (error: unknown) => isMsecretsError(error, "AGE_HEADER"),
        bad,
      );
    }
  });
});
