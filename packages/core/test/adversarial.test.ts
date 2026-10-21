/**
 * Properties that must hold for hostile input, on every platform (no age binary needed):
 * every corruption is rejected with an MsecretsError, nothing partially authenticated
 * is returned, and input size is bounded.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import { type AgeRecipient, MAX_STANZAS, decryptAge, encryptAge } from "../src/crypto/age.ts";
import { fromBase64, toBase64 } from "../src/crypto/encoding.ts";
import { supportsMlKem } from "../src/crypto/primitives.ts";
import {
  MsecretsError,
  addEnvironment,
  addRecipient,
  createDocument,
  generateIdentity,
  inspectCell,
  isMsecretsError,
  parseDocumentText,
  parseIdentity,
  parsePublicKey,
  readOnlyPublicKey,
  revealValue,
  serializeDocument,
} from "../src/index.ts";
import { FUZZ_CASES, FUZZ_SEED, FUZZ_TIMEOUT, MUTATIONS, seeded } from "./fuzz.ts";
import { sampleDocument } from "./helpers.ts";

const SSH = join(import.meta.dirname, "fixtures", "ssh");

/** Runs `action`, which must either succeed or throw an MsecretsError (never a crash). */
function attempt<T>(action: () => T): T | MsecretsError {
  try {
    return action();
  } catch (error) {
    assert.ok(error instanceof MsecretsError, `unexpected ${String(error)}`);
    return error;
  }
}

const unknownStanza = (body: Buffer): AgeRecipient => ({
  wrap: () => [{ args: ["unknown-type", "argument"], body }],
});

const stanzas = (count: number) =>
  Array.from({ length: count }, () => unknownStanza(Buffer.alloc(0)));
/** A header with the given stanza lines and a placeholder MAC. */
const header = (lines: string) =>
  Buffer.from(`age-encryption.org/v1\n${lines}--- ${"A".repeat(43)}\n`);

describe("age under hostile input", () => {
  const identity = generateIdentity();
  const recipients = [
    identity.publicKey.recipient,
    ...(supportsMlKem() ? [generateIdentity({ postQuantum: true }).publicKey.recipient] : []),
    parsePublicKey(readFileSync(join(SSH, "plain.pub"), "utf8")).recipient,
  ];

  test("round-trips every size around the 64 KiB chunk boundary, for every recipient type", () => {
    const ssh = parseIdentity(readFileSync(join(SSH, "plain"), "utf8"));
    for (const size of [0, 1, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 3 * 64 * 1024]) {
      const plaintext = seeded(size).bytes(size);
      assert.deepEqual(
        decryptAge(encryptAge(plaintext, recipients), [identity.ageIdentity]),
        plaintext,
      );
      assert.deepEqual(decryptAge(encryptAge(plaintext, recipients), [ssh.ageIdentity]), plaintext);
    }
  });

  test("every single-bit flip and every truncation of a file is rejected", () => {
    const file = encryptAge(Buffer.from("secret"), [
      unknownStanza(Buffer.alloc(48, 1)),
      identity.publicKey.recipient,
    ]);
    for (let bit = 0; bit < file.length * 8; bit++) {
      const flipped = Buffer.from(file);
      flipped[bit >> 3] = (flipped[bit >> 3] ?? 0) ^ (1 << (bit & 7));
      assert.ok(
        attempt(() => decryptAge(flipped, [identity.ageIdentity])) instanceof MsecretsError,
        `bit ${bit}`,
      );
    }
    for (let length = 0; length < file.length; length++) {
      assert.ok(
        attempt(() => decryptAge(file.subarray(0, length), [identity.ageIdentity])) instanceof
          MsecretsError,
        `length ${length}`,
      );
    }
  });

  test(`random mutations never yield other plaintext (seed ${FUZZ_SEED})`, FUZZ_TIMEOUT, () => {
    const random = seeded(FUZZ_SEED);
    for (let index = 0; index < FUZZ_CASES; index++) {
      const plaintext = random.bytes(random.pick([0, 5, 70_000]));
      let file = encryptAge(plaintext, [random.pick(recipients), identity.publicKey.recipient]);
      for (let count = 1 + random.int(3); count > 0; count--) {
        file = random.pick(MUTATIONS)[1](file, random);
      }
      const result = attempt(() => decryptAge(file, [identity.ageIdentity]));
      assert.ok(result instanceof MsecretsError || result.equals(plaintext), `case ${index}`);
    }
  });

  test("random bytes are rejected with an MsecretsError", () => {
    const random = seeded(FUZZ_SEED);
    for (let index = 0; index < FUZZ_CASES; index++) {
      const garbage = random.bytes(random.int(300));
      const file = random.int(2)
        ? Buffer.concat([Buffer.from("age-encryption.org/v1\n"), garbage])
        : garbage;
      assert.ok(attempt(() => decryptAge(file, [identity.ageIdentity])) instanceof MsecretsError);
    }
  });

  test("an identity that is not a recipient gets nothing", () => {
    const file = encryptAge(Buffer.from("secret"), recipients);
    assert.throws(
      () => decryptAge(file, [generateIdentity().ageIdentity]),
      (error: unknown) => isMsecretsError(error, "AGE_NO_MATCH"),
    );
  });

  test(`headers are bounded: at most ${MAX_STANZAS} stanzas and 1 MiB`, () => {
    const full = encryptAge(Buffer.from("x"), [
      ...stanzas(MAX_STANZAS - 1),
      identity.publicKey.recipient,
    ]);
    assert.deepEqual(decryptAge(full, [identity.ageIdentity]), Buffer.from("x"));
    assert.throws(
      () => encryptAge(Buffer.from("x"), [...stanzas(MAX_STANZAS), identity.publicKey.recipient]),
      (error: unknown) => isMsecretsError(error, "USAGE"),
    );

    assert.throws(
      () => decryptAge(header("-> x\n\n".repeat(MAX_STANZAS + 1)), [identity.ageIdentity]),
      /more than 1024 recipient stanzas/,
    );
    const longBody = `${`${"A".repeat(64)}\n`.repeat(17_000)}\n`;
    assert.throws(
      () => decryptAge(header(`-> x\n${longBody}`), [identity.ageIdentity]),
      /larger than 1 MiB/,
    );
  });
});

describe("encodings and keys under hostile input", () => {
  test("base64 accepts exactly the canonical unpadded encodings", () => {
    const random = seeded(FUZZ_SEED);
    const alphabet = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_ \n"];
    for (let index = 0; index < FUZZ_CASES * 10; index++) {
      const text = Array.from({ length: random.int(12) }, () => random.pick(alphabet)).join("");
      const result = attempt(() => fromBase64(text, "INVALID_KEY", "fuzz"));
      const canonical =
        /^[A-Za-z0-9+/]*$/.test(text) && toBase64(Buffer.from(text, "base64")) === text;
      assert.equal(!(result instanceof MsecretsError), canonical, JSON.stringify(text));
    }
  });

  test("any single changed character in a key is rejected", () => {
    const identity = generateIdentity();
    const random = seeded(FUZZ_SEED);
    const keys: [string, (text: string) => unknown][] = [
      [identity.publicKey.token, parsePublicKey],
      [readOnlyPublicKey(identity.publicKey).token, parsePublicKey],
      [identity.secret, parseIdentity],
    ];
    for (const [key, parse] of keys) {
      for (let index = 0; index < 200; index++) {
        const position = random.int(key.length);
        const replacement = random.pick([..."qpzry9x8gf2tvdw0s3jn54khce6mua7lQPZRY0"]);
        const changed = key.slice(0, position) + replacement + key.slice(position + 1);
        if (changed !== key && changed.toLowerCase() !== key.toLowerCase()) {
          assert.ok(attempt(() => parse(changed)) instanceof MsecretsError, changed);
        }
      }
    }
  });
});

describe("secrets files under hostile input", () => {
  test(`random edits of a file are rejected, or the edited value is invalid (seed ${FUZZ_SEED})`, () => {
    const { document, people } = sampleDocument();
    const text = serializeDocument(document);
    const random = seeded(FUZZ_SEED);
    for (let index = 0; index < FUZZ_CASES; index++) {
      const position = random.int(text.length);
      const edited =
        text.slice(0, position) + random.pick([...'aZ09+/"{}[],:\\ é']) + text.slice(position + 1);
      const parsed = attempt(() => parseDocumentText(edited));
      if (parsed instanceof MsecretsError) {
        continue;
      }
      // Whatever survived validation must still never reveal a value it does not authenticate.
      for (const [secret, environment] of [
        ["DATABASE_URL", "development"],
        ["DATABASE_URL", "production"],
      ] as const) {
        const cell = inspectCell(parsed, secret, environment);
        const value: string | MsecretsError = attempt((): string =>
          revealValue(parsed, [people.alice], secret, environment),
        );
        if (cell.state === "invalid") {
          assert.ok(value instanceof MsecretsError, `case ${index}: an invalid value was revealed`);
        } else if (!(value instanceof MsecretsError)) {
          assert.equal(value, environment === "production" ? "postgres://prod" : "postgres://dev");
        }
      }
    }
  });

  test("files over 64 MiB are rejected before parsing", () => {
    assert.throws(
      () => parseDocumentText(" ".repeat(64 * 1024 * 1024 + 1)),
      (error: unknown) =>
        isMsecretsError(error, "INVALID_FILE") && /larger than 64 MiB/.test(error.message),
    );
  });

  test(`an environment has at most ${MAX_STANZAS} recipients`, () => {
    const document = createDocument();
    const names = Array.from({ length: MAX_STANZAS + 1 }, (_, index) => `r${index}`);
    for (const name of names) {
      addRecipient(document, name, readOnlyPublicKey(generateIdentity().publicKey).token);
    }
    addEnvironment(document, "big", names);
    assert.throws(
      () => parseDocumentText(serializeDocument(document)),
      (error: unknown) =>
        isMsecretsError(error, "INVALID_FILE") && /At most 1024 recipients/.test(error.message),
    );
  });
});
