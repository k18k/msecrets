/**
 * Interoperability with the reference age implementation.
 * Runs when `age` is on PATH or MSECRETS_AGE_BIN points to it; CI installs it.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import { armor, decryptAge, encryptAge } from "../src/crypto/age.ts";
import { supportsMlKem } from "../src/crypto/primitives.ts";
import { generateIdentity, parseIdentity, parsePublicKey } from "../src/keys.ts";

const AGE = process.env["MSECRETS_AGE_BIN"] ?? "age";
const AGE_KEYGEN = process.env["MSECRETS_AGE_KEYGEN_BIN"] ?? "age-keygen";
const hasAge = spawnSync(AGE, ["--version"], { encoding: "utf8" }).status === 0;
const SSH = join(import.meta.dirname, "fixtures", "ssh");

const age = (args: string[], input?: Buffer) => execFileSync(AGE, args, input ? { input } : {});
const keygen = (args: string[]) =>
  execFileSync(AGE_KEYGEN, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });

describe("age CLI interoperability", { skip: hasAge ? false : "age binary not available" }, () => {
  const directory = mkdtempSync(join(tmpdir(), "msecrets-interop-"));
  after(() => rmSync(directory, { recursive: true, force: true }));

  const plaintext = Buffer.from("interop ✓ ".repeat(10_000));

  for (const postQuantum of [false, true]) {
    const label = postQuantum ? "MLKEM768-X25519" : "X25519";
    const skip = postQuantum && !supportsMlKem() ? "ML-KEM unsupported" : false;

    test(`${label}: msecrets encrypts, age decrypts`, { skip }, () => {
      const identity = generateIdentity({ postQuantum });
      const keyFile = join(directory, `${label}.key`);
      writeFileSync(keyFile, `${identity.secret}\n`);
      const ciphertext = encryptAge(plaintext, [identity.publicKey.recipient]);
      assert.deepEqual(age(["-d", "-i", keyFile], ciphertext), plaintext);
    });

    test(`${label}: age encrypts (armored), msecrets decrypts`, { skip }, () => {
      const keyFile = join(directory, `${label}-age.key`);
      keygen([...(postQuantum ? ["-pq"] : []), "-o", keyFile]);
      const identity = parseIdentity(
        readFileSync(keyFile, "utf8")
          .split("\n")
          .find((line) => line.startsWith("AGE-")) ?? "",
      );
      const recipient = keygen(["-y", keyFile]).trim();
      assert.equal(recipient, parsePublicKey(recipient).token);
      const ciphertext = age(["-a", "-r", recipient], plaintext);
      assert.deepEqual(decryptAge(ciphertext, [identity.ageIdentity]), plaintext);
    });
  }

  test("ssh-ed25519: both directions", () => {
    const identity = parseIdentity(readFileSync(join(SSH, "plain"), "utf8"));
    const fromUs = encryptAge(plaintext, [
      parsePublicKey(readFileSync(join(SSH, "plain.pub"), "utf8")).recipient,
    ]);
    assert.deepEqual(age(["-d", "-i", join(SSH, "plain")], fromUs), plaintext);

    const fromAge = age(["-R", join(SSH, "plain.pub")], plaintext);
    assert.deepEqual(decryptAge(fromAge, [identity.ageIdentity]), plaintext);
  });

  test("armored output is accepted by age", () => {
    const identity = generateIdentity();
    const keyFile = join(directory, "armor.key");
    writeFileSync(keyFile, `${identity.secret}\n`);
    const armored = Buffer.from(armor(encryptAge(plaintext, [identity.publicKey.recipient])));
    assert.deepEqual(age(["-d", "-i", keyFile], armored), plaintext);
  });
});
