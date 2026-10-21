/**
 * Differential fuzzing against the reference age implementation: random valid
 * files (several recipient types, unknown stanzas, chunk boundaries, armor) and
 * mutations of them must be accepted or rejected exactly as `age` does, with the
 * same plaintext. Runs when `age` is available (CI installs it).
 *
 * Reproduce a failure with MSECRETS_FUZZ_SEED; go deeper with MSECRETS_FUZZ_CASES.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";

import { type AgeRecipient, armor, decryptAge, encryptAge } from "../src/crypto/age.ts";
import { supportsMlKem } from "../src/crypto/primitives.ts";
import { MsecretsError } from "../src/errors.ts";
import { generateIdentity, parseIdentity, parsePublicKey, readOnlyPublicKey } from "../src/keys.ts";
import { FUZZ_CASES, FUZZ_SEED, FUZZ_TIMEOUT, MUTATIONS, type Random, seeded } from "./fuzz.ts";

const AGE = process.env["MSECRETS_AGE_BIN"] ?? "age";
const hasAge = spawnSync(AGE, ["--version"]).status === 0;
const SSH = join(import.meta.dirname, "fixtures", "ssh");
const SIZES = [0, 1, 31, 32, 1000, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 128 * 1024];

type Outcome = { ok: boolean; plaintext?: Buffer };

/** A recipient type age does not know: it must be ignored, whatever its arguments and body. */
const unknown = (random: Random): AgeRecipient => ({
  wrap: () => [
    {
      args: [
        `fuzz-${random.int(1000)}`,
        ...Array.from({ length: random.int(4) }, () =>
          random.bytes(1 + random.int(8)).toString("base64url"),
        ),
      ],
      body: random.bytes(random.pick([0, 1, 47, 48, 49, 96, 200])),
    },
  ],
});

describe("age differential fuzzing", { skip: hasAge ? false : "age binary not available" }, () => {
  const directory = mkdtempSync(join(tmpdir(), "msecrets-fuzz-"));
  after(() => rmSync(directory, { recursive: true, force: true }));

  const classical = generateIdentity();
  const postQuantum = supportsMlKem() ? generateIdentity({ postQuantum: true }) : undefined;
  const ssh = parseIdentity(readFileSync(join(SSH, "plain"), "utf8"));
  const sshPublic = parsePublicKey(readFileSync(join(SSH, "plain.pub"), "utf8"));
  const stranger = generateIdentity();

  const keyFiles = [join(SSH, "plain")];
  for (const [name, identity] of [
    ["classical", classical],
    ["post-quantum", postQuantum],
  ] as const) {
    if (identity) {
      keyFiles.push(join(directory, `${name}.key`));
      writeFileSync(join(directory, `${name}.key`), `${identity.secret}\n`);
    }
  }
  const identities = [classical, postQuantum, ssh].flatMap((identity) =>
    identity ? [identity.ageIdentity] : [],
  );

  const ours = (file: Buffer): Outcome => {
    try {
      return { ok: true, plaintext: decryptAge(file, identities) };
    } catch (error) {
      assert.ok(error instanceof MsecretsError, `unexpected ${String(error)}`);
      return { ok: false };
    }
  };
  const reference = (file: Buffer): Outcome => {
    const result = spawnSync(AGE, ["-d", ...keyFiles.flatMap((key) => ["-i", key])], {
      input: file,
      maxBuffer: 16 * 1024 * 1024,
    });
    return result.status === 0 ? { ok: true, plaintext: result.stdout } : { ok: false };
  };

  const validFile = (random: Random): Buffer => {
    const ownRecipients = [
      classical.publicKey.recipient,
      sshPublic.recipient,
      ...(postQuantum ? [postQuantum.publicKey.recipient] : []),
    ];
    const recipients = [random.pick(ownRecipients)];
    for (let extra = random.int(4); extra > 0; extra--) {
      recipients.splice(
        random.int(recipients.length + 1),
        0,
        random.pick([stranger.publicKey.recipient, unknown(random), random.pick(ownRecipients)]),
      );
    }
    const file = encryptAge(random.bytes(random.pick(SIZES)), recipients);
    return random.int(5) === 0 ? Buffer.from(armor(file)) : file;
  };

  // Files written by age itself, including the "grease" stanzas it adds.
  const fromAge = [
    readOnlyPublicKey(classical.publicKey).token,
    ...(postQuantum ? [readOnlyPublicKey(postQuantum.publicKey).token] : []),
  ].flatMap((recipient) =>
    [SIZES[2], SIZES[6]].map((size) =>
      execFileSync(AGE, ["-r", recipient], { input: Buffer.alloc(size ?? 0, 0x61) }),
    ),
  );
  fromAge.push(execFileSync(AGE, ["-R", join(SSH, "plain.pub")], { input: Buffer.from("ssh") }));

  test(
    `valid and mutated files: same verdict and plaintext as age (seed ${FUZZ_SEED}, ${FUZZ_CASES} cases)`,
    FUZZ_TIMEOUT,
    () => {
      const random = seeded(FUZZ_SEED);
      let accepted = 0;
      for (let index = 0; index < FUZZ_CASES; index++) {
        let file = random.int(4) === 0 ? random.pick(fromAge) : validFile(random);
        const applied: string[] = [];
        if (random.int(5) !== 0) {
          for (let count = 1 + random.int(3); count > 0; count--) {
            const [name, mutate] = random.pick(MUTATIONS);
            file = mutate(file, random);
            applied.push(name);
          }
        }

        const expected = reference(file);
        const actual = ours(file);
        if (
          actual.ok !== expected.ok ||
          (actual.ok && !actual.plaintext?.equals(expected.plaintext ?? Buffer.alloc(0)))
        ) {
          // A private directory: a predictable name in the shared temp dir could be a planted symlink.
          const saved = join(
            mkdtempSync(join(tmpdir(), "msecrets-fuzz-failure-")),
            `${FUZZ_SEED}-${index}.age`,
          );
          writeFileSync(saved, file);
          assert.fail(
            `case ${index} (${applied.join(", ") || "unmutated"}): age ${expected.ok ? "accepts" : "rejects"}, msecrets ${actual.ok ? "accepts" : "rejects"}${actual.ok && expected.ok ? " with different plaintext" : ""}. File: ${saved}`,
          );
        }
        accepted += Number(actual.ok);
      }
      // Both outcomes must actually be exercised.
      assert.ok(accepted > FUZZ_CASES / 10 && accepted < FUZZ_CASES, `accepted ${accepted}`);
    },
  );
});
