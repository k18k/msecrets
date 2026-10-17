import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { describe, test } from "node:test";

import {
  armor,
  autoSource,
  configDirectory,
  deleteKeychain,
  encryptAge,
  formatIdentityFile,
  fromCommand,
  fromEnv,
  fromFile,
  generateIdentity,
  isMsecretsError,
  loadIdentities,
  parseSourceSpec,
  readKeychain,
  readUserConfig,
  scryptRecipient,
  splitCommandLine,
  writeKeychain,
} from "../src/index.ts";
import { tempDir } from "./helpers.ts";

const tokens = (loaded: { identity: { publicKey: { token: string } } }[]) =>
  loaded.map((entry) => entry.identity.publicKey.token);

describe("identity sources", () => {
  test("env: reads the variable and scrubs it", () => {
    const identity = generateIdentity();
    const env: NodeJS.ProcessEnv = { MSECRETS_IDENTITY: identity.secret };
    assert.deepEqual(tokens(fromEnv("MSECRETS_IDENTITY", { env }).load()), [
      identity.publicKey.token,
    ]);
    assert.equal(env["MSECRETS_IDENTITY"], undefined);
    assert.deepEqual(fromEnv("MSECRETS_IDENTITY", { env }).load(), []);

    const kept: NodeJS.ProcessEnv = { KEY: identity.secret };
    fromEnv("KEY", { env: kept, scrub: false }).load();
    assert.equal(kept["KEY"], identity.secret);
  });

  test("env: invalid content names the source", () => {
    assert.throws(
      () => fromEnv("X", { env: { X: "garbage" } }).load(),
      (error: unknown) =>
        isMsecretsError(error, "IDENTITY_SOURCE") && error.message.startsWith("env X: "),
    );
  });

  test("file: required or optional", (t) => {
    const directory = tempDir(t);
    const identity = generateIdentity();
    writeFileSync(join(directory, "key.txt"), formatIdentityFile(identity));
    assert.deepEqual(tokens(fromFile("key.txt", { cwd: directory }).load()), [
      identity.publicKey.token,
    ]);
    assert.deepEqual(fromFile("missing.txt", { cwd: directory, optional: true }).load(), []);
    assert.throws(
      () => fromFile("missing.txt", { cwd: directory }).load(),
      (error: unknown) => isMsecretsError(error, "IDENTITY_SOURCE"),
    );
  });

  test("command: password manager style output, failures, and missing tools", () => {
    const identity = generateIdentity();
    const print = fromCommand([
      process.execPath,
      "-e",
      `process.stdout.write(${JSON.stringify(`${identity.secret}\n`)})`,
    ]);
    assert.deepEqual(tokens(print.load()), [identity.publicKey.token]);
    assert.throws(() => fromCommand([process.execPath, "-e", "process.exit(3)"]).load(), /failed/);
    assert.throws(
      () => fromCommand(["msecrets-definitely-not-installed"]).load(),
      /is not installed or not on PATH/,
    );
    assert.throws(
      () => fromCommand([]),
      (error: unknown) => isMsecretsError(error, "USAGE"),
    );
  });

  test("specs map to the right sources", () => {
    assert.equal(
      parseSourceSpec("op://Private/msecrets/identity").label,
      "1Password op://Private/msecrets/identity",
    );
    assert.equal(parseSourceSpec("bw:msecrets").label, "Bitwarden msecrets");
    assert.equal(parseSourceSpec("pass:dev/msecrets").label, "pass dev/msecrets");
    assert.equal(parseSourceSpec("keychain:work").label, "OS keychain (work)");
    assert.equal(parseSourceSpec("keychain").label, "OS keychain (default)");
    assert.equal(parseSourceSpec("env:MY_KEY").label, "env MY_KEY");
    assert.equal(parseSourceSpec("file:/tmp/key").label, `file ${resolve("/tmp/key")}`);
    assert.equal(parseSourceSpec("~/key.txt").label, `file ${join(homedir(), "key.txt")}`);
    assert.equal(
      parseSourceSpec("cmd:gopass show -o msecrets").label,
      "command `gopass show -o msecrets`",
    );
    assert.throws(
      () => parseSourceSpec("vault:secret"),
      (error: unknown) => isMsecretsError(error, "USAGE"),
    );
  });

  test("command lines split on whitespace and honor quotes", () => {
    assert.deepEqual(splitCommandLine(`op read "op://My Vault/item/field"  --no-newline 'a b'`), [
      "op",
      "read",
      "op://My Vault/item/field",
      "--no-newline",
      "a b",
    ]);
  });

  test("loadIdentities removes duplicates", () => {
    const identity = generateIdentity();
    const loaded = loadIdentities([
      { label: "one", load: () => [{ identity, source: "one" }] },
      { label: "two", load: () => [{ identity, source: "two" }] },
    ]);
    assert.deepEqual(
      loaded.map((entry) => entry.source),
      ["one"],
    );
  });
});

describe("automatic identity chain", () => {
  test("runtime variables win over the developer config", (t) => {
    const directory = tempDir(t);
    const runtime = generateIdentity();
    const developer = generateIdentity();
    writeFileSync(join(directory, "identity.txt"), formatIdentityFile(developer));
    writeFileSync(
      join(directory, "config.json"),
      JSON.stringify({ identities: [`file:${join(directory, "identity.txt")}`] }),
    );

    assert.deepEqual(tokens(autoSource({ env: {}, configDirectory: directory }).load()), [
      developer.publicKey.token,
    ]);
    const env: NodeJS.ProcessEnv = { MSECRETS_IDENTITY: runtime.secret };
    assert.deepEqual(tokens(autoSource({ env, configDirectory: directory }).load()), [
      runtime.publicKey.token,
    ]);
    assert.equal(env["MSECRETS_IDENTITY"], undefined, "scrubbed");
  });

  test("MSECRETS_IDENTITY_FILE with MSECRETS_PASSPHRASE, and MSECRETS_IDENTITY_SOURCE", (t) => {
    const directory = tempDir(t);
    const identity = generateIdentity();
    const path = join(directory, "identity.age");
    writeFileSync(
      path,
      armor(encryptAge(Buffer.from(formatIdentityFile(identity)), [scryptRecipient("pw", 10)])),
    );

    const env: NodeJS.ProcessEnv = { MSECRETS_IDENTITY_FILE: path, MSECRETS_PASSPHRASE: "pw" };
    assert.deepEqual(tokens(autoSource({ env, configDirectory: directory }).load()), [
      identity.publicKey.token,
    ]);
    assert.equal(env["MSECRETS_PASSPHRASE"], undefined, "scrubbed");

    assert.throws(
      () =>
        autoSource({ env: { MSECRETS_IDENTITY_FILE: path }, configDirectory: directory }).load(),
      /set MSECRETS_PASSPHRASE/,
    );

    const viaSpec = autoSource({
      env: { MSECRETS_IDENTITY_SOURCE: `file:${path}`, MSECRETS_PASSPHRASE: "pw" },
      configDirectory: directory,
    });
    assert.deepEqual(tokens(viaSpec.load()), [identity.publicKey.token]);
  });

  test("systemd credentials", (t) => {
    const directory = tempDir(t);
    const identity = generateIdentity();
    writeFileSync(join(directory, "msecrets_identity"), identity.secret);
    assert.deepEqual(
      tokens(
        autoSource({
          env: { CREDENTIALS_DIRECTORY: directory },
          configDirectory: directory,
        }).load(),
      ),
      [identity.publicKey.token],
    );
  });

  test("falls back to the default identity file, or nothing", (t) => {
    const directory = tempDir(t);
    assert.deepEqual(autoSource({ env: {}, configDirectory: directory }).load(), []);
    const identity = generateIdentity();
    writeFileSync(join(directory, "identity.txt"), identity.secret);
    assert.deepEqual(tokens(autoSource({ env: {}, configDirectory: directory }).load()), [
      identity.publicKey.token,
    ]);
  });

  test("invalid config files are reported", (t) => {
    const directory = tempDir(t);
    assert.equal(readUserConfig(directory), null);
    writeFileSync(join(directory, "config.json"), "{");
    assert.throws(() => readUserConfig(directory), /Invalid .*config\.json/);
    writeFileSync(join(directory, "config.json"), JSON.stringify({ identities: "keychain" }));
    assert.throws(() => readUserConfig(directory), /must be an array/);
  });

  test("config directory per platform", () => {
    assert.equal(configDirectory({ MSECRETS_CONFIG_DIR: "/x" }, "linux"), "/x");
    assert.equal(configDirectory({ XDG_CONFIG_HOME: "/xdg" }, "linux"), join("/xdg", "msecrets"));
    assert.equal(
      configDirectory({ APPDATA: "C:\\Users\\me\\AppData\\Roaming" }, "win32"),
      join("C:\\Users\\me\\AppData\\Roaming", "msecrets"),
    );
    assert.equal(configDirectory({}, "darwin"), join(homedir(), ".config", "msecrets"));
  });
});

describe("OS keychain", () => {
  test("validates input before running anything", () => {
    assert.throws(
      () => readKeychain("Bad Account"),
      (error: unknown) => isMsecretsError(error, "USAGE"),
    );
    assert.throws(() => writeKeychain("default", "two\nlines"), /single-line/);
    assert.throws(
      () => readKeychain("default", "aix"),
      (error: unknown) => isMsecretsError(error, "UNSUPPORTED"),
    );
  });

  test(
    "round-trips through the real OS keychain",
    { skip: process.env["MSECRETS_TEST_KEYCHAIN"] ? false : "set MSECRETS_TEST_KEYCHAIN=1 to run" },
    () => {
      const account = `msecrets-test-${process.pid}`;
      const identity = generateIdentity();
      try {
        assert.equal(readKeychain(account), null);
        writeKeychain(account, identity.secret);
        assert.equal(readKeychain(account), identity.secret);
        assert.deepEqual(tokens(parseSourceSpec(`keychain:${account}`).load()), [
          identity.publicKey.token,
        ]);
        const replacement = generateIdentity();
        writeKeychain(account, replacement.secret);
        assert.equal(readKeychain(account), replacement.secret);
      } finally {
        deleteKeychain(account);
      }
      assert.equal(readKeychain(account), null);
    },
  );
});
