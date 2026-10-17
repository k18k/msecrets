import assert from "node:assert/strict";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import { tempDir } from "../../core/test/helpers.ts";
import { interactive, workspace } from "./harness.ts";

const ok = (result: { code: number; stderr: string }) =>
  assert.equal(result.code, 0, result.stderr);

describe("terminal prompts", () => {
  test("set prompts for a hidden value that never appears on screen", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));

    const result = await interactive(
      alice,
      ws.project,
      ["set", "API_KEY", "--all"],
      [[/Value for API_KEY \(development, production\): $/, "s3cr3t-value\r"]],
    );
    ok(result);
    assert.equal(result.unanswered, 0);
    assert.ok(!result.stderr.includes("s3cr3t-value"));
    assert.equal(
      (await alice.run(["get", "API_KEY", "--env", "production"])).stdout,
      "s3cr3t-value",
    );
  });

  test("backspace edits hidden input; ctrl-c cancels with exit code 130", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(
      await interactive(alice, ws.project, ["set", "X"], [[/Value for X/, "abcd\u007f\u007fzz\r"]]),
    );
    assert.equal((await alice.run(["get", "X"])).stdout, "abzz");
    assert.equal(
      (await interactive(alice, ws.project, ["set", "Y"], [[/Value for Y/, "abc\u0003"]])).code,
      130,
    );
  });

  test("dangerous commands ask for confirmation on a terminal", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(await alice.run(["set", "X", "1"]));

    const declined = await interactive(
      alice,
      ws.project,
      ["rm", "X"],
      [[/Delete X from every environment\? \[y\/N\] $/, "n\n"]],
    );
    assert.equal(declined.code, 2);
    assert.match(declined.stderr, /Aborted/);
    ok(await interactive(alice, ws.project, ["rm", "X"], [[/\[y\/N\]/, "y\n"]]));
    assert.equal((await alice.run(["get", "X"])).code, 1);
  });

  test("a passphrase-protected identity file is created and unlocked interactively", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    const mismatch = await interactive(
      alice,
      ws.project,
      ["init", "--store", "file", "--passphrase", "--name", "alice"],
      [
        [/New passphrase for the identity file: $/, "correct horse\r"],
        [/Repeat the passphrase: $/, "wrong\r"],
      ],
    );
    assert.equal(mismatch.code, 2);
    assert.match(mismatch.stderr, /do not match/);

    ok(
      await interactive(
        alice,
        ws.project,
        ["init", "--store", "file", "--passphrase", "--name", "alice"],
        [
          [/New passphrase/, "correct horse\r"],
          [/Repeat the passphrase/, "correct horse\r"],
        ],
      ),
    );
    assert.match(
      readFileSync(join(alice.config, "identity.txt"), "utf8"),
      /^-----BEGIN AGE ENCRYPTED FILE-----/,
    );

    const unlocked = await interactive(
      alice,
      ws.project,
      ["set", "X", "1"],
      [[/Passphrase for file .*identity\.txt: $/, "correct horse\r"]],
    );
    ok(unlocked);
    assert.equal(
      (await alice.run(["get", "X"], { env: { MSECRETS_PASSPHRASE: "correct horse" } })).stdout,
      "1",
    );

    const headless = await alice.run(["get", "X"]);
    assert.equal(headless.code, 1);
    assert.match(headless.stderr, /passphrase-protected; set MSECRETS_PASSPHRASE/);
  });

  test("passphrase-protected SSH keys work as identities", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    const key = join(
      import.meta.dirname,
      "..",
      "..",
      "core",
      "test",
      "fixtures",
      "ssh",
      "encrypted-ctr",
    );
    const publicKey = readFileSync(`${key}.pub`, "utf8").trim();
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(await alice.run(["recipient", "add", "ssh-user", publicKey, "--env", "development"]));
    ok(await alice.run(["set", "X", "for-ssh"]));

    const result = await interactive(
      alice,
      ws.project,
      ["get", "X", "--identity", `file:${key}`],
      [[/Passphrase for file .*encrypted-ctr: $/, "correct horse\r"]],
    );
    ok(result);
    assert.equal(result.stdout, "for-ssh");
  });

  test("exporting an identity to a terminal asks first", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["identity", "new", "--store", "file"]));
    const declined = await interactive(
      alice,
      ws.project,
      ["identity", "export"],
      [[/prints your private key on the screen\. Continue\? \[y\/N\] $/, "n\n"]],
      {},
      { stdoutIsTerminal: true },
    );
    assert.equal(declined.code, 2);
    assert.equal(declined.stdout, "");

    const redirected = await interactive(alice, ws.project, ["identity", "export"], []);
    ok(redirected);
    assert.match(redirected.stdout, /^AGE-SECRET-KEY-1/m);
  });
});

/** Stand-ins for `secret-tool` and `security` that keep entries in a JSON file. */
function fakeKeychainTools(directory: string): void {
  const store = JSON.stringify(join(directory, "store.json"));
  const prelude = `#!/usr/bin/env node
const fs = require("fs");
const file = ${store};
const load = () => (fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : {});
const save = (data) => fs.writeFileSync(file, JSON.stringify(data));
const args = process.argv.slice(2);
const after = (flag) => args[args.indexOf(flag) + 1];
`;
  writeFileSync(
    join(directory, "secret-tool"),
    `${prelude}
const account = after("account");
const data = load();
if (args[0] === "lookup") { if (!(account in data)) process.exit(1); process.stdout.write(data[account]); }
else if (args[0] === "store") { data[account] = fs.readFileSync(0, "utf8"); save(data); }
else if (args[0] === "clear") { delete data[account]; save(data); }
`,
  );
  writeFileSync(
    join(directory, "security"),
    `${prelude}
const data = load();
if (args[0] === "-i") {
  const line = fs.readFileSync(0, "utf8").trim().split(" ");
  data[line[line.indexOf("-a") + 1]] = line[line.indexOf("-w") + 1];
  save(data);
} else {
  const account = after("-a");
  if (!(account in data)) process.exit(44);
  if (args[0] === "find-generic-password") process.stdout.write(data[account] + "\\n");
  if (args[0] === "delete-generic-password") { delete data[account]; save(data); }
}
`,
  );
  chmodSync(join(directory, "secret-tool"), 0o755);
  chmodSync(join(directory, "security"), 0o755);
}

describe(
  "OS keychain storage",
  { skip: process.platform === "win32" ? "POSIX stand-ins only" : false },
  () => {
    test("init stores the identity in the keychain and later commands read it from there", async (t) => {
      const tools = tempDir(t);
      mkdirSync(tools, { recursive: true });
      fakeKeychainTools(tools);
      const path = `${tools}:${process.env["PATH"] ?? ""}`;
      const previous = process.env["PATH"];
      process.env["PATH"] = path;
      t.after(() => {
        process.env["PATH"] = previous;
      });

      const ws = workspace(t);
      const alice = ws.person("alice");
      const init = await alice.run(["init", "--name", "alice"], { env: { PATH: path } });
      ok(init);
      assert.match(init.stderr, /Created your identity \(OS keychain\)/);
      assert.deepEqual(JSON.parse(readFileSync(join(alice.config, "config.json"), "utf8")), {
        identities: ["keychain:default"],
      });
      assert.match(readFileSync(join(tools, "store.json"), "utf8"), /AGE-SECRET-KEY-1/);

      ok(await alice.run(["set", "X", "from-keychain"], { env: { PATH: path } }));
      assert.equal(
        (await alice.run(["get", "X"], { env: { PATH: path } })).stdout,
        "from-keychain",
      );
      const whoami = await alice.run(["whoami"], { env: { PATH: path } });
      assert.match(whoami.stdout, /from OS keychain \(default\)/);
    });

    test("without a working keychain, init falls back to a private file", async (t) => {
      const ws = workspace(t);
      const alice = ws.person("alice");
      const init = await alice.run(["init", "--name", "alice"], { env: { PATH: tempDir(t) } });
      ok(init);
      assert.match(init.stderr, /OS keychain unavailable/);
      const identityFile = join(alice.config, "identity.txt");
      assert.match(readFileSync(identityFile, "utf8"), /AGE-SECRET-KEY-1/);
      if (process.platform !== "win32") {
        const { statSync } = await import("node:fs");
        assert.equal(statSync(identityFile).mode & 0o777, 0o600);
      }
    });
  },
);
