import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import { parseDocumentText } from "../../core/src/index.ts";
import { parseDotenv } from "../src/formats.ts";
import { identityFrom, workspace } from "./harness.ts";

const ok = (result: { code: number; stderr: string }) =>
  assert.equal(result.code, 0, result.stderr);

describe("team workflow", () => {
  test("init, set, get, ls, check", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");

    const init = await alice.run(["init", "--store", "file", "--name", "alice"]);
    ok(init);
    assert.match(
      init.stderr,
      /Created \.env\.ms\.json \(development, production\); you are recipient "alice"/,
    );
    assert.match(readFileSync(join(alice.config, "config.json"), "utf8"), /"file:.*identity\.txt"/);
    assert.equal((await alice.run(["init", "--store", "file"])).code, 1);

    ok(await alice.run(["set", "DATABASE_URL", "postgres://dev"]));
    ok(
      await alice.run(["set", "DATABASE_URL", "--env", "production"], {
        input: "postgres://prod\n",
      }),
    );
    ok(await alice.run(["set", "API_KEY", "key-1", "--all", "-d", "Payments"]));

    assert.equal((await alice.run(["get", "DATABASE_URL"])).stdout, "postgres://dev");
    assert.equal(
      (await alice.run(["get", "DATABASE_URL", "-e", "production"])).stdout,
      "postgres://prod",
    );
    assert.equal(
      (await alice.run(["get", "DATABASE_URL"], { env: { MSECRETS_ENV: "production" } })).stdout,
      "postgres://prod",
    );

    const ls = await alice.run(["ls"]);
    ok(ls);
    assert.match(ls.stdout, /API_KEY\s+●\s+●\s+Payments/);
    ok(await alice.run(["check"]));

    ok(await alice.run(["env", "add", "staging"]));
    const failing = await alice.run(["check"]);
    assert.equal(failing.code, 1);
    assert.match(failing.stdout, /DATABASE_URL has no value in "staging"/);

    const json = JSON.parse((await alice.run(["ls", "--json"])).stdout) as {
      ok: boolean;
      secrets: Record<string, { values: Record<string, string> }>;
    };
    assert.equal(json.ok, false);
    assert.equal(json.secrets["API_KEY"]?.values["staging"], "missing");
  });

  test("a teammate joins, a member syncs, a machine reads production, access is revoked", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    const bob = ws.person("bob");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(await alice.run(["set", "DATABASE_URL", "dev-url"]));
    ok(await alice.run(["set", "DATABASE_URL", "prod-url", "--env", "production"]));

    // bob joins with access to development; he cannot re-encrypt anything yet.
    const joined = await bob.run([
      "join",
      "--store",
      "file",
      "--name",
      "bob",
      "--env",
      "development",
    ]);
    ok(joined);
    assert.match(joined.stderr, /a member runs `msecrets sync`/);
    const stale = await bob.run(["get", "DATABASE_URL"]);
    assert.equal(stale.code, 1);
    assert.match(stale.stderr, /out of date for you; ask a member to run `msecrets sync`/);
    assert.equal((await alice.run(["check"])).code, 1);

    const synced = await alice.run(["sync"]);
    ok(synced);
    assert.match(synced.stderr, /Re-encrypted 1 value/);
    assert.equal((await bob.run(["get", "DATABASE_URL"])).stdout, "dev-url");
    assert.equal((await bob.run(["get", "DATABASE_URL", "--env", "production"])).code, 1);

    // A machine identity for production, handed to the runtime through MSECRETS_IDENTITY.
    const machine = await alice.run([
      "recipient",
      "add",
      "deploy",
      "--generate",
      "--env",
      "production",
      "-d",
      "CI deploys",
    ]);
    ok(machine);
    const identity = identityFrom(machine.stdout);
    assert.match(identity, /^AGE-SECRET-KEY-1/);
    const runtime = ws.person("runtime");
    const exported = await runtime.run(["export", "--format", "json", "--env", "production"], {
      env: { MSECRETS_IDENTITY: identity },
    });
    ok(exported);
    assert.deepEqual(JSON.parse(exported.stdout), { DATABASE_URL: "prod-url" });

    const whoami = await bob.run(["whoami"]);
    assert.match(whoami.stdout, /recipient bob: development \(read\/write\)/);
    const recipients = await alice.run(["recipient", "ls"]);
    assert.match(recipients.stdout, /alice \(you\)/);
    assert.match(recipients.stdout, /deploy\s+x25519 read-only\s+production\s+CI deploys/);

    // bob cannot revoke the machine: he cannot re-encrypt production.
    const refused = await bob.run(["revoke", "deploy", "production"]);
    assert.equal(refused.code, 1);
    assert.match(refused.stderr, /requires re-encrypting values you cannot decrypt/);

    const revoked = await alice.run(["revoke", "bob", "development"]);
    ok(revoked);
    assert.match(revoked.stderr, /could read these values and may have kept copies/);
    assert.equal((await bob.run(["get", "DATABASE_URL"])).code, 1);
    ok(await alice.run(["check"]));

    ok(await alice.run(["recipient", "rm", "bob", "--yes"]));
    assert.equal(
      parseDocumentText(readFileSync(join(ws.project, ".env.ms.json"), "utf8")).recipients["bob"],
      undefined,
    );
  });

  test("rename, describe, scope, unset, rm, env and recipient management", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(
      await alice.run([
        "init",
        "--store",
        "file",
        "--name",
        "alice",
        "--env",
        "development,production",
      ]),
    );
    ok(await alice.run(["set", "A", "1", "--all"]));
    ok(await alice.run(["set", "SENTRY", "dsn", "--env", "production"]));

    ok(await alice.run(["mv", "A", "B"]));
    assert.equal((await alice.run(["get", "B"])).stdout, "1");
    ok(await alice.run(["describe", "B", "The", "B", "value"]));
    ok(await alice.run(["scope", "SENTRY", "production"]));
    ok(await alice.run(["check"]));

    assert.equal(
      (await alice.run(["scope", "B", "production"])).code,
      2,
      "needs --yes without a terminal",
    );
    ok(await alice.run(["scope", "B", "production", "--yes"]));
    ok(await alice.run(["unset", "B", "--env", "production"]));
    assert.equal((await alice.run(["check"])).code, 1);
    assert.equal((await alice.run(["rm", "B"])).code, 2);
    ok(await alice.run(["rm", "B", "--yes"]));

    ok(await alice.run(["env", "mv", "production", "prod"]));
    assert.equal((await alice.run(["get", "SENTRY", "--env", "prod"])).stdout, "dsn");
    const environments = await alice.run(["env", "ls"]);
    assert.match(environments.stdout, /prod\s+1\/1\s+alice/);
    ok(await alice.run(["env", "rm", "prod", "--yes"]));
    ok(await alice.run(["recipient", "mv", "alice", "alice.smith"]));
    ok(await alice.run(["check"]));

    const document = parseDocumentText(readFileSync(join(ws.project, ".env.ms.json"), "utf8"));
    assert.deepEqual(Object.keys(document.environments), ["development"]);
    assert.deepEqual(Object.keys(document.secrets), []);
    assert.deepEqual(Object.keys(document.recipients), ["alice.smith"]);
  });
});

describe("more access management", () => {
  test("rotate a machine key, copy recipients for a new environment, describe and list", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(await alice.run(["set", "TOKEN", "t", "--all"]));
    const first = identityFrom(
      (await alice.run(["recipient", "add", "ci", "--generate", "--env", "production"])).stdout,
    );
    const rotated = await alice.run(["recipient", "rotate", "ci", "--generate"]);
    ok(rotated);
    assert.match(rotated.stderr, /Rotated the key of "ci" \(1 value\(s\) re-encrypted\)/);
    const second = identityFrom(rotated.stdout);
    assert.notEqual(first, second);
    const runtime = ws.person("runtime");
    assert.equal(
      (
        await runtime.run(["get", "TOKEN", "--env", "production"], {
          env: { MSECRETS_IDENTITY: first },
        })
      ).code,
      1,
    );
    assert.equal(
      (
        await runtime.run(["get", "TOKEN", "--env", "production"], {
          env: { MSECRETS_IDENTITY: second },
        })
      ).stdout,
      "t",
    );
    assert.equal(
      (
        await runtime.run(["set", "TOKEN", "x", "--env", "production"], {
          env: { MSECRETS_IDENTITY: second },
        })
      ).code,
      1,
      "machine keys are read-only",
    );

    ok(await alice.run(["env", "add", "staging", "--from", "production"]));
    const environments = await alice.run(["env", "ls"]);
    assert.match(environments.stdout, /staging\s+0\/1\s+alice, ci/);
    ok(await alice.run(["describe", "TOKEN", "API", "token"]));
    ok(await alice.run(["describe", "TOKEN"]));
    const synced = await alice.run(["sync"]);
    ok(synced);
    assert.match(synced.stderr, /Everything is up to date/);
  });

  test("whoami for someone who is not a recipient, and adding people by key", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    const bob = ws.person("bob");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(await bob.run(["identity", "new", "--store", "file"]));
    assert.match((await bob.run(["whoami"])).stdout, /not a recipient of this file/);

    const bobKey = (await bob.run(["identity", "show"])).stdout.trim();
    ok(
      await alice.run(["recipient", "add", "bob", bobKey, "--env", "development", "-d", "Backend"]),
    );
    assert.match((await bob.run(["whoami"])).stdout, /recipient bob: development \(read\/write\)/);
    assert.equal((await alice.run(["recipient", "add", "bob2", bobKey])).code, 1);
    assert.equal((await alice.run(["recipient", "add", "x"])).code, 2);
  });
});

describe("runtime commands", () => {
  test("run injects secrets, hides the identity, and passes the exit code", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice", "--env", "development"]));
    ok(await alice.run(["set", "GREETING", "hello world"]));
    ok(await alice.run(["set", "PRESET", "from-file"]));

    const output = join(ws.root, "child.json");
    const script = `require("fs").writeFileSync(${JSON.stringify(output)}, JSON.stringify({ g: process.env.GREETING, p: process.env.PRESET, i: process.env.MSECRETS_IDENTITY ?? null })); process.exit(7)`;
    const identity = readFileSync(join(alice.config, "identity.txt"), "utf8");

    const result = await alice.run(["run", "--", process.execPath, "-e", script], {
      env: { PRESET: "explicit", MSECRETS_IDENTITY: identity },
    });
    assert.equal(result.code, 7);
    assert.deepEqual(JSON.parse(readFileSync(output, "utf8")), {
      g: "hello world",
      p: "explicit",
      i: null,
    });

    assert.equal(
      (
        await alice.run(["run", "--override", process.execPath, "-e", script], {
          env: { PRESET: "explicit" },
        })
      ).code,
      7,
    );
    assert.equal((JSON.parse(readFileSync(output, "utf8")) as { p: string }).p, "from-file");

    assert.equal((await alice.run(["run"])).code, 2);
    assert.equal((await alice.run(["run", "--", "msecrets-no-such-command"])).code, 2);
  });

  test("run refuses an incomplete environment", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice"]));
    ok(await alice.run(["set", "ONLY_DEV", "x"]));
    const result = await alice.run([
      "run",
      "--env",
      "production",
      "--",
      process.execPath,
      "-e",
      "0",
    ]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /incomplete; these secrets have no value: ONLY_DEV/);
  });

  test("import and export dotenv round-trip", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["init", "--store", "file", "--name", "alice", "--env", "development"]));
    const dotenv = [
      "# comment",
      "PLAIN=value",
      'export QUOTED="two words"',
      'MULTI="line1\\nline2"',
      "SINGLE='$NOT_EXPANDED'",
      "EMPTY=",
      "",
    ].join("\n");
    writeFileSync(join(ws.project, ".env"), dotenv);

    const imported = await alice.run(["import", ".env"]);
    ok(imported);
    assert.match(imported.stderr, /Imported 5 secret/);
    assert.match(
      (await alice.run(["import", "-"], { input: "PLAIN=changed\n" })).stderr,
      /Kept existing values/,
    );

    const exported = await alice.run(["export"]);
    ok(exported);
    assert.deepEqual(Object.fromEntries(parseDotenv(exported.stdout)), {
      EMPTY: "",
      MULTI: "line1\nline2",
      PLAIN: "value",
      QUOTED: "two words",
      SINGLE: "$NOT_EXPANDED",
    });
    assert.match(
      (await alice.run(["export", "--format", "shell"])).stdout,
      /^export MULTI='line1\nline2'$/m,
    );
    assert.match(
      (await alice.run(["export", "--format", "powershell"])).stdout,
      /^\$env:SINGLE = '\$NOT_EXPANDED'$/m,
    );
    assert.equal((await alice.run(["export", "--format", "xml"])).code, 2);
  });
});

describe("identities", () => {
  test("identity new / show / use / export", async (t) => {
    const ws = workspace(t);
    const carol = ws.person("carol");
    const printed = await carol.run(["identity", "new", "--store", "print"]);
    ok(printed);
    const secret = identityFrom(printed.stdout);
    assert.match(printed.stderr, /Public key: msecrets1/);

    writeFileSync(join(ws.root, "carol.key"), `${secret}\n`);
    const used = await carol.run(["identity", "use", `file:${join(ws.root, "carol.key")}`]);
    ok(used);
    const shown = await carol.run(["identity", "show"]);
    assert.equal(shown.stdout.trim(), used.stdout.trim());
    assert.equal(identityFrom((await carol.run(["identity", "export"])).stdout), secret);

    assert.equal((await carol.run(["identity", "use", "env:NOT_SET"])).code, 1);
    const viaFlag = await ws.person("dave").run(["identity", "show", "--identity", secret]);
    assert.equal(viaFlag.stdout.trim(), shown.stdout.trim());
  });

  test("no identity: helpful errors", async (t) => {
    const ws = workspace(t);
    const nobody = ws.person("nobody");
    assert.match((await nobody.run(["identity", "show"])).stderr, /No msecrets identity found/);
    assert.equal((await nobody.run(["whoami"])).code, 1);
  });
});

describe("usage", () => {
  test("help, version, unknown commands and options", async (t) => {
    const user = workspace(t).person("x");
    const help = await user.run(["--help"]);
    ok(help);
    assert.match(help.stdout, /Get started:[\s\S]*init[\s\S]*CI and git:/);
    assert.match(
      (await user.run(["set", "--help"])).stdout,
      /Usage: msecrets set <NAME> \[VALUE\]/,
    );
    assert.match((await user.run(["help", "env", "add"])).stdout, /Usage: msecrets env add <NAME>/);
    assert.match((await user.run(["--version"])).stdout, /^4\.\d+\.\d+/);
    assert.equal((await user.run([])).code, 0, "no terminal: prints help");

    const unknown = await user.run(["lst"]);
    assert.equal(unknown.code, 2);
    assert.match(unknown.stderr, /did you mean "ls"/);
    assert.match((await user.run(["env", "nope"])).stderr, /try: env ls, env add, env rm, env mv/);
    assert.match((await user.run(["ls", "--nope"])).stderr, /Unknown option '--nope'/);
    assert.equal((await user.run(["get"])).code, 2);
    const missing = await user.run(["ls"]);
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /No \.env\.ms\.json found/);
    assert.equal((await user.run(["tui"])).code, 2);
  });

  test("global options before the command", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    ok(await alice.run(["-f", "other.ms.json", "init", "--store", "file", "--name", "alice"]));
    ok(await alice.run(["-f", "other.ms.json", "set", "X", "1"]));
    assert.equal((await alice.run(["--file", "other.ms.json", "get", "X"])).stdout, "1");
  });
});
