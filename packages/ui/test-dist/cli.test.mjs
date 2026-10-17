// Runs the built CLI (dist/bin.mjs) as a real process on every supported Node.js version.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const bin = join(here, "..", "dist", "bin.mjs");
const version = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")).version;
const hasGit = spawnSync("git", ["--version"]).status === 0;

function sandbox(t) {
  const root = mkdtempSync(join(tmpdir(), "msecrets-dist-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const env = { ...process.env, NO_COLOR: "1", MSECRETS_CONFIG_DIR: join(root, "config") };
  delete env.MSECRETS_IDENTITY;
  delete env.MSECRETS_FILE;
  delete env.MSECRETS_ENV;
  const run = (args, options = {}) => {
    const result = spawnSync(process.execPath, [bin, ...args], {
      cwd: options.cwd ?? root,
      env: { ...env, ...options.env },
      input: options.input ?? "",
      encoding: "utf8",
    });
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  const ok = (args, options) => {
    const result = run(args, options);
    assert.equal(result.code, 0, `msecrets ${args.join(" ")}\n${result.stderr}`);
    return result;
  };
  const git = (args) => {
    const result = spawnSync(
      "git",
      ["-c", "user.name=Test", "-c", "user.email=test@example.com", ...args],
      {
        cwd: root,
        encoding: "utf8",
      },
    );
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  return { root, run, ok, git };
}

test("version, help, and errors", (t) => {
  const { run, ok } = sandbox(t);
  assert.equal(ok(["--version"]).stdout.trim(), version);
  assert.match(ok([]).stdout, /msecrets <command>/);
  assert.equal(run(["nope"]).code, 2);
  assert.match(run(["ls"]).stderr, /No msecrets\.json found/);
});

test("init, set, get, check, run, export", (t) => {
  const { root, run, ok } = sandbox(t);
  ok(["init", "--store", "file", "--name", "alice"]);
  ok(["set", "DATABASE_URL", "--all"], { input: "postgres://x\n" });
  ok(["set", "TOKEN", "t0k3n", "--all"]);
  assert.equal(ok(["get", "DATABASE_URL", "--env", "production"]).stdout, "postgres://x");
  assert.match(ok(["check"]).stdout, /every value is present, current, and signed/);

  const result = ok([
    "run",
    "--env",
    "production",
    "--",
    process.execPath,
    "-e",
    "process.stdout.write(process.env.TOKEN)",
  ]);
  assert.equal(result.stdout, "t0k3n");
  assert.equal(run(["run", "--", process.execPath, "-e", "process.exit(9)"]).code, 9);
  assert.deepEqual(JSON.parse(ok(["export", "--format", "json"]).stdout), {
    DATABASE_URL: "postgres://x",
    TOKEN: "t0k3n",
  });

  const document = JSON.parse(readFileSync(join(root, "msecrets.json"), "utf8"));
  assert.equal(document.version, 4);
});

test("machine identity for a container", (t) => {
  const { ok } = sandbox(t);
  ok(["init", "--store", "file", "--name", "alice"]);
  ok(["set", "API", "secret", "--all"]);
  const identity = ok([
    "recipient",
    "add",
    "container",
    "--generate",
    "--env",
    "production",
  ]).stdout;
  const runtime = {
    MSECRETS_IDENTITY: identity,
    MSECRETS_CONFIG_DIR: join(tmpdir(), "msecrets-none-" + process.pid),
  };
  assert.equal(ok(["get", "API", "--env", "production"], { env: runtime }).stdout, "secret");
});

test(
  "post-quantum identities",
  { skip: typeof crypto.encapsulate === "function" ? false : "ML-KEM unsupported on this Node.js" },
  (t) => {
    const { ok } = sandbox(t);
    ok(["init", "--store", "file", "--name", "quantum", "--pq"]);
    ok(["set", "KEY", "pq-safe", "--all"]);
    assert.equal(ok(["get", "KEY"]).stdout, "pq-safe");
    assert.match(ok(["recipient", "ls"]).stdout, /quantum \(you\)\s+mlkem768x25519/);
  },
);

test(
  "git: readable diffs and structural merges",
  { skip: hasGit ? false : "git not installed" },
  (t) => {
    const { root, ok, git } = sandbox(t);
    assert.equal(git(["-c", "init.defaultBranch=main", "init", "-q"]).code, 0);
    ok(["init", "--store", "file", "--name", "alice", "--env", "development"]);
    ok(["set", "A", "1"]);
    ok(["git", "setup"]);
    assert.match(
      readFileSync(join(root, ".gitattributes"), "utf8"),
      /^msecrets\.json diff=msecrets merge=msecrets$/m,
    );
    git(["add", "."]);
    assert.equal(git(["commit", "-qm", "init"]).code, 0);

    ok(["set", "A", "2"]);
    const diff = git(["diff"]).stdout;
    assert.match(diff, /^-    development: signed by alice [0-9a-f]{12}$/m);
    assert.match(diff, /^\+    development: signed by alice [0-9a-f]{12}$/m);
    assert.ok(!diff.includes("YWdl"), "no ciphertext in the diff");
    git(["checkout", "--", "msecrets.json"]);

    git(["checkout", "-qb", "feature"]);
    ok(["set", "B", "feature"]);
    git(["commit", "-qam", "feature"]);
    git(["checkout", "-q", "main"]);
    ok(["set", "C", "main"]);
    git(["commit", "-qam", "main"]);

    const merge = git(["merge", "-q", "--no-edit", "feature"]);
    assert.equal(merge.code, 0, merge.stderr + merge.stdout);
    assert.equal(ok(["get", "B"]).stdout, "feature");
    assert.equal(ok(["get", "C"]).stdout, "main");
    ok(["check"]);

    git(["checkout", "-qb", "conflict"]);
    ok(["set", "A", "theirs"]);
    git(["commit", "-qam", "theirs"]);
    git(["checkout", "-q", "main"]);
    ok(["set", "A", "ours"]);
    git(["commit", "-qam", "ours"]);
    const conflicted = git(["merge", "-q", "--no-edit", "conflict"]);
    assert.notEqual(conflicted.code, 0);
    assert.match(conflicted.stdout + conflicted.stderr, /secrets\.A\.values\.development/);
    assert.equal(ok(["get", "A"]).stdout, "ours", "the file stays valid with our side");
  },
);
