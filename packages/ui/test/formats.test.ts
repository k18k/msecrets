import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import { formatDotenv, formatPowerShell, formatShell, parseDotenv } from "../src/formats.ts";
import { planSpawn, runToCompletion, spawnCommand } from "../src/spawn.ts";
import { tempDir } from "../../core/test/helpers.ts";

describe("dotenv", () => {
  test("parses the common dialect", () => {
    const parsed = parseDotenv(
      [
        "# comment",
        "  A=1",
        "export B = spaced value   # trailing comment",
        'C="escaped \\" quote\\tand tab"',
        "D='literal \\n stays'",
        "E=`backtick`",
        'F="multi',
        'line"',
        "G=",
        "H=a#b",
        "",
      ].join("\r\n"),
    );
    assert.deepEqual(Object.fromEntries(parsed), {
      A: "1",
      B: "spaced value",
      C: 'escaped " quote\tand tab',
      D: "literal \\n stays",
      E: "backtick",
      F: "multi\nline",
      G: "",
      H: "a#b",
    });
  });

  test("reports malformed lines with their number", () => {
    assert.throws(() => parseDotenv("A=1\nnot a pair\n"), /dotenv line 2: expected KEY=value/);
    assert.throws(() => parseDotenv('A="open\n'), /unterminated " quote for A/);
    assert.throws(
      () => parseDotenv('A="x" trailing\n'),
      /unexpected characters after the closing quote of A/,
    );
  });

  test("format and parse round-trip any value", () => {
    const values = {
      PLAIN: "abc-123_./:@%+,=",
      SPACES: "a b",
      QUOTES: `it's "quoted"`,
      NEWLINES: "one\ntwo\r\nthree",
      BACKSLASH: "C:\\path\\n",
      HASH: "a #b",
      EMPTY: "",
      UNICODE: "zażółć 🔐",
    };
    assert.deepEqual(Object.fromEntries(parseDotenv(formatDotenv(values))), values);
  });

  test("shell and PowerShell quoting", () => {
    assert.equal(formatShell({ A: "it's $HOME" }), "export A='it'\\''s $HOME'\n");
    assert.equal(formatPowerShell({ A: "it's $env:HOME" }), "$env:A = 'it''s $env:HOME'\n");
  });
});

describe("spawning on Windows", () => {
  test("executables run directly, without a shell", () => {
    assert.deepEqual(planSpawn(["node", "-e", "1"], { env: {}, cwd: "/", platform: "linux" }), {
      file: "node",
      args: ["-e", "1"],
      verbatim: false,
    });
    assert.deepEqual(
      planSpawn(["C:\\x\\tool.exe", "a b"], { env: {}, cwd: "C:\\", platform: "win32" }),
      {
        file: "C:\\x\\tool.exe",
        args: ["a b"],
        verbatim: false,
      },
    );
  });

  test(".cmd shims go through cmd.exe with every argument escaped", () => {
    const plan = planSpawn(["C:\\npm\\npm.cmd", "run", "a&b", 'say "hi"', "100%"], {
      env: { ComSpec: "C:\\Windows\\cmd.exe" },
      cwd: "C:\\",
      platform: "win32",
    });
    assert.equal(plan.file, "C:\\Windows\\cmd.exe");
    assert.equal(plan.verbatim, true);
    assert.deepEqual(plan.args.slice(0, 3), ["/d", "/s", "/c"]);
    const line = plan.args[3] ?? "";
    assert.ok(line.includes('^^^"a^^^&b^^^"'), line);
    assert.ok(line.includes('^^^"say^^^ \\^^^"hi\\^^^"^^^"'), line);
    assert.ok(line.includes("100^^^%"), line);
    assert.ok(!/[^^]&/.test(line), "no unescaped metacharacters");
  });

  test(
    "arguments survive cmd.exe and a real .cmd shim unchanged",
    { skip: process.platform === "win32" ? false : "Windows only" },
    async (t) => {
      const directory = tempDir(t);
      const output = join(directory, "args.json");
      const shim = join(directory, "echo-args.cmd");
      writeFileSync(
        shim,
        `@"${process.execPath}" -e "require('fs').writeFileSync(process.argv[1], JSON.stringify(process.argv.slice(2)))" "${output}" %*\r\n`,
      );
      const tricky = [
        "plain",
        "two words",
        'quote " inside',
        "amp & pipe | caret ^",
        "percent %PATH%",
        "trailing backslash\\",
        "(parens) <angle> !bang!",
      ];
      const child = spawnCommand([shim, ...tricky], { env: process.env, cwd: directory });
      assert.equal(await runToCompletion(child, false), 0);
      assert.deepEqual(JSON.parse(readFileSync(output, "utf8")), tricky);
    },
  );

  test("an empty command is a usage error", () => {
    assert.throws(() => planSpawn([], { env: {}, cwd: "/" }), /No command given/);
  });
});
