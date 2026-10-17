import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";

import * as sdk from "../../ts-sdk/src/index.ts";
import { COMMANDS } from "../src/commands.ts";
import { workspace } from "./harness.ts";

const UI = join(import.meta.dirname, "..");
const SKILL = readFileSync(join(UI, "skills", "msecrets", "SKILL.md"), "utf8");
const INSTALLED = [".claude/skills/msecrets/SKILL.md", ".agents/skills/msecrets/SKILL.md"];

const ok = (result: { code: number; stderr: string }) =>
  assert.equal(result.code, 0, result.stderr);

describe("agent skill", () => {
  test("follows the Agent Skills format", () => {
    const frontmatter = /^---\n([\s\S]*?)\n---\n/.exec(SKILL)?.[1] ?? "";
    const fields = Object.fromEntries(
      frontmatter
        .split("\n")
        .map((line) => [
          line.slice(0, line.indexOf(":")),
          line.slice(line.indexOf(":") + 1).trim(),
        ]),
    );
    assert.deepEqual(Object.keys(fields), ["name", "description"]);
    assert.equal(fields["name"], "msecrets", "the name must match the directory");
    const description = fields["description"] ?? "";
    assert.ok(description.length > 100 && description.length <= 1024, "description length");
    assert.doesNotMatch(description, /[<>]/);
  });

  test("mentions only real commands, SDK exports, and error codes", () => {
    const names = new Set(COMMANDS.map((command) => command.name));
    const used = [...SKILL.matchAll(/npx msecrets ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?/g)];
    assert.ok(used.length > 20);
    for (const [usage, first = "", second] of used) {
      assert.ok(
        names.has(`${first} ${second}`) || names.has(first),
        `SKILL.md uses \`${usage}\`, which is not a command`,
      );
    }

    const imports = [...SKILL.matchAll(/import \{ ([A-Za-z, ]+) \} from "@msecrets\/ts-sdk"/g)];
    for (const exported of imports.flatMap((match) => (match[1] ?? "").split(", "))) {
      assert.equal(typeof sdk[exported as keyof typeof sdk], "function", exported);
    }

    const codes = [...SKILL.matchAll(/^\| `([A-Z_]+)` /gm)].map((match) => match[1] ?? "");
    assert.deepEqual(codes, [
      "NOT_FOUND",
      "IDENTITY_SOURCE",
      "ACCESS_DENIED",
      "SIGNATURE",
      "INVALID_FILE",
    ]);
    const errors = readFileSync(join(UI, "..", "core", "src", "errors.ts"), "utf8");
    for (const code of codes) {
      assert.match(errors, new RegExp(`\\| "${code}"`), code);
    }
  });

  test("--print writes the skill to stdout", async (t) => {
    const result = await workspace(t).person("alice").run(["skill", "--print"]);
    ok(result);
    assert.equal(result.stdout, SKILL);
  });

  test("installs into the git root for every agent, then keeps it up to date", async (t) => {
    const ws = workspace(t);
    execFileSync("git", ["init", "-q"], { cwd: ws.root });
    const alice = ws.person("alice");

    const first = await alice.run(["skill"]);
    ok(first);
    for (const path of INSTALLED) {
      assert.equal(readFileSync(join(ws.root, path), "utf8"), SKILL, path);
    }
    assert.match(first.stderr, /Installed .*\.claude[\\/]skills[\\/]msecrets[\\/]SKILL\.md/);
    assert.match(first.stderr, /Commit these files/);

    writeFileSync(join(ws.root, INSTALLED[0] ?? ""), "old version");
    const second = await alice.run(["skill"]);
    ok(second);
    assert.match(second.stderr, /Updated .*\.claude/);
    assert.match(second.stderr, /Up to date: .*\.agents/);
    assert.equal(readFileSync(join(ws.root, INSTALLED[0] ?? ""), "utf8"), SKILL);
  });

  test("outside git, installs into the working directory; --global into the home directory", async (t) => {
    const ws = workspace(t);
    const home = join(ws.root, "home");
    mkdirSync(home);
    const alice = ws.person("alice");
    // GIT_CEILING_DIRECTORIES keeps git from finding a repository above the temporary directory.
    const env = { HOME: home, USERPROFILE: home, GIT_CEILING_DIRECTORIES: ws.root };

    ok(await alice.run(["skill"], { env }));
    for (const path of INSTALLED) {
      assert.equal(readFileSync(join(ws.project, path), "utf8"), SKILL, path);
    }

    const global = await alice.run(["skill", "--global"], { env });
    ok(global);
    assert.match(global.stderr, /every project/);
    for (const path of INSTALLED) {
      assert.equal(readFileSync(join(home, path), "utf8"), SKILL, path);
    }
  });

  test("the Claude Code plugin ships the same skill and version", () => {
    const marketplace = JSON.parse(
      readFileSync(join(UI, "..", "..", ".claude-plugin", "marketplace.json"), "utf8"),
    ) as { plugins: { name: string; source: string }[] };
    assert.deepEqual(
      marketplace.plugins.map((plugin) => [plugin.name, plugin.source]),
      [["msecrets", "./packages/ui"]],
    );
    const plugin = JSON.parse(readFileSync(join(UI, ".claude-plugin", "plugin.json"), "utf8")) as {
      name: string;
      version: string;
    };
    const manifest = JSON.parse(readFileSync(join(UI, "package.json"), "utf8")) as {
      version: string;
      files: string[];
    };
    assert.equal(plugin.name, "msecrets");
    assert.equal(plugin.version, manifest.version, "bump the plugin version with the package");
    assert.ok(manifest.files.includes("skills"));
  });
});
