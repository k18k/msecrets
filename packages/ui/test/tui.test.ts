import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, test } from "node:test";

import {
  generateIdentity,
  parseDocumentText,
  revealValue,
  setValue,
} from "../../core/src/index.ts";
import { main } from "../src/cli.ts";
import { Context } from "../src/context.ts";
import type { InputStream, Io, OutputStream } from "../src/terminal.ts";
import { TuiApp, fit } from "../src/tui/app.ts";
import { createSymbols, supportsUnicode } from "../src/symbols.ts";
import { decodeKeys } from "../src/tui/keys.ts";
import { Output, type Workspace, workspace } from "./harness.ts";

const UP = "\u001b[A";
const DOWN = "\u001b[B";
const RIGHT = "\u001b[C";
const ESC = "\u001b";
const ENTER = "\r";
const TAB = "\t";
const CTRL_U = "\u0015";

async function setup(
  t: Parameters<typeof workspace>[0],
): Promise<{ ws: Workspace; app: TuiApp; writes: string[]; context: Context }> {
  const ws = workspace(t);
  const alice = ws.person("alice");
  await alice.run(["init", "--store", "file", "--name", "alice"]);
  await alice.run(["set", "DATABASE_URL", "postgres://dev"]);
  await alice.run(["set", "API_KEY", "key", "--all"]);

  const io: Io = {
    stdin: new PassThrough() as unknown as InputStream,
    stdout: new Output() as unknown as OutputStream,
    stderr: new Output() as unknown as OutputStream,
    env: { MSECRETS_CONFIG_DIR: alice.config, NO_COLOR: "1", TERM: "xterm-256color" },
    cwd: ws.project,
  };
  const context = new Context(io, {});
  const writes: string[] = [];
  const app = new TuiApp(context, await context.identities(), null, (text) => writes.push(text));
  return { ws, app, writes, context };
}

const screen = (app: TuiApp, width = 110, height = 30) => app.render(width, height).join("\n");
const file = (ws: Workspace) =>
  parseDocumentText(readFileSync(join(ws.project, "msecrets.json"), "utf8"));

describe("TUI", () => {
  test("renders the secret × environment matrix with health and hints", async (t) => {
    const { app } = await setup(t);
    const output = screen(app);
    assert.match(output, / msecrets .*msecrets\.json {2}you: alice/);
    assert.match(output, /1 Secrets .* 2 Environments .* 3 Recipients .* 4 Checks/);
    assert.match(output, /SECRET\s+development\s+production\s+DESCRIPTION/);
    assert.match(output, /› API_KEY\s+\[●\]\s+●/, "the selected cell is bracketed");
    assert.match(output, /DATABASE_URL\s+●\s+○/);
    assert.match(output, /1 error\(s\)/);
    assert.match(output, /enter edit · v reveal/);
    for (const line of app.render(110, 30)) {
      assert.ok([...line.replace(/\u001b\[[0-9;]*m/g, "")].length <= 110, line);
    }
  });

  test("add a secret, then fill the missing cell", async (t) => {
    const { app, ws, context } = await setup(t);
    await app.feed(`aNEW_SECRET${ENTER}s3cret${ENTER}`);
    assert.equal(app.status?.text, "Set NEW_SECRET in development");
    assert.equal(
      revealValue(file(ws), await context.identities(), "NEW_SECRET", "development"),
      "s3cret",
    );

    // Move to DATABASE_URL × production (missing) and set it.
    app.row = app.secrets().indexOf("DATABASE_URL");
    await app.feed(`${RIGHT}${ENTER}postgres://prod${ENTER}`);
    assert.equal(
      revealValue(file(ws), await context.identities(), "DATABASE_URL", "production"),
      "postgres://prod",
    );
  });

  test("editing pre-fills the current value, hidden until tab", async (t) => {
    const { app, ws, context } = await setup(t);
    app.row = app.secrets().indexOf("DATABASE_URL");
    await app.feed(ENTER);
    assert.ok(screen(app).includes("•".repeat("postgres://dev".length)));
    assert.ok(!screen(app).includes("postgres://dev"));
    await app.feed(TAB);
    assert.ok(screen(app).includes("postgres://dev"));
    await app.feed(`\u007f\u007f\u007fprod${ENTER}`);
    assert.equal(
      revealValue(file(ws), await context.identities(), "DATABASE_URL", "development"),
      "postgres://prod",
    );
  });

  test("escape cancels without writing", async (t) => {
    const { app, ws } = await setup(t);
    const before = readFileSync(join(ws.project, "msecrets.json"), "utf8");
    await app.feed(`${ENTER}changed${ESC}`);
    assert.equal(app.modals.length, 0);
    assert.equal(readFileSync(join(ws.project, "msecrets.json"), "utf8"), before);
  });

  test("reveal shows the value and copies it through OSC 52", async (t) => {
    const { app, writes } = await setup(t);
    app.row = app.secrets().indexOf("DATABASE_URL");
    await app.feed("v");
    assert.match(screen(app), /│ postgres:\/\/dev/);
    await app.feed("c");
    assert.deepEqual(writes, [
      `\u001b]52;c;${Buffer.from("postgres://dev").toString("base64")}\u0007`,
    ]);
    assert.equal(app.modals.length, 0);
  });

  test("revealed values cannot inject terminal escape sequences", async (t) => {
    const { app, context } = await setup(t);
    context.update((document) =>
      setValue(document, app.identities, {
        secret: "EVIL",
        environment: "development",
        value: "a\u001b[2Jb\u0007c",
      }),
    );
    app.reload();
    app.row = app.secrets().indexOf("EVIL");
    app.column = 0;
    await app.feed("v");
    const output = screen(app);
    assert.ok(output.includes("a\ufffd[2Jb\ufffdc"));
    assert.ok(!output.includes("\u001b[2J"));
  });

  test("rename, describe, unset, delete", async (t) => {
    const { app, ws } = await setup(t);
    app.row = app.secrets().indexOf("API_KEY");
    await app.feed(`r${CTRL_U}PAYMENT_KEY${ENTER}`);
    assert.ok(file(ws).secrets["PAYMENT_KEY"]);
    app.row = app.secrets().indexOf("PAYMENT_KEY");
    await app.feed(`DPayments provider${ENTER}`);
    assert.equal(file(ws).secrets["PAYMENT_KEY"]?.description, "Payments provider");
    await app.feed("uy");
    assert.equal(file(ws).secrets["PAYMENT_KEY"]?.values["development"], undefined);
    await app.feed("dn");
    assert.ok(file(ws).secrets["PAYMENT_KEY"], "n cancels");
    await app.feed("dy");
    assert.equal(file(ws).secrets["PAYMENT_KEY"], undefined);
  });

  test("invalid input shows an error and changes nothing", async (t) => {
    const { app, ws } = await setup(t);
    const before = readFileSync(join(ws.project, "msecrets.json"), "utf8");
    await app.feed(`abad name${ENTER}`);
    assert.equal(app.status?.tone, "error");
    assert.match(app.status?.text ?? "", /Invalid secret name/);
    assert.equal(readFileSync(join(ws.project, "msecrets.json"), "utf8"), before);
  });

  test("filter, help, navigation, quit", async (t) => {
    const { app } = await setup(t);
    await app.feed(`/data${ENTER}`);
    assert.deepEqual(app.secrets(), ["DATABASE_URL"]);
    assert.match(screen(app), /filter: data/);
    await app.feed(ESC);
    assert.equal(app.secrets().length, 2);

    await app.feed(`${DOWN}${DOWN}${DOWN}`);
    assert.equal(app.row, 1, "clamped to the last row");
    await app.feed(`${UP}\u001b[F`);
    assert.equal(app.row, 1);
    await app.feed("\u001b[H");
    assert.equal(app.row, 0);

    await app.feed("?");
    assert.match(screen(app), /Keys/);
    await app.feed("x");
    assert.equal(app.modals.length, 0);

    await app.feed("q");
    assert.equal(app.done, true);
  });

  test("environments: add, grant, revoke", async (t) => {
    const { app, ws } = await setup(t);
    const bob = generateIdentity();
    await app.feed(`3abob${ENTER}${bob.publicKey.token}${ENTER}`);
    assert.ok(file(ws).recipients["bob"]);

    await app.feed(`2astaging${ENTER}`);
    assert.deepEqual(file(ws).environments["staging"]?.recipients, ["alice"]);
    app.row = app.environments().indexOf("development");
    await app.feed(`g${ENTER}`);
    assert.deepEqual(file(ws).environments["development"]?.recipients, ["alice", "bob"]);
    assert.equal(revealValue(file(ws), [bob], "DATABASE_URL", "development"), "postgres://dev");

    await app.feed("x");
    assert.match(screen(app), /Revoke access to development/);
    await app.feed(`${DOWN}${ENTER}`);
    assert.deepEqual(file(ws).environments["development"]?.recipients, ["alice"]);
    assert.match(screen(app), /could read these and may have copies/);
    await app.feed(ENTER);

    app.view = "environments";
    await app.feed("4");
    assert.match(screen(app), /has no value in "staging"/);
    const finding = app.report.findings[0];
    await app.feed(ENTER);
    assert.equal(app.view, "secrets");
    assert.equal(app.secrets()[app.row], finding?.secret);
    assert.equal(app.environments()[app.column], finding?.environment);
  });

  test("recipients view: rename, describe, grant, revoke, remove", async (t) => {
    const { app, ws } = await setup(t);
    const bob = generateIdentity();
    await app.feed(`3abob${ENTER}${bob.publicKey.token}${ENTER}`);
    app.row = app.recipients().indexOf("bob");
    await app.feed(`r${CTRL_U}robert${ENTER}`);
    assert.ok(file(ws).recipients["robert"]);
    app.row = app.recipients().indexOf("robert");
    await app.feed(`DContractor${ENTER}`);
    assert.equal(file(ws).recipients["robert"]?.description, "Contractor");
    assert.match(screen(app), /robert\s+x25519\s+none\s+Contractor/);

    await app.feed(`g${DOWN}${ENTER}`);
    assert.deepEqual(file(ws).environments["production"]?.recipients, ["alice", "robert"]);
    await app.feed(`x${ENTER}`);
    assert.deepEqual(file(ws).environments["production"]?.recipients, ["alice"]);
    await app.feed(ENTER);
    await app.feed("x");
    assert.equal(app.status?.text, "Nothing to choose for: Revoke robert from");
    await app.feed("dy");
    assert.equal(file(ws).recipients["robert"], undefined);
    await app.feed(ENTER);
    assert.match(screen(app), /alice \(you\)/);
  });

  test("environments view: rename and remove", async (t) => {
    const { app, ws } = await setup(t);
    await app.feed("2");
    app.row = app.environments().indexOf("production");
    await app.feed(`r${CTRL_U}prod${ENTER}`);
    assert.deepEqual(Object.keys(file(ws).environments), ["development", "prod"]);
    app.row = app.environments().indexOf("prod");
    await app.feed("d");
    assert.match(screen(app), /Remove prod\?/);
    await app.feed("y");
    assert.deepEqual(Object.keys(file(ws).environments), ["development"]);
    await app.feed("g");
    await app.feed(ESC);
    assert.equal(app.modals.length, 0);
  });

  test("input editing: cursor movement, insertion, delete", async (t) => {
    const { app, ws, context } = await setup(t);
    app.row = app.secrets().indexOf("API_KEY");
    await app.feed(`${ENTER}${CTRL_U}acd\u001b[D\u001b[Db\u001b[F!\u001b[H\u001b[3~X${ENTER}`);
    assert.equal(
      revealValue(file(ws), await context.identities(), "API_KEY", "development"),
      "Xbcd!",
    );
  });

  test("renders on tiny and huge terminals", async (t) => {
    const { app } = await setup(t);
    for (const [width, height] of [
      [20, 5],
      [40, 12],
      [300, 80],
    ] as const) {
      const lines = app.render(width, height);
      assert.equal(lines.length, height);
      for (const line of lines) {
        assert.ok([...line.replace(/\u001b\[[0-9;]*m/g, "")].length <= width);
      }
    }
    await app.feed("?");
    assert.equal(app.render(30, 8).length, 8);
  });

  test("page keys and view cycling", async (t) => {
    const { app } = await setup(t);
    await app.feed("\u001b[6~");
    assert.equal(app.row, 1);
    await app.feed("\u001b[5~");
    assert.equal(app.row, 0);
    await app.feed(TAB);
    assert.equal(app.view, "environments");
    await app.feed("\u001b[Z\u001b[Z");
    assert.equal(app.view, "checks");
  });

  test("read-only mode explains why", async (t) => {
    const { context } = await setup(t);
    const app = new TuiApp(
      context,
      [],
      "no identity found (run `msecrets identity new`)",
      () => {},
    );
    assert.match(screen(app), /Read-only: no identity found/);
    await app.feed(ENTER);
    assert.equal(app.status?.tone, "error");
  });

  test("full-screen session: enters and restores the terminal", async (t) => {
    const ws = workspace(t);
    const alice = ws.person("alice");
    await alice.run(["init", "--store", "file", "--name", "alice"]);

    const rawModes: boolean[] = [];
    const stdin = Object.assign(new PassThrough(), {
      isTTY: true,
      setRawMode: (mode: boolean) => rawModes.push(mode),
    });
    const stdout = Object.assign(new Output(), { isTTY: true });
    const io: Io = {
      stdin: stdin as unknown as InputStream,
      stdout: stdout as unknown as OutputStream,
      stderr: new Output() as unknown as OutputStream,
      env: { MSECRETS_CONFIG_DIR: alice.config, NO_COLOR: "1", TERM: "xterm-256color" },
      cwd: ws.project,
    };
    const session = main([], io);
    setTimeout(() => stdin.write("q"), 50);
    assert.equal(await session, 0);
    assert.deepEqual(rawModes, [true, false]);
    assert.ok(stdout.text.startsWith("\u001b[?1049h"));
    assert.ok(stdout.text.endsWith("\u001b[?25h\u001b[?1049l"));
  });
});

describe("keys and layout", () => {
  test("legacy Windows consoles get ASCII symbols", () => {
    assert.equal(supportsUnicode({}, "win32"), false);
    assert.equal(supportsUnicode({ WT_SESSION: "1" }, "win32"), true);
    assert.equal(supportsUnicode({ TERM_PROGRAM: "vscode" }, "win32"), true);
    assert.equal(supportsUnicode({}, "darwin"), true);
    assert.equal(supportsUnicode({ TERM: "linux" }, "linux"), false);
    assert.equal(Object.values(createSymbols(false).cell).join(""), "+~-x!.");
  });

  test("decodes terminal input", () => {
    assert.deepEqual(decodeKeys(`a${UP}\u001bOB\u001b[3~\r\n\u0003é🔐\u001b[1;5C\u001b`), [
      { name: "char", char: "a" },
      { name: "up" },
      { name: "down" },
      { name: "delete" },
      { name: "enter" },
      { name: "ctrl", char: "c" },
      { name: "char", char: "é" },
      { name: "char", char: "🔐" },
      { name: "escape" },
    ]);
  });

  test("fit truncates by visible width and keeps ANSI intact", () => {
    assert.equal(fit("abc", 5), "abc  ");
    assert.equal(fit("abcdef", 4), "abc…\u001b[0m");
    assert.equal(fit("\u001b[31mabcdef\u001b[39m", 4), "\u001b[31mabc…\u001b[0m");
  });
});
