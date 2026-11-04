// Type-checks index.d.ts the way users import it: the package by name, the secrets file as JSON.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const DIST = join(import.meta.dirname, "..", "..", "dist", "ts-sdk");

const usage = (module) => `
import { createClient, injectEnv, isMsecretsError, fromEnv, type Secrets, type ErrorCode } from "@msecrets/ts-sdk";
${module === "esm" ? 'import file from "./app.ms.json" with { type: "json" };' : 'import file = require("./app.ms.json");'}

const secrets: Secrets<typeof file> = createClient(file, { env: "production", identities: [fromEnv("PROD_KEY"), "env:X"] });
const url: string = secrets.DATABASE_URL;
const dsn: string | undefined = secrets.SENTRY_DSN;
// @ts-expect-error: a secret limited to some environments is not always a string
const required: string = secrets.SENTRY_DSN;
// @ts-expect-error: unknown secret names are type errors
secrets.DATABSE_URL;
// @ts-expect-error: the result is read-only
secrets.API_TOKEN = "x";
const loose: Readonly<Record<string, string | undefined>> = createClient({ secrets: {} });
const names: string[] = injectEnv(file, { override: true, target: process.env });
const custom = createClient(file, { identities: [{ label: "vault", load: () => [{ identity: "AGE-SECRET-KEY-1", source: "vault" }] }] });
try {} catch (error) { if (isMsecretsError(error, "SIGNATURE")) { const code: ErrorCode = error.code; void code; } }
void [url, dsn, required, loose, names, custom];
`;

const tsc = spawnSync("tsc", ["--version"], { encoding: "utf8", shell: process.platform === "win32" });

for (const module of ["esm", "cjs"]) {
  test(`index.d.ts types the secrets file (${module})`, { skip: tsc.status !== 0 && "tsc is not on PATH" }, (t) => {
    const directory = mkdtempSync(join(tmpdir(), "msecrets-types-"));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    mkdirSync(join(directory, "node_modules", "@msecrets"), { recursive: true });
    symlinkSync(DIST, join(directory, "node_modules", "@msecrets", "ts-sdk"), "junction");
    copyFileSync(join(import.meta.dirname, "fixtures", "app.ms.json"), join(directory, "app.ms.json"));
    writeFileSync(join(directory, module === "esm" ? "usage.mts" : "usage.cts"), usage(module));
    writeFileSync(join(directory, "process.d.ts"), "declare var process: { env: Record<string, string | undefined> };\n");
    const compilerOptions = { noEmit: true, strict: true, module: "nodenext", resolveJsonModule: true, types: [] };
    writeFileSync(join(directory, "tsconfig.json"), JSON.stringify({ compilerOptions }));
    const result = spawnSync("tsc", ["-p", "."], { cwd: directory, encoding: "utf8", shell: process.platform === "win32" });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
