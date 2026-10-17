/**
 * Verifies the public install path: packs every publishable package, checks
 * the tarball contents and manifests (no dependencies, only dist), installs
 * the tarballs offline into an empty project, and exercises them from there.
 *
 * Run through npm (`npm run verify:packages`) after `npm run build`.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const npmCli = process.env["npm_execpath"];
if (!npmCli) {
  throw new Error("Run this through npm: `npm run verify:packages`");
}

type Manifest = Record<string, unknown> & { name: string; version: string };

const PACKAGES = ["ts-sdk", "ui"];
const FORBIDDEN_FIELDS = [
  "dependencies",
  "peerDependencies",
  "optionalDependencies",
  "bundleDependencies",
  "bundledDependencies",
];
const ALLOWED_FILES = /^(dist\/.+|schema\/v\d+\.json|package\.json|README\.md|LICENSE)$/;

const work = mkdtempSync(join(tmpdir(), "msecrets-verify-"));
const npm = (args: string[], cwd: string) =>
  execFileSync(process.execPath, [npmCli, ...args], { cwd, encoding: "utf8" });
const node = (args: string[], cwd: string, env: NodeJS.ProcessEnv = {}) =>
  execFileSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...env },
  }).trim();

try {
  const tarballs: string[] = [];

  for (const name of PACKAGES) {
    const directory = join(root, "packages", name);
    const manifest = JSON.parse(readFileSync(join(directory, "package.json"), "utf8")) as Manifest;
    for (const field of FORBIDDEN_FIELDS) {
      assert.equal(manifest[field], undefined, `${manifest.name} must not declare ${field}`);
    }
    for (const field of [
      "license",
      "repository",
      "engines",
      "files",
      "publishConfig",
      "description",
    ]) {
      assert.ok(manifest[field], `${manifest.name} must declare ${field}`);
    }
    assert.ok(
      Array.isArray(manifest["files"]) &&
        manifest["files"].every((entry) => entry === "dist" || entry === "schema"),
      `${manifest.name} must publish only dist (and schema)`,
    );

    const [packed] = JSON.parse(npm(["pack", "--json", "--pack-destination", work], directory)) as [
      { filename: string; files: { path: string }[]; size: number },
    ];
    assert.ok(packed, `npm pack produced nothing for ${manifest.name}`);
    const files = packed.files.map((file) => file.path);
    for (const file of files) {
      assert.match(file, ALLOWED_FILES, `${manifest.name} must not publish ${file}`);
    }
    for (const required of ["package.json", "README.md", "LICENSE"]) {
      assert.ok(files.includes(required), `${manifest.name} must publish ${required}`);
    }
    tarballs.push(join(work, packed.filename));
    console.log(
      `✓ ${manifest.name}@${manifest.version}: ${files.length} files, ${(packed.size / 1024).toFixed(1)} kB packed`,
    );
  }

  const app = join(work, "app");
  mkdirSync(app);
  writeFileSync(join(app, "package.json"), JSON.stringify({ name: "consumer", private: true }));
  npm(["install", "--offline", "--no-audit", "--no-fund", "--ignore-scripts", ...tarballs], app);
  const installed = JSON.parse(readFileSync(join(app, "package-lock.json"), "utf8")) as {
    packages: Record<string, unknown>;
  };
  assert.deepEqual(
    Object.keys(installed.packages).filter(Boolean).toSorted(),
    ["node_modules/@msecrets/ts-sdk", "node_modules/@msecrets/ui"],
    "installing the packages must not pull in anything else",
  );

  const fixtures = join(root, "packages", "ts-sdk", "test", "fixtures");
  copyFileSync(join(fixtures, "app.ms.json"), join(app, ".env.ms.json"));
  const identity = readFileSync(join(fixtures, "production.identity.txt"), "utf8");
  const env = { MSECRETS_ENV: "production", MSECRETS_IDENTITY: identity };

  assert.equal(
    node(
      [
        "--input-type=module",
        "-e",
        `import { load } from "@msecrets/ts-sdk"; console.log(load().DATABASE_URL)`,
      ],
      app,
      env,
    ),
    "postgres://db.internal/prod",
  );
  assert.equal(
    node(["-e", `console.log(require("@msecrets/ts-sdk").load().SENTRY_DSN)`], app, env),
    "https://sentry.example/1",
  );
  for (const flag of ["--import", "--require"]) {
    assert.equal(
      node(
        [flag, "@msecrets/ts-sdk/register", "-e", "console.log(process.env.DATABASE_URL)"],
        app,
        env,
      ),
      "postgres://db.internal/prod",
    );
  }
  for (const types of ["index.d.mts", "index.d.cts"]) {
    assert.match(
      readFileSync(join(app, "node_modules", "@msecrets", "ts-sdk", "dist", types), "utf8"),
      /createClient/,
    );
  }
  console.log(
    "✓ @msecrets/ts-sdk: ESM, CommonJS, register (--import and --require), and types work when installed",
  );

  const version = (
    JSON.parse(readFileSync(join(root, "packages", "ui", "package.json"), "utf8")) as Manifest
  ).version;
  assert.equal(npm(["exec", "--offline", "--", "msecrets", "--version"], app).trim(), version);
  assert.equal(
    node(
      [join("node_modules", "@msecrets", "ui", "dist", "bin.mjs"), "get", "SENTRY_DSN"],
      app,
      env,
    ),
    "https://sentry.example/1",
  );
  console.log("✓ @msecrets/ui: the msecrets binary runs when installed");
} finally {
  rmSync(work, { recursive: true, force: true });
}
