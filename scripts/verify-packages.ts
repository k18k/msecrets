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
const ALLOWED_FILES =
  /^(dist\/.+|schema\/v\d+\.json|skills\/[a-z-]+\/SKILL\.md|package\.json|README\.md|LICENSE)$/;

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
        manifest["files"].every((entry) => ["dist", "schema", "skills"].includes(entry)),
      `${manifest.name} must publish only dist (and schema or skills)`,
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
  copyFileSync(join(fixtures, "app.ms.json"), join(app, "msecrets.json"));
  const identity = readFileSync(join(fixtures, "production.identity.txt"), "utf8");
  const env = { MSECRETS_ENV: "production", MSECRETS_IDENTITY: identity };

  // A consumer imports its secrets file, in ESM and CommonJS, and typechecks against the published types.
  writeFileSync(
    join(app, "app.mjs"),
    `import { createClient } from "@msecrets/ts-sdk";\nimport file from "./msecrets.json" with { type: "json" };\nconsole.log(createClient(file).DATABASE_URL);\n`,
  );
  writeFileSync(
    join(app, "app.cjs"),
    `const { createClient } = require("@msecrets/ts-sdk");\nconsole.log(createClient(require("./msecrets.json")).SENTRY_DSN);\n`,
  );
  assert.equal(node(["app.mjs"], app, env), "postgres://db.internal/prod");
  assert.equal(node(["app.cjs"], app, env), "https://sentry.example/1");

  writeFileSync(
    join(app, "app.mts"),
    [
      `import { createClient, injectEnv } from "@msecrets/ts-sdk";`,
      `import file from "./msecrets.json" with { type: "json" };`,
      `const secrets = createClient(file, { env: "production" });`,
      `const url: string = secrets.DATABASE_URL;`,
      `const dsn: string | undefined = secrets.SENTRY_DSN;`,
      `// @ts-expect-error: limited to some environments`,
      `const required: string = secrets.SENTRY_DSN;`,
      `// @ts-expect-error: not a secret in the file`,
      `secrets.DATABSE_URL;`,
      `// @ts-expect-error: frozen`,
      `secrets.DATABASE_URL = "";`,
      `const names: string[] = injectEnv(file);`,
      `export { dsn, names, required, url };`,
      ``,
    ].join("\n"),
  );
  writeFileSync(
    join(app, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        module: "nodenext",
        strict: true,
        noEmit: true,
        resolveJsonModule: true,
        types: ["node"],
        typeRoots: [join(root, "node_modules", "@types")],
      },
      files: ["app.mts"],
    }),
  );
  node([join(root, "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.json"], app);
  console.log(
    "✓ @msecrets/ts-sdk: JSON imports in ESM and CommonJS, and typed secrets from the published declarations",
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
  npm(["exec", "--offline", "--", "msecrets", "skill"], app);
  assert.equal(
    readFileSync(join(app, ".claude", "skills", "msecrets", "SKILL.md"), "utf8"),
    readFileSync(join(root, "packages", "ui", "skills", "msecrets", "SKILL.md"), "utf8"),
  );
  console.log(
    "✓ @msecrets/ui: the msecrets binary runs when installed and installs the agent skill",
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}
