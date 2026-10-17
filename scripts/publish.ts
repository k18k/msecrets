/**
 * Publishes every package whose version is not on npm yet, then makes sure its
 * tag and GitHub release exist. Each step checks its own state, so re-running
 * after a partial failure (npm published, tag push or release failed) completes
 * the rest.
 *
 * Runs in the release workflow with npm trusted publishing (OIDC). Provenance is
 * attached when the repository is public.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "..");
const npmCli = process.env["npm_execpath"];
if (!npmCli) {
  throw new Error("Run this through npm: `npm run publish:new`");
}
const provenance = process.env["MSECRETS_PROVENANCE"] === "true";

for (const name of ["ts-sdk", "ui"]) {
  const directory = join(root, "packages", name);
  const manifest = JSON.parse(readFileSync(join(directory, "package.json"), "utf8")) as {
    name: string;
    version: string;
  };
  const spec = `${manifest.name}@${manifest.version}`;

  const existing = spawnSync(process.execPath, [npmCli, "view", spec, "version"], {
    encoding: "utf8",
  });
  if (existing.status === 0 && existing.stdout.trim() === manifest.version) {
    console.log(`${spec} is already on npm`);
  } else {
    console.log(`Publishing ${spec}${provenance ? " with provenance" : ""}`);
    execFileSync(
      process.execPath,
      [npmCli, "publish", "--access", "public", ...(provenance ? ["--provenance"] : [])],
      { cwd: directory, stdio: "inherit" },
    );
  }

  // The tag marks the commit this workflow run built and published.
  const tag = spec;
  const remoteTag = spawnSync("git", [
    "ls-remote",
    "--exit-code",
    "--tags",
    "origin",
    `refs/tags/${tag}`,
  ]);
  if (remoteTag.status !== 0) {
    if (spawnSync("git", ["rev-parse", "--verify", "--quiet", `refs/tags/${tag}`]).status !== 0) {
      execFileSync("git", ["tag", tag], { stdio: "inherit" });
    }
    execFileSync("git", ["push", "origin", `refs/tags/${tag}`], { stdio: "inherit" });
  }
  if (spawnSync("gh", ["release", "view", tag]).status !== 0) {
    execFileSync(
      "gh",
      ["release", "create", tag, "--title", spec, "--generate-notes", "--verify-tag"],
      { stdio: "inherit" },
    );
  }
}
