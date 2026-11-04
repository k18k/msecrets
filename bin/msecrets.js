#!/usr/bin/env node
// Runs the native msecrets binary from the platform package npm installed next to this one.
"use strict";
const { spawn } = require("node:child_process");
const { dirname, join } = require("node:path");

const name = `@msecrets/cli-${process.platform}-${process.arch}`;
let binary;
try {
  binary = join(
    dirname(require.resolve(`${name}/package.json`)),
    "bin",
    process.platform === "win32" ? "msecrets.exe" : "msecrets",
  );
} catch {
  console.error(
    `msecrets: the native binary (${name}) is not installed.\n` +
      "npm skips git dependencies unless allowed. Reinstall with:\n" +
      "  npm install -g --allow-git=all github:k18k/msecrets#cli\n" +
      `Supported platforms: linux, darwin, win32 on x64 and arm64 (this is ${process.platform}-${process.arch}).`,
  );
  process.exit(1);
}

const child = spawn(binary, process.argv.slice(2), { stdio: "inherit", windowsHide: false });
// The terminal sends Ctrl-C to the whole process group; the binary decides what it means.
const signals = ["SIGINT", "SIGTERM", "SIGHUP"];
for (const signal of signals) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (error) => {
  console.error(`msecrets: cannot start ${binary}: ${error.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (signal) {
    for (const name of signals) process.removeAllListeners(name);
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
