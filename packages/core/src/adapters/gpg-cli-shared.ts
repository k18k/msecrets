import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export type GpgOptions = {
  homedir?: string;
};

function withHomedir(args: string[], options: GpgOptions = {}): string[] {
  return options.homedir ? ["--homedir", options.homedir, ...args] : args;
}

export function decryptWithGpg(ciphertext: string, options: GpgOptions = {}): string {
  return execFileSync("gpg", withHomedir(["--decrypt", "--batch", "--yes"], options), {
    input: ciphertext,
    encoding: "utf8",
  });
}

export function importPrivateKey(privateKey: string | Buffer, options: GpgOptions = {}) {
  execFileSync("gpg", withHomedir(["--batch", "--yes", "--import"], options), {
    input: privateKey,
    encoding: typeof privateKey === "string" ? "utf8" : undefined,
    stdio: ["pipe", "ignore", "pipe"],
  });
}

export function createTempGpgHome(): string {
  const homedir = mkdtempSync(join(tmpdir(), "msecrets-gpg-"));
  chmodSync(homedir, 0o700);
  return homedir;
}

export function cleanupDir(path: string) {
  rmSync(path, { force: true, recursive: true });
}
