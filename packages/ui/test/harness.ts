import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import type { TestContext } from "node:test";

import { tempDir } from "../../core/test/helpers.ts";
import { main } from "../src/cli.ts";
import type { InputStream, Io, OutputStream } from "../src/terminal.ts";

export class Output extends Writable {
  text = "";
  isTTY = false;
  columns = 120;
  rows = 40;

  override _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: () => void): void {
    this.text += chunk.toString();
    callback();
  }
}

export type RunResult = { code: number; stdout: string; stderr: string };

export type Person = {
  config: string;
  run(argv: string[], options?: { input?: string; env?: NodeJS.ProcessEnv }): Promise<RunResult>;
};

export type Workspace = { root: string; project: string; person(name: string): Person };

export function workspace(t: TestContext): Workspace {
  const root = tempDir(t);
  const project = join(root, "project");
  mkdirSync(project);

  return {
    root,
    project,
    person(name) {
      const config = join(root, `config-${name}`);
      return {
        config,
        async run(argv, options = {}) {
          const stdin = new PassThrough() as PassThrough & InputStream;
          stdin.end(options.input ?? "");
          const stdout = new Output();
          const stderr = new Output();
          const io: Io = {
            stdin,
            stdout: stdout as unknown as OutputStream,
            stderr: stderr as unknown as OutputStream,
            env: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              MSECRETS_CONFIG_DIR: config,
              NO_COLOR: "1",
              ...options.env,
            },
            cwd: project,
          };
          const code = await main(argv, io);
          return { code, stdout: stdout.text, stderr: stderr.text };
        },
      };
    },
  };
}

/** Extracts the identity line from `--store print` / `--generate` output. */
export function identityFrom(output: string): string {
  return output.split("\n").find((line) => line.startsWith("AGE-SECRET-KEY-")) ?? "";
}

export type Exchange = [prompt: RegExp, answer: string];

/**
 * Runs a command on a simulated terminal: each answer is typed when its prompt
 * appears on stderr, like a person would.
 */
export async function interactive(
  person: Person,
  project: string,
  argv: string[],
  exchanges: Exchange[],
  env: NodeJS.ProcessEnv = {},
  options: { stdoutIsTerminal?: boolean } = {},
): Promise<RunResult & { unanswered: number }> {
  const stdin = Object.assign(new PassThrough(), { isTTY: true, setRawMode: () => stdin });
  const stdout = new Output();
  stdout.isTTY = options.stdoutIsTerminal ?? false;
  const stderr = new Output();
  const pending = [...exchanges];
  let seen = 0;
  const original = stderr._write.bind(stderr);
  stderr._write = (chunk, encoding, callback) => {
    original(chunk, encoding, callback);
    const next = pending[0];
    if (next && next[0].test(stderr.text.slice(seen))) {
      seen = stderr.text.length;
      pending.shift();
      setImmediate(() => stdin.write(next[1]));
    }
  };
  const io: Io = {
    stdin: stdin as unknown as InputStream,
    stdout: stdout as unknown as OutputStream,
    stderr: stderr as unknown as OutputStream,
    env: {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      MSECRETS_CONFIG_DIR: person.config,
      NO_COLOR: "1",
      ...env,
    },
    cwd: project,
  };
  const code = await main(argv, io);
  return { code, stdout: stdout.text, stderr: stderr.text, unanswered: pending.length };
}
