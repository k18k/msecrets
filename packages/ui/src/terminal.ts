import { createInterface } from "node:readline";

import { MsecretsError } from "../../core/src/index.ts";

export type InputStream = NodeJS.ReadableStream & {
  isTTY?: boolean;
  setRawMode?(mode: boolean): unknown;
};
export type OutputStream = NodeJS.WritableStream & {
  isTTY?: boolean;
  columns?: number;
  rows?: number;
};

/** Everything a command touches outside the process: injectable for tests. */
export type Io = {
  stdin: InputStream;
  stdout: OutputStream;
  stderr: OutputStream;
  env: NodeJS.ProcessEnv;
  cwd: string;
};

export function processIo(): Io {
  return {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
    cwd: process.cwd(),
  };
}

export type Style = (text: string) => string;
export type Colors = Record<
  "bold" | "dim" | "red" | "green" | "yellow" | "blue" | "magenta" | "cyan" | "inverse",
  Style
>;

export function colorsEnabled(stream: OutputStream, env: NodeJS.ProcessEnv): boolean {
  if (env["NO_COLOR"]) {
    return false;
  }
  if (env["FORCE_COLOR"] !== undefined) {
    return env["FORCE_COLOR"] !== "0";
  }
  return Boolean(stream.isTTY) && env["TERM"] !== "dumb";
}

export function createColors(enabled: boolean): Colors {
  const wrap =
    (open: number, close: number): Style =>
    (text) =>
      enabled ? `\u001b[${open}m${text}\u001b[${close}m` : text;
  return {
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    inverse: wrap(7, 27),
  };
}

const ANSI = /\u001b\[[0-9;?]*[A-Za-z]|\u001b\][^\u0007]*\u0007/g;

/** Makes untrusted text safe to print: control characters (escape sequences) become U+FFFD. */
export function sanitize(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, "\ufffd");
}

export function stripAnsi(text: string): string {
  return text.replace(ANSI, "");
}

/** Display width; treats every code point as one column (the UI only uses such characters). */
export function visibleLength(text: string): number {
  return [...stripAnsi(text)].length;
}

export function padEnd(text: string, width: number): string {
  return text + " ".repeat(Math.max(0, width - visibleLength(text)));
}

/** Renders rows as aligned columns. */
export function table(rows: readonly (readonly string[])[], gap = 2): string[] {
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, index) => {
      widths[index] = Math.max(widths[index] ?? 0, visibleLength(cell));
    });
  }
  return rows.map((row) =>
    row
      .map((cell, index) =>
        index === row.length - 1 ? cell : padEnd(cell, (widths[index] ?? 0) + gap),
      )
      .join("")
      .trimEnd(),
  );
}

export class CancelledError extends Error {
  constructor() {
    super("Cancelled");
    this.name = "CancelledError";
  }
}

export function readAll(stream: InputStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer | string) => chunks.push(Buffer.from(chunk)));
    stream.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    stream.once("error", reject);
    stream.resume();
  });
}

/** Asks a question on the terminal. Hidden input is not echoed. */
export function ask(io: Io, question: string, options: { hidden?: boolean } = {}): Promise<string> {
  if (!io.stdin.isTTY) {
    return Promise.reject(
      new MsecretsError("USAGE", `Cannot ask "${question.trim()}" without a terminal`),
    );
  }

  const rawMode = io.stdin.setRawMode?.bind(io.stdin);
  if (!options.hidden || !rawMode) {
    const readline = createInterface({ input: io.stdin, output: io.stderr, terminal: true });
    return new Promise((resolve, reject) => {
      readline.once("SIGINT", () => {
        readline.close();
        reject(new CancelledError());
      });
      readline.question(question, (answer) => {
        readline.close();
        resolve(answer);
      });
    });
  }

  const stdin = io.stdin;
  const setRawMode = rawMode;
  io.stderr.write(question);
  return new Promise((resolve, reject) => {
    let value = "";
    const finish = (error?: Error) => {
      stdin.removeListener("data", onData);
      setRawMode(false);
      stdin.pause();
      io.stderr.write("\n");
      if (error) {
        reject(error);
      } else {
        resolve(value);
      }
    };
    const onData = (chunk: Buffer | string) => {
      const chars = [...chunk.toString()];
      for (const [index, char] of chars.entries()) {
        if (char === "\r" || char === "\n") {
          // Keep input typed (or pasted) ahead for the next prompt; a CRLF counts as one Enter.
          const rest = chars
            .slice(char === "\r" && chars[index + 1] === "\n" ? index + 2 : index + 1)
            .join("");
          finish();
          if (rest) {
            stdin.unshift(Buffer.from(rest));
          }
          return;
        }
        if (char === "\u0003" || char === "\u0004") {
          finish(new CancelledError());
          return;
        }
        if (char === "\u007f" || char === "\b") {
          value = [...value].slice(0, -1).join("");
        } else if (char >= " ") {
          value += char;
        }
      }
    };
    setRawMode(true);
    stdin.on("data", onData);
    stdin.resume();
  });
}

export async function confirm(io: Io, question: string): Promise<boolean> {
  const answer = await ask(io, `${question} [y/N] `);
  return /^y(es)?$/i.test(answer.trim());
}
