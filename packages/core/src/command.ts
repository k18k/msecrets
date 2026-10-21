/** Cross-platform command execution without a shell. */
import { statSync } from "node:fs";
import { delimiter, extname, isAbsolute, join, resolve } from "node:path";

import { MsecretsError } from "./errors.ts";

const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/** Quotes an argument for CreateProcess: backslashes double only before a quote or the end. */
function quoteWindowsArgument(argument: string): string {
  let quoted = '"';
  let backslashes = 0;
  for (const char of argument) {
    if (char === "\\") {
      backslashes++;
      continue;
    }
    quoted += "\\".repeat(char === '"' ? backslashes * 2 + 1 : backslashes) + char;
    backslashes = 0;
  }
  return `${quoted}${"\\".repeat(backslashes * 2)}"`;
}

/** Quotes an argument for CreateProcess, then escapes cmd.exe metacharacters. */
function escapeWindowsArgument(argument: string, doubleEscape: boolean): string {
  const quoted = quoteWindowsArgument(argument).replace(CMD_META, "^$1");
  // Batch files parse their arguments a second time.
  return doubleEscape ? quoted.replace(CMD_META, "^$1") : quoted;
}

function isFile(path: string): boolean {
  return statSync(path, { throwIfNoEntry: false })?.isFile() ?? false;
}

/** Resolves a command like the Windows shell does (PATH and PATHEXT). */
function resolveWindowsCommand(
  command: string,
  env: NodeJS.ProcessEnv,
  cwd: string,
): string | null {
  const extensions = (env["PATHEXT"] ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const candidates = extname(command) ? [""] : extensions;
  const directories =
    isAbsolute(command) || /[\\/]/.test(command)
      ? [""]
      : [cwd, ...(env["PATH"] ?? env["Path"] ?? "").split(delimiter).filter(Boolean)];

  for (const directory of directories) {
    for (const extension of candidates) {
      const candidate = resolve(cwd, join(directory, command + extension));
      if (isFile(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

export type CommandPlan = { file: string; args: string[]; verbatim: boolean };

/**
 * How to start a command without a shell. On Windows, commands resolve through
 * PATH and PATHEXT, and `.cmd`/`.bat` shims (such as npm-installed CLIs) run
 * through cmd.exe with every argument escaped.
 */
export function planCommand(
  argv: readonly string[],
  options: { env: NodeJS.ProcessEnv; cwd: string; platform?: NodeJS.Platform },
): CommandPlan {
  const [command, ...args] = argv;
  if (!command) {
    throw new MsecretsError("USAGE", "No command given");
  }
  if ((options.platform ?? process.platform) !== "win32") {
    return { file: command, args, verbatim: false };
  }

  const resolved = resolveWindowsCommand(command, options.env, options.cwd) ?? command;
  if (!/\.(cmd|bat)$/i.test(resolved)) {
    return { file: resolved, args, verbatim: false };
  }
  const line = [
    resolved.replace(CMD_META, "^$1"),
    ...args.map((argument) => escapeWindowsArgument(argument, true)),
  ].join(" ");
  return {
    file: options.env["ComSpec"] ?? "cmd.exe",
    args: ["/d", "/s", "/c", `"${line}"`],
    verbatim: true,
  };
}
