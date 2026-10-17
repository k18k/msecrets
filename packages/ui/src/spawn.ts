import { type ChildProcess, spawn } from "node:child_process";
import { statSync } from "node:fs";
import { constants } from "node:os";
import { delimiter, extname, isAbsolute, join, resolve } from "node:path";

import { MsecretsError } from "../../core/src/index.ts";

const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

/** Quotes an argument for CreateProcess, then escapes cmd.exe metacharacters. */
function escapeWindowsArgument(argument: string, doubleEscape: boolean): string {
  let quoted = argument.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, "$1$1");
  quoted = `"${quoted}"`.replace(CMD_META, "^$1");
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

export type SpawnPlan = { file: string; args: string[]; verbatim: boolean };

/** How to start a command: `.cmd`/`.bat` shims on Windows go through cmd.exe with escaped arguments. */
export function planSpawn(
  argv: readonly string[],
  options: { env: NodeJS.ProcessEnv; cwd: string; platform?: NodeJS.Platform },
): SpawnPlan {
  const [command, ...args] = argv;
  if (!command) {
    throw new MsecretsError(
      "USAGE",
      "No command given; usage: msecrets run [--env NAME] -- <command> [args...]",
    );
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

/** Spawns a command with inherited stdio. */
export function spawnCommand(
  argv: readonly string[],
  options: { env: NodeJS.ProcessEnv; cwd: string },
): ChildProcess {
  const plan = planSpawn(argv, options);
  return spawn(plan.file, plan.args, {
    env: options.env,
    cwd: options.cwd,
    stdio: "inherit",
    windowsVerbatimArguments: plan.verbatim,
  });
}

/**
 * Runs a child to completion and resolves to its exit code. Termination signals
 * are forwarded; SIGINT only without a terminal, since a terminal already
 * delivers Ctrl-C to the whole process group.
 */
export function runToCompletion(child: ChildProcess, interactive: boolean): Promise<number> {
  const signals: NodeJS.Signals[] =
    process.platform === "win32"
      ? ["SIGINT", "SIGHUP"]
      : ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];
  const forward = (signal: NodeJS.Signals) => {
    if (signal !== "SIGINT" || !interactive) {
      child.kill(signal);
    }
  };
  const cleanup = () => {
    for (const signal of signals) {
      process.removeListener(signal, forward);
    }
  };
  for (const signal of signals) {
    process.on(signal, forward);
  }

  return new Promise((resolvePromise, reject) => {
    child.once("error", (error) => {
      cleanup();
      const code = (error as NodeJS.ErrnoException).code;
      reject(
        new MsecretsError(
          "USAGE",
          code === "ENOENT"
            ? `Command not found: ${child.spawnfile}`
            : `Failed to start ${child.spawnfile}: ${error.message}`,
          { cause: error },
        ),
      );
    });
    child.once("exit", (code, signal) => {
      cleanup();
      // Conventional shell exit status for a child terminated by a signal.
      resolvePromise(code ?? 128 + (signal ? (constants.signals[signal] ?? 1) : 1));
    });
  });
}
