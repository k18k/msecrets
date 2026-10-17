import { type ChildProcess, spawn } from "node:child_process";
import { constants } from "node:os";

import { MsecretsError, planCommand } from "../../core/src/index.ts";

/** Spawns a command with inherited stdio. */
export function spawnCommand(
  argv: readonly string[],
  options: { env: NodeJS.ProcessEnv; cwd: string },
): ChildProcess {
  if (!argv.length) {
    throw new MsecretsError(
      "USAGE",
      "No command given; usage: msecrets run [--env NAME] -- <command> [args...]",
    );
  }
  const plan = planCommand(argv, options);
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
