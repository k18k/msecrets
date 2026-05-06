import assert from "node:assert";
import { spawnSync } from "node:child_process";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const repoRoot = resolve(import.meta.dirname, "../..");
const cliEntry = resolve(import.meta.dirname, "src/index.ts");

function waitForExit(child: import("node:child_process").ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.killed) {
    return Promise.resolve();
  }

  return new Promise((resolveExit) => {
    child.once("exit", () => resolveExit());
  });
}

function findOpenPort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();

    server.once("error", rejectPort);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();

      if (!address || typeof address === "string") {
        server.close(() => {
          rejectPort(new Error("Could not resolve random open port"));
        });
        return;
      }

      const { port } = address;
      server.close((error) => {
        if (error) {
          rejectPort(error);
          return;
        }

        resolvePort(port);
      });
    });
  });
}

function isLoopbackBindDenied(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "EPERM";
}

function waitForOutput(
  stream: { value: string },
  predicate: (value: string) => boolean,
  timeoutMs = 20_000,
): Promise<void> {
  return new Promise((resolveWait, rejectWait) => {
    const startedAt = Date.now();

    const interval = setInterval(() => {
      if (predicate(stream.value)) {
        clearInterval(interval);
        resolveWait();
        return;
      }

      if (Date.now() - startedAt >= timeoutMs) {
        clearInterval(interval);
        rejectWait(new Error(`Timed out waiting for expected output.\n${stream.value}`));
      }
    }, 25);

    interval.unref();
  });
}

test("cli package entrypoint creates a versioned secrets file", { timeout: 10_000 }, () => {
  const workdir = mkdtempSync(join(tmpdir(), "msecrets-cli-test-"));
  const configPath = join(workdir, ".env.ci.json");

  const firstRun = spawnSync(process.execPath, [cliEntry, "--config", configPath, "init"], {
    cwd: repoRoot,
    encoding: "utf8",
  });

  assert.equal(firstRun.status, 0, firstRun.stderr);
  assert.equal(existsSync(configPath), true);

  const parsed = JSON.parse(readFileSync(configPath, "utf8")) as {
    version: string;
    environments: string[];
  };

  assert.equal(parsed.version, "2.0.0");
  assert.deepEqual(parsed.environments, ["development"]);

  const secondRun = spawnSync(process.execPath, [cliEntry, "--config", configPath, "init"], {
    cwd: repoRoot,
    encoding: "utf8",
  });

  assert.equal(secondRun.status, 0, secondRun.stderr);
});

test(
  "cli ui command launches local ui endpoint without auto-build",
  { skip: !existsSync(resolve(repoRoot, "packages/ui/dist/client/index.html")), timeout: 30_000 },
  async (t) => {
    const workdir = mkdtempSync(join(tmpdir(), "msecrets-cli-ui-test-"));
    const configPath = join(workdir, "secrets.ms.json");
    let preferredPort: number;
    try {
      preferredPort = await findOpenPort();
    } catch (error) {
      if (isLoopbackBindDenied(error)) {
        t.skip("127.0.0.1 binding is not permitted in this environment");
        return;
      }

      throw error;
    }
    const output = { value: "" };

    writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          version: "2.0.0",
          environments: ["development"],
          keys: [],
          secrets: {},
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const child = spawn(
      process.execPath,
      [cliEntry, "--config", configPath, "ui", "--no-open", "--port", String(preferredPort)],
      {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const appendOutput = (chunk: Buffer | string) => {
      output.value += chunk.toString();
    };

    child.stdout.on("data", appendOutput);
    child.stderr.on("data", appendOutput);

    try {
      await waitForOutput(output, (value) =>
        value.includes(`msecrets UI: https://127.0.0.1:${preferredPort}`),
      );

      assert.ok(output.value.includes(`Using config: ${configPath}`));
    } finally {
      child.kill("SIGTERM");
      await waitForExit(child);
    }
  },
);
