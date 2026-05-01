import assert from "node:assert";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { test } from "node:test";

const uiDirectory = resolve(import.meta.dirname);
const builtClientIndex = resolve(uiDirectory, "dist/client/index.html");

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
    const probe = createServer();

    probe.once("error", rejectPort);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      if (!address || typeof address === "string") {
        probe.close(() => {
          rejectPort(new Error("Could not resolve random open port"));
        });
        return;
      }

      const { port } = address;
      probe.close((error) => {
        if (error) {
          rejectPort(error);
          return;
        }

        resolvePort(port);
      });
    });
  });
}

function waitForOutput(
  stream: { value: string },
  predicate: (value: string) => boolean,
  timeoutMs = 15_000,
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

function getHttps(pathname: string, port: number): Promise<{ body: string; statusCode: number }> {
  return new Promise((resolveRequest, rejectRequest) => {
    const request = httpsRequest(
      {
        host: "127.0.0.1",
        method: "GET",
        path: pathname,
        port,
        rejectUnauthorized: false,
      },
      (response) => {
        const chunks: Buffer[] = [];

        response.on("data", (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });

        response.on("end", () => {
          resolveRequest({
            body: Buffer.concat(chunks).toString("utf8"),
            statusCode: response.statusCode ?? 0,
          });
        });
      },
    );

    request.once("error", rejectRequest);
    request.end();
  });
}

test(
  "ui server uses first positional config arg and binds to 127.0.0.1",
  { skip: !existsSync(builtClientIndex), timeout: 30_000 },
  async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "msecrets-ui-e2e-"));
    const configPath = join(tempDir, "secrets.ms.json");
    const port = await findOpenPort();
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

    const child = spawn(process.execPath, ["./server/start.ts", configPath, "--port", String(port)], {
      cwd: uiDirectory,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const appendOutput = (chunk: Buffer | string) => {
      output.value += chunk.toString();
    };

    child.stdout.on("data", appendOutput);
    child.stderr.on("data", appendOutput);

    try {
      await waitForOutput(output, (value) => value.includes(`https://127.0.0.1:${port}`));

      assert.ok(output.value.includes(`Using config: ${configPath}`));

      const response = await getHttps("/", port);
      assert.equal(response.statusCode, 200);
      assert.ok(response.body.includes("<html"));
    } finally {
      child.kill("SIGTERM");
      await waitForExit(child);
    }
  },
);
