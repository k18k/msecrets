import { spawn, spawnSync } from "node:child_process";
import { accessSync, constants, mkdirSync, readFileSync } from "node:fs";
import { request as createHttpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createConnection, createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { cwd, env, platform } from "node:process";

import { Command } from "commander";

import { getConfigPath } from "#cli/program.ts";

const LOCAL_UI_HOST = "127.0.0.1";
const DEFAULT_UI_PORT = 2345;
const MAX_PORT_ATTEMPTS = 20;
const WORKSPACE_UI_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), "../../../ui");

type UiRuntime = {
  directory: string;
  mode: "packaged" | "workspace";
  serverEntry: string;
};

function getAbsoluteConfigPath(): string {
  return resolve(cwd(), getConfigPath());
}

function hasBuiltUi(uiDirectory: string): boolean {
  try {
    accessSync(resolve(uiDirectory, "dist", "client", "index.html"), constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function resolveFirstReadablePath(baseDirectory: string, candidates: string[]): string | null {
  for (const candidate of candidates) {
    const fullPath = resolve(baseDirectory, candidate);
    if (hasReadableFile(fullPath)) {
      return fullPath;
    }
  }

  return null;
}

function hasReadableFile(filePath: string): boolean {
  try {
    accessSync(filePath, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function resolveUiRuntime(): UiRuntime {
  const packagedUiDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "ui");
  const packagedServerEntry = resolveFirstReadablePath(packagedUiDirectory, [
    "server.js",
    "start.mjs",
    "dist/start.mjs",
  ]);

  if (packagedServerEntry && hasBuiltUi(packagedUiDirectory)) {
    return {
      directory: packagedUiDirectory,
      mode: "packaged",
      serverEntry: packagedServerEntry,
    };
  }

  const workspaceServerEntry = resolve(WORKSPACE_UI_DIRECTORY, "server", "start.ts");

  if (hasReadableFile(workspaceServerEntry)) {
    return {
      directory: WORKSPACE_UI_DIRECTORY,
      mode: "workspace",
      serverEntry: workspaceServerEntry,
    };
  }

  throw new Error("Could not locate the msecrets UI runtime.");
}

function commandExists(command: string): boolean {
  const commandCheck = spawnSync(command, ["--help"], {
    stdio: "ignore",
  });

  return !commandCheck.error;
}

function getHttpsCertificatePaths(): {
  certPath: string;
  directory: string;
  keyPath: string;
} {
  const directory = resolve(
    env["MSECRETS_CERT_DIRECTORY"] ?? resolve(homedir(), ".msecrets", "certs"),
  );

  return {
    certPath: resolve(directory, "localhost.crt"),
    directory,
    keyPath: resolve(directory, "localhost.key"),
  };
}

function tryGenerateCertificateWithMkcert(certPath: string, keyPath: string): boolean {
  if (!commandExists("mkcert")) {
    return false;
  }

  const generation = spawnSync(
    "mkcert",
    ["-cert-file", certPath, "-key-file", keyPath, "localhost", "127.0.0.1", "::1"],
    {
      stdio: "ignore",
    },
  );

  return generation.status === 0 && hasReadableFile(certPath) && hasReadableFile(keyPath);
}

function tryGenerateCertificateWithOpenSsl(certPath: string, keyPath: string): boolean {
  if (!commandExists("openssl")) {
    return false;
  }

  const generation = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "3650",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ],
    {
      stdio: "ignore",
    },
  );

  return generation.status === 0 && hasReadableFile(certPath) && hasReadableFile(keyPath);
}

function ensureHttpsCertificate(): { certPath: string; keyPath: string } {
  const { certPath, directory, keyPath } = getHttpsCertificatePaths();

  mkdirSync(directory, {
    recursive: true,
  });

  if (hasReadableFile(certPath) && hasReadableFile(keyPath)) {
    return {
      certPath,
      keyPath,
    };
  }

  if (
    tryGenerateCertificateWithMkcert(certPath, keyPath) ||
    tryGenerateCertificateWithOpenSsl(certPath, keyPath)
  ) {
    return {
      certPath,
      keyPath,
    };
  }

  throw new Error(
    "Could not create an HTTPS certificate automatically. Install `mkcert` or `openssl` and retry.",
  );
}

function checkPortAvailability(port: number): Promise<boolean> {
  return new Promise((resolveAvailability) => {
    const server = createServer();
    server.unref();

    server.once("error", () => {
      resolveAvailability(false);
    });

    server.listen(port, "127.0.0.1", () => {
      server.close(() => {
        resolveAvailability(true);
      });
    });
  });
}

async function findAvailablePort(startingPort: number): Promise<number> {
  for (let port = startingPort; port < startingPort + MAX_PORT_ATTEMPTS; port += 1) {
    if (await checkPortAvailability(port)) {
      return port;
    }
  }

  throw new Error(
    `Could not find an open port between ${startingPort} and ${startingPort + MAX_PORT_ATTEMPTS - 1}`,
  );
}

async function waitForPort(port: number, timeoutMs = 15000): Promise<void> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const isReachable = await new Promise<boolean>((resolveReachable) => {
      const socket = createConnection({
        host: LOCAL_UI_HOST,
        port,
      });

      socket.once("connect", () => {
        socket.end();
        resolveReachable(true);
      });

      socket.once("error", () => {
        resolveReachable(false);
      });
    });

    if (isReachable) {
      return;
    }

    await new Promise((resolveDelay) => {
      setTimeout(resolveDelay, 100);
    });
  }

  throw new Error(`Timed out while waiting for the UI server on port ${port}.`);
}

function openBrowser(url: string) {
  const command = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const commandArgs =
    platform === "darwin" ? [url] : platform === "win32" ? ["/c", "start", "", url] : [url];

  try {
    const browserProcess = spawn(command, commandArgs, {
      detached: true,
      stdio: "ignore",
    });
    browserProcess.unref();
    browserProcess.on("error", () => {
      // Best-effort browser opening only.
    });
  } catch {
    // Best-effort browser opening only.
  }
}

export const uiCommand = new Command()
  .command("ui")
  .description("Launch the built msecrets UI")
  .option("-p, --port <port>", "Preferred UI port", String(DEFAULT_UI_PORT))
  .option("--no-open", "Do not open a browser automatically")
  .action(async (options: { open?: boolean; port?: string }) => {
    const uiRuntime = resolveUiRuntime();
    const uiDirectory = uiRuntime.directory;
    const configPath = getAbsoluteConfigPath();
    const { certPath, keyPath } = ensureHttpsCertificate();
    const preferredPort = Number(options.port ?? DEFAULT_UI_PORT);

    if (!Number.isInteger(preferredPort) || preferredPort < 1 || preferredPort > 65535) {
      throw new Error(`Invalid UI port: ${options.port ?? ""}`);
    }

    if (!hasBuiltUi(uiDirectory)) {
      throw new Error(
        uiRuntime.mode === "packaged"
          ? "The packaged UI build is missing from this CLI runtime."
          : "UI build is missing. Run `npm --workspace @msecrets/ui run build` and retry.",
      );
    }

    const port = await findAvailablePort(preferredPort);
    const upstreamPort = await findAvailablePort(port + 1);
    const url = `https://${LOCAL_UI_HOST}:${port}`;
    const serverProcess = spawn(
      process.execPath,
      [uiRuntime.serverEntry, configPath, "--port", String(upstreamPort)],
      {
        cwd: uiDirectory,
        env: {
          ...env,
        },
        stdio: "inherit",
      },
    );

    await new Promise<void>((resolveSpawn, rejectSpawn) => {
      serverProcess.once("spawn", resolveSpawn);
      serverProcess.once("error", rejectSpawn);
    });

    await waitForPort(upstreamPort);

    const httpsServer = createHttpsServer(
      {
        cert: readFileSync(certPath),
        key: readFileSync(keyPath),
      },
      (incomingRequest, outgoingResponse) => {
        const proxyRequest = createHttpRequest(
          {
            host: LOCAL_UI_HOST,
            port: upstreamPort,
            path: incomingRequest.url,
            method: incomingRequest.method,
            headers: {
              ...incomingRequest.headers,
              host: `${LOCAL_UI_HOST}:${upstreamPort}`,
            },
          },
          (proxyResponse) => {
            outgoingResponse.writeHead(proxyResponse.statusCode ?? 502, proxyResponse.headers);
            proxyResponse.pipe(outgoingResponse);
          },
        );

        proxyRequest.once("error", () => {
          if (!outgoingResponse.headersSent) {
            outgoingResponse.writeHead(502);
          }

          outgoingResponse.end("msecrets UI proxy error");
        });

        incomingRequest.pipe(proxyRequest);
      },
    );

    await new Promise<void>((resolveListen, rejectListen) => {
      httpsServer.once("error", rejectListen);
      httpsServer.listen(port, LOCAL_UI_HOST, () => {
        httpsServer.off("error", rejectListen);
        resolveListen();
      });
    });

    let closeHttpsServerPromise: Promise<void> | null = null;
    const closeHttpsServer = () => {
      if (!closeHttpsServerPromise) {
        closeHttpsServerPromise = new Promise<void>((resolveClose, rejectClose) => {
          httpsServer.close((error) => {
            if (error) {
              rejectClose(error);
              return;
            }

            resolveClose();
          });
        });
      }

      return closeHttpsServerPromise;
    };

    console.log(`msecrets UI: ${url}`);
    console.log(`Using config: ${configPath}`);
    console.log(`HTTPS cert: ${certPath}`);

    if (options.open !== false) {
      openBrowser(url);
    }

    const forwardSignalAndClose = (signal: NodeJS.Signals) => {
      void closeHttpsServer().catch(() => {});

      if (!serverProcess.killed) {
        serverProcess.kill(signal);
      }
    };

    process.once("SIGINT", () => forwardSignalAndClose("SIGINT"));
    process.once("SIGTERM", () => forwardSignalAndClose("SIGTERM"));

    const exitCode = await new Promise<number>((resolveExit, rejectExit) => {
      serverProcess.once("error", rejectExit);
      serverProcess.once("exit", (code) => {
        resolveExit(code ?? 1);
      });
    });

    await closeHttpsServer();
    process.exitCode = exitCode;
  });
