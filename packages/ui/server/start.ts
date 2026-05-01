#!/usr/bin/env node
import { createServer } from "node:https";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { createThrowawayCertificate } from "./cert.ts";
import { RPCHandler } from "@orpc/server/node";
import { router } from "./orpc.ts";
import { onError } from "@orpc/server";
import { getProdRuntimeOptions } from "./lib/runtime-options.server.ts";

const { cert, key } = createThrowawayCertificate();
const runtimeOptions = getProdRuntimeOptions();

const timer = setTimeout(gracefulExit, 120_000);

const handler = new RPCHandler(router, {
  interceptors: [
    async ({ next }) => {
      timer.refresh();
      return await next();
    },
    onError((error) => {
      console.error(error);
    }),
  ],
});

const distDir = resolve(import.meta.dirname, '..', "./dist/client");
const indexHtmlPath = join(distDir, "index.html");

const contentTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".wasm": "application/wasm",
};

async function sendFile(
  res: import("node:http").ServerResponse,
  filePath: string,
  method: string,
) {
  const fileStat = await stat(filePath);

  if (!fileStat.isFile()) {
    res.statusCode = 404;
    res.end("Not Found");
    return;
  }

  res.statusCode = 200;
  res.setHeader(
    "content-type",
    contentTypes[extname(filePath)] ?? "application/octet-stream",
  );
  res.setHeader("content-length", String(fileStat.size));

  if (method === "HEAD") {
    res.end();
    return;
  }

  createReadStream(filePath).pipe(res);
}

const server = createServer({ cert, key }, async (req, res) => {
  try {
    const { matched } = await handler.handle(req, res, {
      prefix: "/rpc",
    });

    if (matched) return;

    if (!req.url) {
      res.statusCode = 400;
      res.end("Missing URL");
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.statusCode = 405;
      res.end("Method Not Allowed");
      return;
    }

    const url = new URL(req.url, "https://localhost");
    const pathname = decodeURIComponent(url.pathname);

    const requestedPath = normalize(
      pathname === "/" ? "/index.html" : pathname,
    );
    const filePath = resolve(join(distDir, requestedPath));

    if (!filePath.startsWith(distDir + "/") && filePath !== distDir) {
      res.statusCode = 403;
      res.end("Forbidden");
      return;
    }

    try {
      await sendFile(res, filePath, req.method);
      return;
    } catch {
      // SPA fallback.
      await sendFile(res, indexHtmlPath, req.method);
      return;
    }
  } catch (error) {
    console.error(error);

    if (!res.headersSent) {
      res.statusCode = 500;
      res.end("Internal Server Error");
    } else {
      res.destroy();
    }
  }
});

try {
  server.listen(runtimeOptions.port, runtimeOptions.host, () => {
    console.log(`Server is listening on https://${runtimeOptions.host}:${runtimeOptions.port}`);
    console.log(`Using config: ${runtimeOptions.configPath}`);
  });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to start UI server: ${message}`);
  process.exit(1);
}

function gracefulExit() {
  console.log("Shutting down server...");
  server.close(() => {
    console.log("Server has been shut down.");
    process.exit(0);
  });
}
