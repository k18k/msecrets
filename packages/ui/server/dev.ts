import http from "node:http";
import { createServer as createViteServer } from "vite";
import { RPCHandler } from "@orpc/server/node";
import { router } from "./orpc.ts";
import viteConfig from "../vite.config.ts";
import { getDevRuntimeOptions } from "./lib/runtime-options.server.ts";

const handler = new RPCHandler(router);
const runtimeOptions = getDevRuntimeOptions();

const parentServer = http.createServer();

const vite = await createViteServer(viteConfig);

parentServer.on("request", async (req, res) => {
  const { matched } = await handler.handle(req, res, {
    prefix: "/rpc",
  });

  if (matched) {
    return;
  }

  if (!req.url) {
    res.statusCode = 400;
    res.end("Missing URL");
    return;
  }

  if (req.url.startsWith("/api/")) {
    if (req.url === "/api/health") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.statusCode = 404;
    res.end("API route not found");
    return;
  }

  vite.middlewares(req, res, (err?: unknown) => {
    if (err) {
      vite.ssrFixStacktrace(err as Error);
      res.statusCode = 500;
      res.end(String(err));
      return;
    }

    res.statusCode = 404;
    res.end("Not found");
  });
});

parentServer.once("error", (error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to start development server: ${message}`);
  process.exit(1);
});

parentServer.listen(runtimeOptions.port, runtimeOptions.host, () => {
  console.log(`http://${runtimeOptions.host}:${runtimeOptions.port}`);
  console.log(`Using config: ${runtimeOptions.configPath}`);
});
