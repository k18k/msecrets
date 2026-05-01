import { resolve } from "node:path";

const DEFAULT_CONFIG_PATH = ".env.ms.json";
const DEFAULT_PROD_PORT = 9842;
const DEFAULT_DEV_PORT = 3000;
const LOCALHOST_HOST = "127.0.0.1";

type RuntimeMode = "dev" | "prod";

export type UiRuntimeOptions = {
  configPath: string;
  host: string;
  port: number;
};

function parsePort(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error(`Invalid port: ${value}`);
  }

  const port = Number(value);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port: ${value}`);
  }

  return port;
}

function parseRuntimeOptions(args: string[], mode: RuntimeMode): UiRuntimeOptions {
  let configPath: string | undefined;
  let port = mode === "prod" ? DEFAULT_PROD_PORT : DEFAULT_DEV_PORT;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];

    if (!argument) {
      continue;
    }

    if (argument === "--") {
      continue;
    }

    if (argument === "-p" || argument === "--port") {
      const next = args[index + 1];
      if (!next) {
        throw new Error("Missing value for --port");
      }

      port = parsePort(next);
      index += 1;
      continue;
    }

    if (argument.startsWith("--port=")) {
      const rawPort = argument.slice("--port=".length);
      if (!rawPort) {
        throw new Error("Missing value for --port");
      }

      port = parsePort(rawPort);
      continue;
    }

    if (argument.startsWith("-")) {
      throw new Error(`Unknown option: ${argument}`);
    }

    if (!configPath) {
      configPath = argument;
      continue;
    }

    throw new Error(`Unexpected extra argument: ${argument}`);
  }

  return {
    configPath: resolve(process.cwd(), configPath ?? DEFAULT_CONFIG_PATH),
    host: LOCALHOST_HOST,
    port,
  };
}

let cachedProdOptions: UiRuntimeOptions | null = null;
let cachedDevOptions: UiRuntimeOptions | null = null;

export function getProdRuntimeOptions(argv = process.argv.slice(2)): UiRuntimeOptions {
  if (!cachedProdOptions) {
    cachedProdOptions = parseRuntimeOptions(argv, "prod");
  }

  return cachedProdOptions;
}

export function getDevRuntimeOptions(argv = process.argv.slice(2)): UiRuntimeOptions {
  if (!cachedDevOptions) {
    cachedDevOptions = parseRuntimeOptions(argv, "dev");
  }

  return cachedDevOptions;
}
