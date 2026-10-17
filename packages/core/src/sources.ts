/**
 * Identity sources: where private keys come from at runtime.
 *
 * Sources never come from the committed secrets file (that would let a
 * repository run commands); they come from code, environment variables, or the
 * developer's own config file.
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

import { planCommand } from "./command.ts";
import { MsecretsError } from "./errors.ts";
import { readKeychain } from "./keychain.ts";
import { type Identity, parseIdentities } from "./keys.ts";

export type LoadedIdentity = {
  identity: Identity;
  /** Where the identity came from (never contains secret material). */
  source: string;
};

export type IdentitySource = {
  readonly label: string;
  load(): LoadedIdentity[];
};

export type SourceOptions = {
  env?: NodeJS.ProcessEnv;
  /** Supplies passphrases for encrypted identity files and SSH keys. */
  passphrase?: (label: string) => string;
  /** Delete identity variables from `env` after reading them (default true). */
  scrub?: boolean;
  configDirectory?: string;
  cwd?: string;
};

export const IDENTITY_VARIABLE = "MSECRETS_IDENTITY";
export const IDENTITY_FILE_VARIABLE = "MSECRETS_IDENTITY_FILE";
export const IDENTITY_SOURCE_VARIABLE = "MSECRETS_IDENTITY_SOURCE";
export const PASSPHRASE_VARIABLE = "MSECRETS_PASSPHRASE";
export const CONTAINER_IDENTITY_NAME = "msecrets_identity";

function parse(
  contents: string | Uint8Array,
  label: string,
  options: SourceOptions,
): LoadedIdentity[] {
  try {
    const passphrase = options.passphrase;
    return parseIdentities(contents, passphrase ? { passphrase: () => passphrase(label) } : {}).map(
      (identity) => ({
        identity,
        source: label,
      }),
    );
  } catch (error) {
    if (error instanceof MsecretsError) {
      throw new MsecretsError(
        error.code === "INVALID_KEY" ? "IDENTITY_SOURCE" : error.code,
        `${label}: ${error.message}`,
        {
          cause: error,
        },
      );
    }
    throw error;
  }
}

/** Passphrase supplier backed by MSECRETS_PASSPHRASE (read once, then scrubbed). */
export function passphraseFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  scrub = true,
): (label: string) => string {
  let passphrase = env[PASSPHRASE_VARIABLE];
  if (scrub) {
    delete env[PASSPHRASE_VARIABLE];
  }
  return (label) => {
    if (passphrase === undefined) {
      throw new MsecretsError(
        "IDENTITY_SOURCE",
        `${label} is passphrase-protected; set ${PASSPHRASE_VARIABLE}`,
      );
    }
    return passphrase;
  };
}

export function fromString(
  text: string,
  label = "inline identity",
  options: SourceOptions = {},
): IdentitySource {
  return { label, load: () => parse(text, label, options) };
}

/** Reads identities from an environment variable and, by default, deletes it so child processes never see it. */
export function fromEnv(
  variable: string = IDENTITY_VARIABLE,
  options: SourceOptions = {},
): IdentitySource {
  const label = `env ${variable}`;
  return {
    label,
    load() {
      const env = options.env ?? process.env;
      const text = env[variable];
      if (options.scrub ?? true) {
        delete env[variable];
      }
      return text?.trim() ? parse(text, label, options) : [];
    },
  };
}

function expandHome(path: string): string {
  return path === "~" || path.startsWith("~/") || path.startsWith("~\\")
    ? join(homedir(), path.slice(1))
    : path;
}

export function fromFile(
  path: string,
  options: SourceOptions & { optional?: boolean } = {},
): IdentitySource {
  const fullPath = resolve(options.cwd ?? process.cwd(), expandHome(path));
  const label = `file ${fullPath}`;
  return {
    label,
    load() {
      let contents: Buffer;
      try {
        contents = readFileSync(fullPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT" && options.optional) {
          return [];
        }
        throw new MsecretsError("IDENTITY_SOURCE", `${label}: ${(error as Error).message}`, {
          cause: error,
        });
      }
      // Bytes, not text: a passphrase-protected identity file may be binary age.
      return parse(contents, label, options);
    },
  };
}

/** Runs a command (password manager CLI) whose standard output is the identity. */
export function fromCommand(
  argv: readonly string[],
  options: SourceOptions & { label?: string; firstLine?: boolean } = {},
): IdentitySource {
  const [command, ...args] = argv;
  if (!command) {
    throw new MsecretsError("USAGE", "An identity command must not be empty");
  }
  const label = options.label ?? `command \`${argv.join(" ")}\``;
  return {
    label,
    load() {
      const env = options.env ?? process.env;
      const plan = planCommand([command, ...args], { env, cwd: options.cwd ?? process.cwd() });
      const result = spawnSync(plan.file, plan.args, {
        encoding: "utf8",
        // Password managers may prompt for unlock on the terminal.
        stdio: ["inherit", "pipe", "inherit"],
        timeout: 120_000,
        windowsHide: true,
        windowsVerbatimArguments: plan.verbatim,
        maxBuffer: 1024 * 1024,
        env,
        ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
      });
      if (result.error) {
        const missing = (result.error as NodeJS.ErrnoException).code === "ENOENT";
        throw new MsecretsError(
          "IDENTITY_SOURCE",
          missing
            ? `${label}: \`${command}\` is not installed or not on PATH`
            : `${label} failed: ${result.error.message}`,
          { cause: result.error },
        );
      }
      if (result.status !== 0) {
        throw new MsecretsError(
          "IDENTITY_SOURCE",
          `${label} failed (exit code ${result.status ?? result.signal})`,
        );
      }
      const output = result.stdout;
      // `pass` and similar tools keep the secret on the first line and metadata below it.
      return parse(options.firstLine ? (output.split(/\r?\n/)[0] ?? "") : output, label, options);
    },
  };
}

export function fromKeychain(account = "default"): IdentitySource {
  const label = `OS keychain (${account})`;
  return {
    label,
    load() {
      const secret = readKeychain(account);
      if (secret === null) {
        throw new MsecretsError(
          "IDENTITY_SOURCE",
          `${label}: no msecrets identity stored for account "${account}"`,
        );
      }
      return parse(secret, label, {});
    },
  };
}

/** Splits a command line on whitespace, honoring single and double quotes. */
export function splitCommandLine(line: string): string[] {
  const tokens: string[] = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  for (const match of line.matchAll(pattern)) {
    tokens.push(match[1] ?? match[2] ?? match[3] ?? "");
  }
  return tokens;
}

function looksLikePath(spec: string): boolean {
  return isAbsolute(spec) || /^(?:\.{1,2}[\\/]|~(?:[\\/]|$))/.test(spec);
}

/**
 * Parses an identity source spec:
 * - `env:NAME`, `file:PATH` (or a bare path), `keychain:ACCOUNT`
 * - `op://vault/item/field` (1Password), `bw:ITEM` (Bitwarden), `pass:NAME` (pass)
 * - `cmd:COMMAND ARGS…` (any command printing the identity)
 */
export function parseSourceSpec(spec: string, options: SourceOptions = {}): IdentitySource {
  const trimmed = spec.trim();
  const [scheme = "", ...rest] = trimmed.split(":");
  const value = rest.join(":");

  if (trimmed.startsWith("op://")) {
    return fromCommand(["op", "read", "--no-newline", trimmed], {
      ...options,
      label: `1Password ${trimmed}`,
    });
  }
  if (looksLikePath(trimmed)) {
    return fromFile(trimmed, options);
  }

  switch (scheme) {
    case "env":
      return fromEnv(value, options);
    case "file":
      return fromFile(value, options);
    case "keychain":
      return fromKeychain(value || "default");
    case "bw":
      return fromCommand(["bw", "get", "password", value], {
        ...options,
        label: `Bitwarden ${value}`,
      });
    case "pass":
      return fromCommand(["pass", "show", value], {
        ...options,
        label: `pass ${value}`,
        firstLine: true,
      });
    case "cmd":
      return fromCommand(splitCommandLine(value), options);
    default:
      throw new MsecretsError(
        "USAGE",
        `Unknown identity source "${trimmed}"; use env:, file:, keychain:, op://, bw:, pass:, cmd:, or a path`,
      );
  }
}

/**
 * Makes a source spec independent of the working directory, for the user
 * config: relative file paths become absolute. Other specs are unchanged.
 */
export function absoluteSourceSpec(spec: string, cwd: string): string {
  const trimmed = spec.trim();
  const path = trimmed.startsWith("file:")
    ? trimmed.slice("file:".length)
    : !trimmed.startsWith("op://") && looksLikePath(trimmed)
      ? trimmed
      : undefined;
  return path === undefined || /^~(?:[\\/]|$)/.test(path) ? trimmed : `file:${resolve(cwd, path)}`;
}

// Developer configuration

export type UserConfig = {
  /** Identity source specs, tried in order. */
  identities: string[];
};

export function configDirectory(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): string {
  if (env["MSECRETS_CONFIG_DIR"]) {
    return env["MSECRETS_CONFIG_DIR"];
  }
  if (platform === "win32" && env["APPDATA"]) {
    return join(env["APPDATA"], "msecrets");
  }
  return join(env["XDG_CONFIG_HOME"] || join(homedir(), ".config"), "msecrets");
}

export function readUserConfig(directory: string): UserConfig | null {
  const path = join(directory, "config.json");
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw error;
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (error) {
    throw new MsecretsError("IDENTITY_SOURCE", `Invalid ${path}: ${(error as Error).message}`, {
      cause: error,
    });
  }
  const identities = (json as { identities?: unknown } | null)?.identities;
  if (!Array.isArray(identities) || !identities.every((entry) => typeof entry === "string")) {
    throw new MsecretsError(
      "IDENTITY_SOURCE",
      `Invalid ${path}: "identities" must be an array of identity source strings`,
    );
  }
  return { identities };
}

export const DEFAULT_IDENTITY_FILENAME = "identity.txt";

/**
 * The default identity chain.
 *
 * 1. Explicit runtime configuration: MSECRETS_IDENTITY, MSECRETS_IDENTITY_FILE,
 *    MSECRETS_IDENTITY_SOURCE, and container secrets (/run/secrets/msecrets_identity,
 *    $CREDENTIALS_DIRECTORY/msecrets_identity).
 * 2. Only if none of those yields an identity: the developer config
 *    (`identities` in config.json), or else the default identity file.
 */
export function autoSource(options: SourceOptions = {}): IdentitySource {
  return {
    label: "default identity sources",
    load() {
      const env = options.env ?? process.env;
      const shared = {
        ...options,
        env,
        passphrase: options.passphrase ?? passphraseFromEnv(env, options.scrub ?? true),
      };

      const runtime: IdentitySource[] = [fromEnv(IDENTITY_VARIABLE, shared)];
      const identityFile = env[IDENTITY_FILE_VARIABLE];
      if (identityFile) {
        runtime.push(fromFile(identityFile, shared));
      }
      const sourceSpec = env[IDENTITY_SOURCE_VARIABLE];
      if (sourceSpec) {
        runtime.push(parseSourceSpec(sourceSpec, shared));
      }
      if (process.platform !== "win32") {
        runtime.push(
          fromFile(`/run/secrets/${CONTAINER_IDENTITY_NAME}`, { ...shared, optional: true }),
        );
      }
      if (env["CREDENTIALS_DIRECTORY"]) {
        runtime.push(
          fromFile(join(env["CREDENTIALS_DIRECTORY"], CONTAINER_IDENTITY_NAME), {
            ...shared,
            optional: true,
          }),
        );
      }

      const fromRuntime = runtime.flatMap((source) => source.load());
      if (fromRuntime.length) {
        return fromRuntime;
      }

      const directory = options.configDirectory ?? configDirectory(env);
      const config = readUserConfig(directory);
      if (config) {
        return config.identities.flatMap((spec) => parseSourceSpec(spec, shared).load());
      }
      return fromFile(join(directory, DEFAULT_IDENTITY_FILENAME), {
        ...shared,
        optional: true,
      }).load();
    },
  };
}

export function loadIdentities(sources: readonly IdentitySource[]): LoadedIdentity[] {
  const loaded = sources.flatMap((source) => source.load());
  // The same key may be configured twice; keep the first occurrence.
  return loaded.filter(
    (entry, index) =>
      loaded.findIndex((other) =>
        other.identity.publicKey.encryptionKey.equals(entry.identity.publicKey.encryptionKey),
      ) === index,
  );
}
