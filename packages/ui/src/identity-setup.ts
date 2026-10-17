import { execFileSync } from "node:child_process";
import { chmodSync, closeSync, mkdirSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_IDENTITY_FILENAME,
  type Identity,
  MsecretsError,
  type UserConfig,
  armor,
  configDirectory,
  encryptAge,
  formatIdentityFile,
  generateIdentity,
  nameProblem,
  readUserConfig,
  scryptRecipient,
  writeKeychain,
} from "../../core/src/index.ts";
import type { Context } from "./context.ts";
import { ask } from "./terminal.ts";

export type StoreTarget = "keychain" | "file" | "print";

export function parseStoreTarget(value: string | undefined): StoreTarget | undefined {
  if (value === undefined || value === "keychain" || value === "file" || value === "print") {
    return value;
  }
  throw new MsecretsError("USAGE", `Unknown --store "${value}"; use keychain, file, or print`);
}

function writePrivateFile(path: string, text: string): void {
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeSync(descriptor, text);
  } finally {
    closeSync(descriptor);
  }
  // Mode bits passed to open are subject to the umask; enforce owner-only access.
  chmodSync(path, 0o600);
}

export function writeUserConfig(directory: string, config: UserConfig): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(directory, "config.json");
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
  writePrivateFile(temporary, `${JSON.stringify(config, null, 2)}\n`);
  try {
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw new MsecretsError(
      "IDENTITY_SOURCE",
      `Failed to write ${path}: ${(error as Error).message}`,
      {
        cause: error,
      },
    );
  }
}

/** Adds an identity source spec to the developer config (first position wins). */
export function addIdentitySource(context: Context, spec: string): string {
  const directory = configDirectory(context.io.env);
  const config = readUserConfig(directory) ?? { identities: [] };
  if (!config.identities.includes(spec)) {
    config.identities.push(spec);
    writeUserConfig(directory, config);
  }
  return join(directory, "config.json");
}

/** Stores a new identity and returns the source spec that loads it (null when only printed). */
export async function storeIdentity(
  context: Context,
  identity: Identity,
  target: StoreTarget | undefined,
  options: { account?: string; passphrase?: boolean } = {},
): Promise<string | null> {
  const account = options.account ?? "default";

  if (target === "print") {
    context.io.stdout.write(formatIdentityFile(identity));
    return null;
  }

  if (target === "keychain" || (target === undefined && !options.passphrase)) {
    try {
      writeKeychain(account, identity.secret);
      return `keychain:${account}`;
    } catch (error) {
      if (target === "keychain") {
        throw error;
      }
      context.note(
        context.err.dim(
          `OS keychain unavailable (${(error as Error).message}); storing the identity in a file instead`,
        ),
      );
    }
  }

  const directory = configDirectory(context.io.env);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = join(
    directory,
    account === "default" ? DEFAULT_IDENTITY_FILENAME : `identity-${account}.txt`,
  );
  let text = formatIdentityFile(identity);

  if (options.passphrase) {
    const passphrase = await ask(context.io, "New passphrase for the identity file: ", {
      hidden: true,
    });
    if (!passphrase) {
      throw new MsecretsError("USAGE", "The passphrase must not be empty");
    }
    if ((await ask(context.io, "Repeat the passphrase: ", { hidden: true })) !== passphrase) {
      throw new MsecretsError("USAGE", "The passphrases do not match");
    }
    text = armor(encryptAge(Buffer.from(text), [scryptRecipient(passphrase)]));
  }

  try {
    writePrivateFile(path, text);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new MsecretsError("CONFLICT", `${path} already exists; choose another --account`, {
        cause: error,
      });
    }
    throw error;
  }
  return `file:${path}`;
}

export type IdentityChoice = { identity: Identity; created: boolean };

/** Uses the first loaded identity, or creates, stores, and configures a new one. */
export async function ensureIdentity(
  context: Context,
  options: { store?: StoreTarget | undefined; postQuantum?: boolean; passphrase?: boolean },
): Promise<IdentityChoice> {
  const [existing] = await context.identities();
  if (existing) {
    return { identity: existing, created: false };
  }

  const identity = generateIdentity({ postQuantum: options.postQuantum ?? false });
  const spec = await storeIdentity(
    context,
    identity,
    options.store,
    options.passphrase ? { passphrase: true } : {},
  );
  if (spec) {
    const configPath = addIdentitySource(context, spec);
    context.success(
      `Created your identity (${spec.startsWith("keychain:") ? "OS keychain" : spec.slice(5)}), registered in ${configPath}`,
    );
  } else {
    context.note(
      context.err.yellow(
        "Store the identity printed above in your password manager, then run `msecrets identity use <source>`",
      ),
    );
  }
  return { identity, created: true };
}

/** A recipient name for the current user: git user.email, else the OS user name. */
export function defaultRecipientName(cwd: string): string {
  const candidates: string[] = [];
  try {
    candidates.push(
      execFileSync("git", ["config", "user.email"], {
        cwd,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim(),
    );
  } catch {
    // git is optional; fall back to the OS user name.
  }
  try {
    candidates.push(userInfo().username);
  } catch {
    // Some containers have no passwd entry for the current user.
  }

  for (const candidate of candidates) {
    const name = candidate
      .toLowerCase()
      .replace(/[^a-z0-9._@+-]+/g, "-")
      .replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, "")
      .slice(0, 64)
      .replace(/[^a-z0-9]+$/, "");
    if (name && !nameProblem("recipient", name)) {
      return name;
    }
  }
  return "me";
}
