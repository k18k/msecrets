import {
  type IdentitySource,
  type LoadedIdentity,
  MsecretsError,
  type SecretsDocument,
  autoSource,
  chooseEnvironment,
  fromString,
  loadIdentities,
  own,
  parseDocument,
  parseSourceSpec,
  readDocumentFile,
  resolveDocumentFile,
  revealValue,
  secretEnvironments,
  suggest,
} from "../../core/src/index.ts";

export {
  type ErrorCode,
  type IdentitySource,
  type LoadedIdentity,
  MsecretsError,
  autoSource,
  fromCommand,
  fromEnv,
  fromFile,
  fromKeychain,
  fromString,
  isMsecretsError,
  parseSourceSpec,
} from "../../core/src/index.ts";

/** Anything shaped like a parsed `msecrets.json`, e.g. `import file from "./msecrets.json" with { type: "json" }`. */
export type SecretsFileLike = { secrets: object };

export type ClientOptions = {
  /**
   * The parsed secrets file (a JSON import gives typed secret names) or a path to it.
   * Default: MSECRETS_FILE, else `msecrets.json` in the working directory or its parents.
   */
  file?: SecretsFileLike | string;
  /** Environment. Default: MSECRETS_ENV, else "development" if it exists, else the only environment. */
  env?: string;
  /**
   * Identity sources, tried together. Strings are source specs (`env:NAME`, `file:PATH`,
   * `keychain:ACCOUNT`, `op://…`, `bw:ITEM`, `pass:NAME`, `cmd:…`) or raw identities.
   * Default: the automatic chain (MSECRETS_IDENTITY, MSECRETS_IDENTITY_FILE,
   * MSECRETS_IDENTITY_SOURCE, container secrets, then the developer config).
   */
  identities?: readonly (IdentitySource | string)[];
  /** Working directory used to find the secrets file. */
  cwd?: string;
};

export type Client<Name extends string = string> = {
  /** The environment this client reads. */
  readonly environment: string;
  /** Secret names that have a value in this environment. */
  keys(): Name[];
  /** Whether the secret has a value in this environment. */
  has(name: string): name is Name;
  /** Verifies and decrypts one value. Throws if it is missing, tampered with, or unreadable. */
  get(name: Name): string;
  /**
   * Verifies and decrypts every secret of this environment. Throws when any
   * secret that applies to the environment has no value, so a running app
   * always gets the complete set.
   */
  all(): Readonly<Record<Name, string>>;
  /** Where each loaded identity came from (for diagnostics; contains no secrets). */
  identities(): string[];
};

type SecretNames<F extends SecretsFileLike> = Extract<keyof F["secrets"], string>;

function toSource(entry: IdentitySource | string, cwd: string | undefined): IdentitySource {
  if (typeof entry !== "string") {
    return entry;
  }
  const trimmed = entry.trim();
  return /^AGE-SECRET-KEY-|^-----BEGIN /i.test(trimmed)
    ? fromString(trimmed)
    : parseSourceSpec(trimmed, cwd === undefined ? {} : { cwd });
}

function loadDocument(options: ClientOptions): { document: SecretsDocument; label: string } {
  if (options.file !== undefined && typeof options.file !== "string") {
    return { document: parseDocument(options.file), label: "secrets file" };
  }
  const path = resolveDocumentFile({
    file: options.file,
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
  });
  return { document: readDocumentFile(path), label: path };
}

/**
 * Creates a client for one environment of a secrets file. Everything is
 * synchronous; identities are loaded on first decryption.
 */
export function createClient<F extends SecretsFileLike>(
  options: ClientOptions & { file: F },
): Client<SecretNames<F>>;
export function createClient(options?: ClientOptions): Client;
export function createClient(options: ClientOptions = {}): Client {
  const { document, label } = loadDocument(options);
  const environment = chooseEnvironment(document, options.env).name;
  const sources = options.identities?.map((entry) => toSource(entry, options.cwd)) ?? [
    autoSource(),
  ];
  const cache = new Map<string, string>();
  let loaded: LoadedIdentity[] | undefined;

  const applicable = () =>
    Object.keys(document.secrets).filter((name) => {
      const secret = own(document.secrets, name);
      return secret !== undefined && secretEnvironments(document, secret).includes(environment);
    });

  const identities = (): LoadedIdentity[] => {
    if (!loaded) {
      loaded = loadIdentities(sources);
      if (!loaded.length) {
        throw new MsecretsError(
          "IDENTITY_SOURCE",
          `No msecrets identity found to decrypt ${label}. Set MSECRETS_IDENTITY (or MSECRETS_IDENTITY_FILE / MSECRETS_IDENTITY_SOURCE), mount /run/secrets/msecrets_identity, or run \`msecrets init\` on a developer machine`,
        );
      }
    }
    return loaded;
  };

  const has = (name: string): boolean => {
    const secret = own(document.secrets, name);
    return (
      secret !== undefined &&
      secretEnvironments(document, secret).includes(environment) &&
      own(secret.values, environment) !== undefined
    );
  };

  const get = (name: string): string => {
    const cached = cache.get(name);
    if (cached !== undefined) {
      return cached;
    }

    const secret = own(document.secrets, name);
    if (!secret) {
      throw new MsecretsError(
        "NOT_FOUND",
        `Secret ${name} does not exist in ${label}${suggest(name, Object.keys(document.secrets))}`,
      );
    }
    if (!secretEnvironments(document, secret).includes(environment)) {
      throw new MsecretsError(
        "NOT_FOUND",
        `Secret ${name} does not apply to environment "${environment}"`,
      );
    }
    if (!own(secret.values, environment)) {
      throw new MsecretsError(
        "NOT_FOUND",
        `Secret ${name} has no value in environment "${environment}"`,
      );
    }

    const value = revealValue(
      document,
      identities().map((entry) => entry.identity),
      name,
      environment,
    );
    cache.set(name, value);
    return value;
  };

  return {
    environment,
    keys: () => applicable().filter(has),
    has: (name: string): name is string => has(name),
    get,
    all() {
      const missing = applicable().filter((name) => !has(name));
      if (missing.length) {
        throw new MsecretsError(
          "NOT_FOUND",
          `Environment "${environment}" is incomplete; these secrets have no value: ${missing.join(", ")}`,
        );
      }
      return Object.freeze(Object.fromEntries(applicable().map((name) => [name, get(name)])));
    },
    identities: () => identities().map((entry) => entry.source),
  };
}

/** Decrypts the complete environment: `const secrets = load()`. */
export function load<F extends SecretsFileLike>(
  options: ClientOptions & { file: F },
): Readonly<Record<SecretNames<F>, string>>;
export function load(options?: ClientOptions): Readonly<Record<string, string>>;
export function load(options: ClientOptions = {}): Readonly<Record<string, string>> {
  return createClient(options).all();
}

export type InjectOptions = ClientOptions & {
  /** Overwrite variables that are already set (default false: explicit environment wins). */
  override?: boolean;
  /** Target environment object (default process.env). */
  target?: NodeJS.ProcessEnv;
};

/** Decrypts the complete environment into `process.env`. Returns the names that were set. */
export function injectEnv(options: InjectOptions = {}): string[] {
  const target = options.target ?? process.env;
  const secrets = load(options);
  return Object.entries(secrets).flatMap(([name, value]) => {
    if (!options.override && target[name] !== undefined) {
      return [];
    }
    target[name] = value;
    return [name];
  });
}
