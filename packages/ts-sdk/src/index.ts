import {
  type IdentitySource,
  MsecretsError,
  autoSource,
  chooseEnvironment,
  fromString,
  loadIdentities,
  own,
  parseDocument,
  parseSourceSpec,
  revealValue,
  secretEnvironments,
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

/**
 * A parsed `msecrets.json`. Import it so TypeScript knows your secret names:
 * `import file from "./msecrets.json" with { type: "json" }`.
 */
export type SecretsFile = { secrets: object };

type SecretNames<F extends SecretsFile> = Extract<keyof F["secrets"], string>;

/**
 * The decrypted environment, shaped like the secrets file. Secrets limited to
 * some environments (`"environments": [...]` in the file) may be absent.
 */
export type Secrets<F extends SecretsFile> = [SecretNames<F>] extends [never]
  ? Readonly<Record<string, string | undefined>>
  : {
      readonly [Name in SecretNames<F>]: F["secrets"][Name] extends { environments: unknown }
        ? string | undefined
        : string;
    };

export type ClientOptions = {
  /** Environment. Default: MSECRETS_ENV, else "development" if it exists, else the only environment. */
  env?: string;
  /**
   * Identity sources, tried together. Strings are source specs (`env:NAME`, `file:PATH`,
   * `keychain:ACCOUNT`, `op://…`, `bw:ITEM`, `pass:NAME`, `cmd:…`) or raw identities.
   * Default: the automatic chain (MSECRETS_IDENTITY, MSECRETS_IDENTITY_FILE,
   * MSECRETS_IDENTITY_SOURCE, container secrets, then the developer config).
   */
  identities?: readonly (IdentitySource | string)[];
};

function toSource(entry: IdentitySource | string): IdentitySource {
  if (typeof entry !== "string") {
    return entry;
  }
  const trimmed = entry.trim();
  return /^AGE-SECRET-KEY-|^-----BEGIN /i.test(trimmed)
    ? fromString(trimmed)
    : parseSourceSpec(trimmed);
}

/**
 * Verifies and decrypts every secret of one environment of an imported
 * secrets file: `const secrets = createClient(file); secrets.DATABASE_URL`.
 * Throws if the environment is incomplete or any value is tampered with or
 * unreadable, so a running app never sees half of its secrets. The result is
 * frozen, and `console.log` shows only its names.
 */
export function createClient<F extends SecretsFile>(
  file: F,
  options: ClientOptions = {},
): Secrets<F> {
  const document = parseDocument(file);
  const environment = chooseEnvironment(document, options.env).name;
  const applicable = Object.entries(document.secrets).filter(([, secret]) =>
    secretEnvironments(document, secret).includes(environment),
  );
  const names = applicable.map(([name]) => name);
  const missing = applicable.filter(([, secret]) => !own(secret.values, environment));
  if (missing.length) {
    throw new MsecretsError(
      "NOT_FOUND",
      `Environment "${environment}" is incomplete; these secrets have no value: ${missing.map(([name]) => name).join(", ")}`,
    );
  }

  const sources = options.identities?.map(toSource) ?? [autoSource()];
  const identities = names.length ? loadIdentities(sources).map((entry) => entry.identity) : [];
  if (names.length && !identities.length) {
    throw new MsecretsError(
      "IDENTITY_SOURCE",
      "No msecrets identity found. Set MSECRETS_IDENTITY (or MSECRETS_IDENTITY_FILE / MSECRETS_IDENTITY_SOURCE), mount /run/secrets/msecrets_identity, or run `msecrets init` on a developer machine",
    );
  }

  const secrets = Object.fromEntries(
    names.map((name) => [name, revealValue(document, identities, name, environment)]),
  );
  Object.defineProperty(secrets, Symbol.for("nodejs.util.inspect.custom"), {
    value: () => `Secrets (${environment}) { ${names.join(", ")} }`,
  });
  return Object.freeze(secrets) as Secrets<F>;
}

export type InjectOptions = ClientOptions & {
  /** Overwrite variables that are already set (default false: explicit environment wins). */
  override?: boolean;
  /** Target environment object (default process.env). */
  target?: NodeJS.ProcessEnv;
};

/**
 * Decrypts the environment into `process.env`, for libraries that read it:
 * `injectEnv(file)`. Returns the names that were set.
 */
export function injectEnv(file: SecretsFile, options: InjectOptions = {}): string[] {
  const target = options.target ?? process.env;
  const secrets: Readonly<Record<string, string | undefined>> = createClient(file, options);
  return Object.keys(secrets).flatMap((name) => {
    if (!options.override && target[name] !== undefined) {
      return [];
    }
    target[name] = secrets[name];
    return [name];
  });
}
