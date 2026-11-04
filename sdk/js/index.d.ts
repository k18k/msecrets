export type ErrorCode =
  /** The age header is malformed or a recipient stanza is invalid. */
  | "AGE_HEADER"
  /** None of the provided identities can unwrap the file key. */
  | "AGE_NO_MATCH"
  /** The file key was unwrapped, but the header MAC does not match. */
  | "AGE_HMAC"
  /** The encrypted payload is truncated, tampered with, or malformed. */
  | "AGE_PAYLOAD"
  /** The ASCII armor is malformed. */
  | "AGE_ARMOR"
  /** A key, identity, or recipient string is malformed. */
  | "INVALID_KEY"
  /** The secrets file does not match the v4 format. */
  | "INVALID_FILE"
  /** A value signature is missing, malformed, or does not verify. */
  | "SIGNATURE"
  /** None of the loaded identities is allowed to perform the operation. */
  | "ACCESS_DENIED"
  /** A secret, environment, recipient, or file does not exist. */
  | "NOT_FOUND"
  /** The operation conflicts with existing state. */
  | "CONFLICT"
  /** An identity source (env, file, keychain, password manager) failed. */
  | "IDENTITY_SOURCE"
  /** The runtime lacks a required capability. */
  | "UNSUPPORTED"
  /** The caller passed invalid arguments. */
  | "USAGE";

export declare class MsecretsError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string, options?: ErrorOptions);
}

export declare function isMsecretsError(error: unknown, code?: ErrorCode): error is MsecretsError;

export type LoadedIdentity = {
  /** The identity: an AGE-SECRET-KEY-1…, AGE-SECRET-KEY-PQ-1…, or OpenSSH Ed25519 private key. */
  identity: string;
  /** Where the identity came from (never contains secret material). */
  source: string;
};

/** Built-in sources are interpreted by the core; custom ones implement `load` themselves. */
export type IdentitySource = {
  readonly label: string;
  load(): LoadedIdentity[];
};

export type SourceOptions = {
  /** Supplies passphrases for encrypted identity files and SSH keys. */
  passphrase?: (label: string) => string;
  /** Delete identity variables from `process.env` after reading them (default true). */
  scrub?: boolean;
  configDirectory?: string;
  cwd?: string;
};

export declare function fromString(text: string, label?: string, options?: SourceOptions): IdentitySource;
/** Reads identities from an environment variable and, by default, deletes it so child processes never see it. */
export declare function fromEnv(variable?: string, options?: SourceOptions): IdentitySource;
export declare function fromFile(path: string, options?: SourceOptions & { optional?: boolean }): IdentitySource;
/** Runs a command (password manager CLI) whose standard output is the identity. */
export declare function fromCommand(
  argv: readonly string[],
  options?: SourceOptions & { label?: string; firstLine?: boolean },
): IdentitySource;
export declare function fromKeychain(account?: string): IdentitySource;
/**
 * Parses an identity source spec:
 * - `env:NAME`, `file:PATH` (or a bare path), `keychain:ACCOUNT`
 * - `op://vault/item/field` (1Password), `bw:ITEM` (Bitwarden), `pass:NAME` (pass)
 * - `cmd:COMMAND ARGS…` (any command printing the identity)
 */
export declare function parseSourceSpec(spec: string, options?: SourceOptions): IdentitySource;
/** The default identity chain (see ClientOptions.identities). */
export declare function autoSource(options?: SourceOptions): IdentitySource;

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

/**
 * Verifies and decrypts every secret of one environment of an imported
 * secrets file: `const secrets = createClient(file); secrets.DATABASE_URL`.
 * Throws if the environment is incomplete or any value is tampered with or
 * unreadable, so a running app never sees half of its secrets. The result is
 * frozen, and `console.log` shows only its names.
 */
export declare function createClient<F extends SecretsFile>(file: F, options?: ClientOptions): Secrets<F>;

export type InjectOptions = ClientOptions & {
  /** Overwrite variables that are already set (default false: explicit environment wins). */
  override?: boolean;
  /** Target environment object (default process.env). */
  target?: Record<string, string | undefined>;
};

/**
 * Decrypts the environment into `process.env`, for libraries that read it:
 * `injectEnv(file)`. Returns the names that were set.
 */
export declare function injectEnv(file: SecretsFile, options?: InjectOptions): string[];
