import {
  type EnvironmentChoice,
  type Identity,
  type IdentitySource,
  type LoadedIdentity,
  IDENTITY_FILE_VARIABLE,
  IDENTITY_SOURCE_VARIABLE,
  IDENTITY_VARIABLE,
  MsecretsError,
  PASSPHRASE_VARIABLE,
  type SecretsDocument,
  autoSource,
  chooseEnvironment,
  fromString,
  loadIdentities,
  parseSourceSpec,
  readDocumentFile,
  resolveDocumentFile,
  updateDocumentFile,
} from "../../core/src/index.ts";
import { type Symbols, createSymbols, supportsUnicode } from "./symbols.ts";
import { type Colors, type Io, ask, colorsEnabled, createColors } from "./terminal.ts";

export type GlobalOptions = {
  file?: string | undefined;
  env?: string | undefined;
  identity?: string[] | undefined;
  as?: string | undefined;
};

class PassphraseNeeded extends Error {
  readonly label: string;

  constructor(label: string) {
    super(`Passphrase needed for ${label}`);
    this.label = label;
  }
}

export class Context {
  readonly io: Io;
  readonly options: GlobalOptions;
  readonly out: Colors;
  readonly err: Colors;
  readonly symbols: Symbols;
  #path: string | undefined;
  #identities: LoadedIdentity[] | undefined;
  #childEnv: NodeJS.ProcessEnv | undefined;

  constructor(io: Io, options: GlobalOptions) {
    this.io = io;
    this.options = options;
    this.out = createColors(colorsEnabled(io.stdout, io.env));
    this.err = createColors(colorsEnabled(io.stderr, io.env));
    this.symbols = createSymbols(supportsUnicode(io.env));
  }

  print(text = ""): void {
    this.io.stdout.write(`${text}\n`);
  }

  /** Diagnostics go to stderr so stdout stays machine-readable. */
  note(text: string): void {
    this.io.stderr.write(`${text}\n`);
  }

  warn(text: string): void {
    this.note(this.err.yellow(`warning: ${text}`));
  }

  success(text: string): void {
    this.note(`${this.err.green(this.symbols.check)} ${text}`);
  }

  get path(): string {
    this.#path ??= resolveDocumentFile({
      file: this.options.file,
      cwd: this.io.cwd,
      env: this.io.env,
    });
    return this.#path;
  }

  /** Path for a file that may not exist yet (init). */
  targetPath(defaultName: string): string {
    const explicit = this.options.file ?? this.io.env["MSECRETS_FILE"];
    return resolveDocumentFile({ file: explicit ?? defaultName, cwd: this.io.cwd, env: {} });
  }

  document(): SecretsDocument {
    return readDocumentFile(this.path);
  }

  update<T>(mutate: (document: SecretsDocument) => T): T {
    return updateDocumentFile(this.path, mutate);
  }

  environment(
    document: SecretsDocument,
    explicit: string | undefined = this.options.env,
  ): EnvironmentChoice {
    return chooseEnvironment(document, explicit, this.io.env);
  }

  /** Identity sources reading from `env`, a copy of the environment that they scrub. */
  sources(passphrase: (label: string) => string, env: NodeJS.ProcessEnv): IdentitySource[] {
    const options = { env, cwd: this.io.cwd, passphrase, scrub: true };
    if (!this.options.identity?.length) {
      return [autoSource(options)];
    }
    return this.options.identity.map((spec) =>
      /^AGE-SECRET-KEY-/i.test(spec.trim())
        ? fromString(spec, "--identity", options)
        : parseSourceSpec(spec, options),
    );
  }

  /** Loads identities, prompting for passphrases on a terminal when needed. */
  async loadedIdentities(): Promise<LoadedIdentity[]> {
    if (this.#identities) {
      return this.#identities;
    }

    const passphrases = new Map<string, string>();
    const fromEnv = this.io.env[PASSPHRASE_VARIABLE];
    for (;;) {
      try {
        // Every attempt starts from the full environment; sources delete the variables they read.
        const env = { ...this.io.env };
        this.#identities = loadIdentities(
          this.sources((label) => {
            const known = passphrases.get(label) ?? fromEnv;
            if (known === undefined) {
              throw new PassphraseNeeded(label);
            }
            return known;
          }, env),
        );
        this.#childEnv = env;
        return this.#identities;
      } catch (error) {
        if (!(error instanceof PassphraseNeeded) || passphrases.has(error.label)) {
          throw error;
        }
        if (!this.io.stdin.isTTY) {
          throw new MsecretsError(
            "IDENTITY_SOURCE",
            `${error.label} is passphrase-protected; set ${PASSPHRASE_VARIABLE}`,
          );
        }
        passphrases.set(
          error.label,
          await ask(this.io, `Passphrase for ${error.label}: `, { hidden: true }),
        );
      }
    }
  }

  /**
   * The environment for commands msecrets runs: without any variable an identity
   * was read from (`env:NAME` sources included) and without msecrets key settings.
   */
  async childEnv(): Promise<NodeJS.ProcessEnv> {
    await this.loadedIdentities();
    const env = { ...this.#childEnv };
    for (const variable of [
      IDENTITY_VARIABLE,
      IDENTITY_FILE_VARIABLE,
      IDENTITY_SOURCE_VARIABLE,
      PASSPHRASE_VARIABLE,
    ]) {
      delete env[variable];
    }
    return env;
  }

  async identities(): Promise<Identity[]> {
    return (await this.loadedIdentities()).map((entry) => entry.identity);
  }

  /** Identities, failing with setup guidance when there are none. */
  async requireIdentities(): Promise<Identity[]> {
    const identities = await this.identities();
    if (!identities.length) {
      throw new MsecretsError(
        "IDENTITY_SOURCE",
        "No msecrets identity found. Create one with `msecrets identity new`, or point to one with --identity, MSECRETS_IDENTITY, or `msecrets identity use <source>`",
      );
    }
    return identities;
  }
}
