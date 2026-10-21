import { execFileSync } from "node:child_process";
import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

import {
  type CellState,
  DEFAULT_FILENAME,
  IDENTITY_VARIABLE,
  type IdentitySource,
  MsecretsError,
  type RevokeResult,
  type SecretsDocument,
  type SyncResult,
  absoluteSourceSpec,
  addEnvironment,
  addRecipient,
  createDocument,
  createDocumentFile,
  deleteSecret,
  describeSecret,
  formatIdentityFile,
  generateIdentity,
  grantAccess,
  inspect,
  members,
  own,
  parsePublicKey,
  readOnlyPublicKey,
  recipientKey,
  removeEnvironment,
  removeRecipient,
  renameEnvironment,
  renameRecipient,
  renameSecret,
  replaceRecipientKey,
  requireEnvironment,
  requireName,
  requireRecipient,
  requireSecret,
  revealValue,
  revokeAccess,
  scopeSecret,
  secretEnvironments,
  setValue,
  sync,
  unsetValue,
} from "../../core/src/index.ts";
import { createClient } from "../../ts-sdk/src/index.ts";
import { Context } from "./context.ts";
import { formatDotenv, formatPowerShell, formatShell, parseDotenv } from "./formats.ts";
import { mergeDocuments, renderForDiff } from "./git.ts";
import {
  addIdentitySource,
  defaultRecipientName,
  ensureIdentity,
  parseStoreTarget,
  storeIdentity,
} from "./identity-setup.ts";
import { runToCompletion, spawnCommand } from "./spawn.ts";
import { CELL_DESCRIPTIONS, cellStyle } from "./symbols.ts";
import { ask, confirm, readAll, table } from "./terminal.ts";

export type OptionSpec = {
  type: "string" | "boolean";
  short?: string;
  multiple?: boolean;
  description: string;
  placeholder?: string;
};

export type Flags = Record<string, string | boolean | (string | boolean)[] | undefined>;

export type Command = {
  name: string;
  args: string;
  summary: string;
  options?: Record<string, OptionSpec>;
  /** Everything after the first positional (or `--`) is passed through verbatim. */
  passthrough?: boolean;
  run(context: Context, args: string[], flags: Flags): Promise<number | void>;
};

export function flagString(flags: Flags, name: string): string | undefined {
  const value = flags[name];
  const last = Array.isArray(value) ? value[value.length - 1] : value;
  return typeof last === "string" ? last : undefined;
}

export function flagBoolean(flags: Flags, name: string): boolean {
  return flags[name] === true;
}

/** Repeatable, comma-separated list flag. */
export function flagList(flags: Flags, name: string): string[] {
  const value = flags[name];
  const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
  return values
    .filter((entry): entry is string => typeof entry === "string")
    .flatMap((entry) => entry.split(","))
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function requireArgs(args: string[], count: number, usage: string): void {
  if (args.length < count) {
    throw new MsecretsError("USAGE", `Missing arguments; usage: msecrets ${usage}`);
  }
}

function displayPath(context: Context, path: string): string {
  const relativePath = relative(context.io.cwd, path);
  return relativePath && !relativePath.startsWith("..") ? relativePath : path;
}

function singleEnvironment(context: Context, document: SecretsDocument, flags: Flags): string {
  const environments = flagList(flags, "env");
  if (environments.length > 1) {
    throw new MsecretsError("USAGE", "This command takes a single --env");
  }
  return context.environment(document, environments[0]).name;
}

async function confirmDanger(context: Context, flags: Flags, question: string): Promise<void> {
  if (flagBoolean(flags, "yes")) {
    return;
  }
  if (!context.io.stdin.isTTY) {
    throw new MsecretsError("USAGE", `${question} Pass --yes to confirm`);
  }
  if (!(await confirm(context.io, question))) {
    throw new MsecretsError("USAGE", "Aborted");
  }
}

function reportSync(context: Context, result: SyncResult): void {
  if (result.updated.length) {
    context.success(`Re-encrypted ${result.updated.length} value(s) for the current recipients`);
  }
  if (result.skipped.length) {
    context.warn(
      `${result.skipped.length} value(s) could not be re-encrypted by you; a member with access must run \`msecrets sync\`:\n${result.skipped
        .map((slot) => `  ${slot.secret} in "${slot.environment}"`)
        .join("\n")}`,
    );
  }
}

function reportRevoke(context: Context, recipient: string, result: RevokeResult): void {
  reportSync(context, result);
  if (result.rotate.length) {
    const secrets = [
      ...new Set(result.rotate.map((slot) => `${slot.secret} (${slot.environment})`)),
    ];
    context.warn(
      `"${recipient}" could read these values and may have kept copies. Rotate them at their source, then \`msecrets set\` the new values:\n  ${secrets.join("\n  ")}`,
    );
  }
}

const YES: OptionSpec = { type: "boolean", short: "y", description: "Do not ask for confirmation" };
const STORE: OptionSpec = {
  type: "string",
  description: "Where to keep a new identity: keychain (default), file, or print",
  placeholder: "WHERE",
};
const PQ: OptionSpec = {
  type: "boolean",
  description: "Generate a post-quantum (ML-KEM-768 + X25519) key",
};
const PASSPHRASE: OptionSpec = {
  type: "boolean",
  description: "Protect a new identity file with a passphrase",
};
const JSON_OUTPUT: OptionSpec = { type: "boolean", description: "Machine-readable JSON output" };
const GENERATE: OptionSpec = {
  type: "boolean",
  description:
    "Generate a read-only machine key and print its identity to stdout (for CI / runtime)",
};

// Setup

const init: Command = {
  name: "init",
  args: "",
  summary: "Create msecrets.json with you as its first recipient",
  options: {
    name: {
      type: "string",
      description: "Your recipient name (default: from git user.email)",
      placeholder: "NAME",
    },
    store: STORE,
    pq: PQ,
    passphrase: PASSPHRASE,
  },
  async run(context, _args, flags) {
    const path = context.targetPath(DEFAULT_FILENAME);
    if (statSync(path, { throwIfNoEntry: false })) {
      throw new MsecretsError(
        "CONFLICT",
        `${displayPath(context, path)} already exists. To add yourself to it, run \`msecrets join\``,
      );
    }

    const environments = flagList(flags, "env");
    const environmentNames = environments.length ? environments : ["development", "production"];
    environmentNames.forEach((name) => requireName("environment", name));
    const name = requireName(
      "recipient",
      flagString(flags, "name") ?? defaultRecipientName(context.io.cwd),
    );

    const { identity } = await ensureIdentity(context, {
      store: parseStoreTarget(flagString(flags, "store")),
      postQuantum: flagBoolean(flags, "pq"),
      passphrase: flagBoolean(flags, "passphrase"),
    });

    const document = createDocument();
    addRecipient(document, name, identity.publicKey.token);
    for (const environment of environmentNames) {
      addEnvironment(document, environment, [name]);
    }
    createDocumentFile(path, document);

    context.success(
      `Created ${displayPath(context, path)} (${environmentNames.join(", ")}); you are recipient "${name}"`,
    );
    context.note(
      [
        "",
        "Next:",
        `  msecrets set DATABASE_URL            ${context.err.dim("# add a secret (prompts for the value)")}`,
        `  msecrets run -- npm start            ${context.err.dim("# run anything with the secrets as env vars")}`,
        `  msecrets git setup                   ${context.err.dim("# readable diffs and conflict-free merges")}`,
        `${`  git add ${displayPath(context, path)}`.padEnd(39)}${context.err.dim("# the file is safe to commit")}`,
      ].join("\n"),
    );
  },
};

const joinCommand: Command = {
  name: "join",
  args: "",
  summary: "Add yourself as a recipient of an existing secrets file",
  options: {
    name: {
      type: "string",
      description: "Your recipient name (default: from git user.email)",
      placeholder: "NAME",
    },
    store: STORE,
    pq: PQ,
    passphrase: PASSPHRASE,
  },
  async run(context, _args, flags) {
    const document = context.document();
    const { identity } = await ensureIdentity(context, {
      store: parseStoreTarget(flagString(flags, "store")),
      postQuantum: flagBoolean(flags, "pq"),
      passphrase: flagBoolean(flags, "passphrase"),
    });

    const [existing] = members(document, [identity]);
    if (existing) {
      context.success(
        `You are already recipient "${existing.name}" of ${displayPath(context, context.path)}`,
      );
      return;
    }

    const name = requireName(
      "recipient",
      flagString(flags, "name") ?? defaultRecipientName(context.io.cwd),
    );
    const environments = flagList(flags, "env");
    context.update((current) => {
      addRecipient(current, name, identity.publicKey.token);
      for (const environment of environments) {
        requireEnvironment(current, environment).recipients.push(name);
      }
    });

    context.success(
      `Added you as recipient "${name}"${environments.length ? ` of ${environments.join(", ")}` : ""}`,
    );
    context.note(
      environments.length
        ? "Commit and push this change. Once it is reviewed, a member runs `msecrets sync` to re-encrypt the values for you."
        : `Commit and push this change, then ask a member to run \`msecrets grant ${name} <environment>\`.`,
    );
  },
};

const whoami: Command = {
  name: "whoami",
  args: "",
  summary: "Show your identities and what they can access",
  async run(context) {
    const loaded = await context.loadedIdentities();
    if (!loaded.length) {
      context.print(
        "No identity found. Create one with `msecrets identity new` (or `msecrets init` in a new project).",
      );
      return 1;
    }

    let document: SecretsDocument | null = null;
    try {
      document = context.document();
    } catch (error) {
      if (!(error instanceof MsecretsError && error.code === "NOT_FOUND")) {
        throw error;
      }
    }

    for (const { identity, source } of loaded) {
      context.print(
        `${context.out.bold(identity.publicKey.kind)} ${context.out.dim(`from ${source}`)}`,
      );
      context.print(`  ${identity.publicKey.token}`);
      if (!document) {
        continue;
      }
      const [member] = members(document, [identity]);
      if (!member) {
        context.print(
          `  ${context.out.yellow("not a recipient of this file")} ${context.out.dim("(run `msecrets join`)")}`,
        );
        continue;
      }
      const canSign = recipientKey(document, member.name).signingKey !== null;
      const access = Object.entries(document.environments)
        .filter(([, environment]) => environment.recipients.includes(member.name))
        .map(([name]) => `${name} (${canSign ? "read/write" : "read"})`);
      context.print(
        `  recipient ${context.out.cyan(member.name)}: ${access.join(", ") || context.out.yellow("no environments")}`,
      );
    }
    return 0;
  },
};

const identityNew: Command = {
  name: "identity new",
  args: "",
  summary: "Generate a new identity and store it",
  options: {
    store: STORE,
    pq: PQ,
    passphrase: PASSPHRASE,
    account: {
      type: "string",
      description: "Keychain account / file name to use (default: default)",
      placeholder: "NAME",
    },
  },
  async run(context, _args, flags) {
    const identity = generateIdentity({ postQuantum: flagBoolean(flags, "pq") });
    const account = flagString(flags, "account");
    const spec = await storeIdentity(
      context,
      identity,
      parseStoreTarget(flagString(flags, "store")),
      {
        ...(account === undefined ? {} : { account }),
        passphrase: flagBoolean(flags, "passphrase"),
      },
    );
    if (spec) {
      const configPath = addIdentitySource(context, spec);
      context.success(`Stored the identity in ${spec}; registered in ${configPath}`);
      context.print(identity.publicKey.token);
    } else {
      context.note(
        context.err.yellow(
          "Store the identity printed above in your password manager, then run `msecrets identity use <source>`",
        ),
      );
      context.note(`Public key: ${identity.publicKey.token}`);
    }
  },
};

const identityShow: Command = {
  name: "identity show",
  args: "",
  summary: "Print the public keys of your identities",
  async run(context) {
    for (const identity of await context.requireIdentities()) {
      context.print(identity.publicKey.token);
    }
  },
};

const identityExport: Command = {
  name: "identity export",
  args: "",
  summary: "Print your identities (private keys), e.g. to move them to a password manager",
  options: { yes: YES },
  async run(context, _args, flags) {
    const identities = await context.requireIdentities();
    if (context.io.stdout.isTTY) {
      await confirmDanger(context, flags, "This prints your private key on the screen. Continue?");
    }
    for (const identity of identities) {
      context.io.stdout.write(formatIdentityFile(identity));
    }
  },
};

const identityUse: Command = {
  name: "identity use",
  args: "<source>",
  summary: "Load your identity from a source (op://…, bw:…, pass:…, keychain:…, file:…, cmd:…)",
  async run(context, args) {
    requireArgs(args, 1, "identity use <source>");
    const source = args[0] ?? "";
    const probe = new Context(context.io, { identity: [source] });
    const loaded = await probe.loadedIdentities();
    if (!loaded.length) {
      throw new MsecretsError("IDENTITY_SOURCE", `${source} did not yield any identity`);
    }
    // The config is shared by every directory: store file paths absolute.
    const configPath = addIdentitySource(context, absoluteSourceSpec(source, context.io.cwd));
    context.success(
      `Using ${source} (${loaded.length} identit${loaded.length === 1 ? "y" : "ies"}); saved in ${configPath}`,
    );
    for (const { identity } of loaded) {
      context.print(identity.publicKey.token);
    }
  },
};

// Inspection

function cellGlyph(context: Context, state: CellState): string {
  return cellStyle(context.out, state)(context.symbols.cell[state]);
}

function printFindings(context: Context, document: SecretsDocument): boolean {
  const report = inspect(document);
  for (const finding of report.findings) {
    const label =
      finding.level === "error" ? context.out.red("error") : context.out.yellow("warning");
    context.print(`${label} ${finding.message}`);
  }
  return report.ok;
}

const ls: Command = {
  name: "ls",
  args: "",
  summary: "Show every secret in every environment, and any problems (use `check` to fail CI)",
  options: { json: JSON_OUTPUT },
  async run(context, _args, flags) {
    const document = context.document();
    const report = inspect(document);
    const environments = Object.keys(document.environments);

    if (flagBoolean(flags, "json")) {
      const secrets = Object.fromEntries(
        Object.keys(document.secrets).map((name) => [
          name,
          {
            ...(document.secrets[name]?.description
              ? { description: document.secrets[name]?.description }
              : {}),
            values: Object.fromEntries(
              report.cells
                .filter((cell) => cell.secret === name)
                .map((cell) => [cell.environment, cell.state]),
            ),
          },
        ]),
      );
      context.print(
        JSON.stringify(
          { file: context.path, environments, secrets, findings: report.findings, ok: report.ok },
          null,
          2,
        ),
      );
      return 0;
    }

    if (!Object.keys(document.secrets).length) {
      context.print(
        `No secrets yet in ${displayPath(context, context.path)}. Add one with \`msecrets set NAME\`.`,
      );
      return 0;
    }

    const rows = [
      [
        context.out.bold("SECRET"),
        ...environments.map((name) => context.out.bold(name)),
        context.out.bold("DESCRIPTION"),
      ],
      ...Object.keys(document.secrets).map((name) => [
        name,
        ...environments.map((environment) => {
          const cell = report.cells.find(
            (entry) => entry.secret === name && entry.environment === environment,
          );
          return cellGlyph(context, cell?.state ?? "absent");
        }),
        context.out.dim(document.secrets[name]?.description ?? ""),
      ]),
    ];
    for (const line of table(rows)) {
      context.print(line);
    }

    const legend = (["ok", "stale", "missing", "invalid"] as const).map(
      (state) => `${cellGlyph(context, state)} ${CELL_DESCRIPTIONS[state]}`,
    );
    context.print(context.out.dim(`\n${legend.join("   ")}`));
    if (report.findings.length) {
      context.print();
      printFindings(context, document);
    }
    return 0;
  },
};

const check: Command = {
  name: "check",
  args: "",
  summary: "Validate the file for CI: every value present, current, and signed (exit 1 otherwise)",
  options: { json: JSON_OUTPUT },
  async run(context, _args, flags) {
    const document = context.document();
    const report = inspect(document);
    if (flagBoolean(flags, "json")) {
      context.print(
        JSON.stringify({ file: context.path, ok: report.ok, findings: report.findings }, null, 2),
      );
      return report.ok ? 0 : 1;
    }

    const ok = printFindings(context, document);
    const counts = `${Object.keys(document.secrets).length} secret(s) × ${Object.keys(document.environments).length} environment(s)`;
    if (ok) {
      context.print(
        `${context.out.green(context.symbols.check)} ${displayPath(context, context.path)}: ${counts}; every value is present, current, and signed`,
      );
      return 0;
    }
    context.print(
      `${context.out.red(context.symbols.cross)} ${displayPath(context, context.path)}: ${counts}; fix the errors above`,
    );
    return 1;
  },
};

// Secrets

const get: Command = {
  name: "get",
  args: "<NAME>",
  summary: "Print a decrypted value",
  async run(context, args, flags) {
    requireArgs(args, 1, "get <NAME> [--env NAME]");
    const document = context.document();
    const value = revealValue(
      document,
      await context.requireIdentities(),
      args[0] ?? "",
      singleEnvironment(context, document, flags),
    );
    context.io.stdout.write(context.io.stdout.isTTY ? `${value}\n` : value);
  },
};

async function readValue(
  context: Context,
  name: string,
  environments: string[],
  given: string | undefined,
): Promise<string> {
  if (given !== undefined) {
    return given;
  }
  if (!context.io.stdin.isTTY) {
    return (await readAll(context.io.stdin)).replace(/\r?\n$/, "");
  }
  return ask(context.io, `Value for ${name} (${environments.join(", ")}): `, { hidden: true });
}

const set: Command = {
  name: "set",
  args: "<NAME> [VALUE]",
  summary: "Encrypt and store a value (prompts, or reads stdin, when VALUE is omitted)",
  options: {
    all: {
      type: "boolean",
      description: "Set the value in every environment the secret applies to",
    },
    description: {
      type: "string",
      short: "d",
      description: "Describe the secret",
      placeholder: "TEXT",
    },
  },
  async run(context, args, flags) {
    requireArgs(args, 1, "set <NAME> [VALUE] [--env NAME]");
    const name = requireName("secret", args[0] ?? "");
    const document = context.document();
    const existing = own(document.secrets, name);
    const explicit = flagList(flags, "env");
    const environments = flagBoolean(flags, "all")
      ? existing
        ? secretEnvironments(document, existing)
        : Object.keys(document.environments)
      : explicit.length
        ? explicit
        : [context.environment(document).name];
    environments.forEach((environment) => requireEnvironment(document, environment));

    const identities = await context.requireIdentities();
    const value = await readValue(context, name, environments, args[1]);
    const description = flagString(flags, "description");
    const signers = context.update((current) => {
      const sealed = environments.map((environment) =>
        setValue(current, identities, {
          secret: name,
          environment,
          value,
          ...(context.options.as ? { as: context.options.as } : {}),
        }),
      );
      if (description !== undefined) {
        describeSecret(current, name, description);
      }
      return [...new Set(sealed.map((entry) => entry.by))];
    });
    context.success(`Set ${name} in ${environments.join(", ")} (signed by ${signers.join(", ")})`);
  },
};

const unset: Command = {
  name: "unset",
  args: "<NAME>",
  summary: "Remove the value of a secret from an environment",
  async run(context, args, flags) {
    requireArgs(args, 1, "unset <NAME> [--env NAME]");
    const name = args[0] ?? "";
    const environments = flagList(flags, "env");
    const removed = context.update((document) => {
      const targets = environments.length ? environments : [context.environment(document).name];
      return targets.filter((environment) => unsetValue(document, name, environment));
    });
    if (removed.length) {
      context.success(`Removed ${name} from ${removed.join(", ")}`);
    } else {
      context.note(`${name} had no value there`);
    }
  },
};

const rm: Command = {
  name: "rm",
  args: "<NAME>",
  summary: "Delete a secret from every environment",
  options: { yes: YES },
  async run(context, args, flags) {
    requireArgs(args, 1, "rm <NAME>");
    const name = args[0] ?? "";
    requireSecret(context.document(), name);
    await confirmDanger(context, flags, `Delete ${name} from every environment?`);
    context.update((document) => deleteSecret(document, name));
    context.success(`Deleted ${name}`);
  },
};

const mv: Command = {
  name: "mv",
  args: "<NAME> <NEW_NAME>",
  summary: "Rename a secret (values are re-signed, not re-encrypted)",
  async run(context, args) {
    requireArgs(args, 2, "mv <NAME> <NEW_NAME>");
    const identities = await context.identities();
    context.update((document) => renameSecret(document, identities, args[0] ?? "", args[1] ?? ""));
    context.success(`Renamed ${args[0]} to ${args[1]}`);
  },
};

const describe: Command = {
  name: "describe",
  args: "<NAME> [TEXT...]",
  summary: "Set (or, without TEXT, clear) the description of a secret",
  async run(context, args) {
    requireArgs(args, 1, "describe <NAME> [TEXT...]");
    const text = args.slice(1).join(" ").trim();
    context.update((document) => describeSecret(document, args[0] ?? "", text || undefined));
    context.success(text ? `Described ${args[0]}` : `Cleared the description of ${args[0]}`);
  },
};

const scope: Command = {
  name: "scope",
  args: "<NAME> [ENV...]",
  summary: "Limit a secret to some environments (--all: every environment)",
  options: {
    all: { type: "boolean", description: "Apply the secret to every environment" },
    yes: YES,
  },
  async run(context, args, flags) {
    requireArgs(args, 1, "scope <NAME> [ENV...] | --all");
    const name = args[0] ?? "";
    const environments = flagBoolean(flags, "all")
      ? undefined
      : args.slice(1).flatMap((entry) => entry.split(","));
    if (environments && !environments.length) {
      throw new MsecretsError("USAGE", "List environments, or pass --all");
    }

    const document = context.document();
    const secret = requireSecret(document, name);
    const dropped = Object.keys(secret.values).filter(
      (environment) => environments && !environments.includes(environment),
    );
    if (dropped.length) {
      await confirmDanger(
        context,
        flags,
        `This removes the values of ${name} in ${dropped.join(", ")}. Continue?`,
      );
    }
    context.update((current) => scopeSecret(current, name, environments));
    context.success(
      environments
        ? `${name} now applies to ${environments.join(", ")}`
        : `${name} now applies to every environment`,
    );
  },
};

// Environments

const envLs: Command = {
  name: "env ls",
  args: "",
  summary: "List environments and their recipients",
  async run(context) {
    const document = context.document();
    const report = inspect(document);
    const rows = [
      [context.out.bold("ENVIRONMENT"), context.out.bold("VALUES"), context.out.bold("RECIPIENTS")],
      ...Object.entries(document.environments).map(([name, environment]) => {
        const cells = report.cells.filter(
          (cell) => cell.environment === name && cell.state !== "absent",
        );
        const ok = cells.filter((cell) => cell.state === "ok").length;
        return [
          name,
          `${ok}/${cells.length}`,
          environment.recipients.join(", ") || context.out.yellow("none"),
        ];
      }),
    ];
    for (const line of table(rows)) {
      context.print(line);
    }
  },
};

const envAdd: Command = {
  name: "env add",
  args: "<NAME>",
  summary: "Add an environment (recipients: --recipients, --from ENV, or you)",
  options: {
    recipients: {
      type: "string",
      multiple: true,
      description: "Recipients of the new environment",
      placeholder: "LIST",
    },
    from: {
      type: "string",
      description: "Copy the recipients of another environment",
      placeholder: "ENV",
    },
  },
  async run(context, args, flags) {
    requireArgs(args, 1, "env add <NAME>");
    const name = args[0] ?? "";
    const identities = await context.identities();
    const recipients = context.update((document) => {
      const from = flagString(flags, "from");
      const chosen = flagList(flags, "recipients");
      const list = from
        ? requireEnvironment(document, from).recipients
        : chosen.length
          ? chosen
          : members(document, identities).map((member) => member.name);
      addEnvironment(document, name, list);
      return list;
    });
    context.success(`Added environment "${name}" (recipients: ${recipients.join(", ") || "none"})`);
    if (!recipients.length) {
      context.warn(
        "The environment has no recipients yet; add some with `msecrets grant <recipient> " +
          name +
          "`",
      );
    }
  },
};

const envRm: Command = {
  name: "env rm",
  args: "<NAME>",
  summary: "Remove an environment and its values",
  options: { yes: YES },
  async run(context, args, flags) {
    requireArgs(args, 1, "env rm <NAME>");
    const name = args[0] ?? "";
    requireEnvironment(context.document(), name);
    await confirmDanger(context, flags, `Remove environment "${name}" and all of its values?`);
    const result = context.update((document) => removeEnvironment(document, name));
    context.success(`Removed environment "${name}" (${result.removedValues.length} value(s))`);
    if (result.removedSecrets.length) {
      context.note(`Deleted secrets that only applied to it: ${result.removedSecrets.join(", ")}`);
    }
  },
};

const envMv: Command = {
  name: "env mv",
  args: "<NAME> <NEW_NAME>",
  summary: "Rename an environment (values are re-signed)",
  async run(context, args) {
    requireArgs(args, 2, "env mv <NAME> <NEW_NAME>");
    const identities = await context.identities();
    context.update((document) =>
      renameEnvironment(document, identities, args[0] ?? "", args[1] ?? ""),
    );
    context.success(`Renamed environment "${args[0]}" to "${args[1]}"`);
  },
};

// Recipients and access

async function resolveKeyArgument(key: string): Promise<string> {
  const github = /^github:([A-Za-z0-9-]{1,39})$/.exec(key);
  if (!github) {
    return key;
  }
  const url = `https://github.com/${github[1]}.keys`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new MsecretsError("NOT_FOUND", `Could not fetch ${url}: HTTP ${response.status}`);
  }
  const keys = (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("ssh-ed25519 "));
  if (keys.length !== 1) {
    throw new MsecretsError(
      "USAGE",
      `${url} has ${keys.length} ssh-ed25519 keys; pass the one to use explicitly`,
    );
  }
  return keys[0] ?? "";
}

const recipientLs: Command = {
  name: "recipient ls",
  args: "",
  summary: "List recipients, their key types, and their access",
  async run(context) {
    const document = context.document();
    const mine = new Set(
      members(document, await context.identities()).map((member) => member.name),
    );
    const rows = [
      [
        context.out.bold("RECIPIENT"),
        context.out.bold("KEY"),
        context.out.bold("ENVIRONMENTS"),
        context.out.bold("DESCRIPTION"),
      ],
      ...Object.keys(document.recipients).map((name) => {
        const key = recipientKey(document, name);
        const environments = Object.entries(document.environments)
          .filter(([, environment]) => environment.recipients.includes(name))
          .map(([environment]) => environment);
        return [
          `${name}${mine.has(name) ? context.out.cyan(" (you)") : ""}`,
          `${key.kind}${key.signingKey ? "" : context.out.dim(" read-only")}`,
          environments.join(", ") || context.out.dim("none"),
          context.out.dim(document.recipients[name]?.description ?? ""),
        ];
      }),
    ];
    for (const line of table(rows)) {
      context.print(line);
    }
  },
};

const recipientAdd: Command = {
  name: "recipient add",
  args: "<NAME> [KEY | github:USER]",
  summary: "Add a recipient (person or machine); --generate creates a machine key",
  options: {
    generate: GENERATE,
    pq: PQ,
    description: {
      type: "string",
      short: "d",
      description: "Describe the recipient",
      placeholder: "TEXT",
    },
  },
  async run(context, args, flags) {
    requireArgs(args, 1, "recipient add <NAME> <KEY> | --generate");
    const name = args[0] ?? "";
    const generated = flagBoolean(flags, "generate")
      ? generateIdentity({ postQuantum: flagBoolean(flags, "pq") })
      : null;
    if (!generated && !args[1]) {
      throw new MsecretsError(
        "USAGE",
        "Pass the recipient's public key (msecrets1…, age1…, ssh-ed25519 …, github:USER) or --generate",
      );
    }
    const key = generated
      ? readOnlyPublicKey(generated.publicKey).token
      : await resolveKeyArgument(args.slice(1).join(" "));
    const environments = flagList(flags, "env");
    const identities = environments.length ? await context.identities() : [];

    const result = context.update((document) => {
      addRecipient(document, name, key, flagString(flags, "description"));
      return environments.length ? grantAccess(document, identities, name, environments) : null;
    });

    context.success(
      `Added recipient "${name}"${environments.length ? ` with access to ${environments.join(", ")}` : ""}`,
    );
    if (result) {
      reportSync(context, result);
    }
    if (!parsePublicKey(key).signingKey) {
      context.note(
        context.err.dim("This key cannot sign, so the recipient can read but not write values."),
      );
    }
    if (generated) {
      context.io.stdout.write(formatIdentityFile(generated, `recipient ${name}`));
      context.note(
        context.err.yellow(
          `The identity above is shown only once. Store it in your runtime secret store and expose it as ${IDENTITY_VARIABLE} (or mount it at /run/secrets/msecrets_identity).`,
        ),
      );
    }
  },
};

const recipientRm: Command = {
  name: "recipient rm",
  args: "<NAME>",
  summary: "Remove a recipient and re-encrypt everything it could read",
  options: { yes: YES },
  async run(context, args, flags) {
    requireArgs(args, 1, "recipient rm <NAME>");
    const name = args[0] ?? "";
    requireRecipient(context.document(), name);
    await confirmDanger(context, flags, `Remove recipient "${name}"?`);
    const identities = await context.identities();
    const result = context.update((document) => removeRecipient(document, identities, name));
    context.success(`Removed recipient "${name}"`);
    reportRevoke(context, name, result);
  },
};

const recipientMv: Command = {
  name: "recipient mv",
  args: "<NAME> <NEW_NAME>",
  summary: "Rename a recipient",
  async run(context, args) {
    requireArgs(args, 2, "recipient mv <NAME> <NEW_NAME>");
    context.update((document) => renameRecipient(document, args[0] ?? "", args[1] ?? ""));
    context.success(`Renamed recipient "${args[0]}" to "${args[1]}"`);
  },
};

const recipientRotate: Command = {
  name: "recipient rotate",
  args: "<NAME> [NEW_KEY]",
  summary: "Replace a recipient's key and re-encrypt its values (--generate: new machine key)",
  options: { generate: GENERATE, pq: PQ },
  async run(context, args, flags) {
    requireArgs(args, 1, "recipient rotate <NAME> <NEW_KEY> | --generate");
    const name = args[0] ?? "";
    const generated = flagBoolean(flags, "generate")
      ? generateIdentity({ postQuantum: flagBoolean(flags, "pq") })
      : null;
    if (!generated && !args[1]) {
      throw new MsecretsError("USAGE", "Pass the new public key or --generate");
    }
    const key = generated
      ? readOnlyPublicKey(generated.publicKey).token
      : await resolveKeyArgument(args.slice(1).join(" "));
    const identities = await context.requireIdentities();
    const updated = context.update((document) =>
      replaceRecipientKey(document, identities, name, key),
    );
    context.success(`Rotated the key of "${name}" (${updated.length} value(s) re-encrypted)`);
    if (generated) {
      context.io.stdout.write(formatIdentityFile(generated, `recipient ${name}`));
      context.note(
        context.err.yellow(
          "The identity above is shown only once; replace the old one in your runtime secret store.",
        ),
      );
    }
  },
};

const grant: Command = {
  name: "grant",
  args: "<RECIPIENT> <ENV...>",
  summary: "Give a recipient access to environments (re-encrypts their values)",
  async run(context, args) {
    requireArgs(args, 2, "grant <RECIPIENT> <ENV...>");
    const [recipient = "", ...environments] = args;
    const identities = await context.identities();
    const result = context.update((document) =>
      grantAccess(
        document,
        identities,
        recipient,
        environments.flatMap((entry) => entry.split(",")),
      ),
    );
    context.success(`Granted "${recipient}" access to ${environments.join(", ")}`);
    reportSync(context, result);
  },
};

const revoke: Command = {
  name: "revoke",
  args: "<RECIPIENT> <ENV...>",
  summary: "Take away access and re-encrypt the affected values without the recipient",
  options: {
    incomplete: {
      type: "boolean",
      description: "Record the revocation even if you cannot re-encrypt every value",
    },
  },
  async run(context, args, flags) {
    requireArgs(args, 2, "revoke <RECIPIENT> <ENV...>");
    const [recipient = "", ...environments] = args;
    const identities = await context.identities();
    const result = context.update((document) =>
      revokeAccess(
        document,
        identities,
        recipient,
        environments.flatMap((entry) => entry.split(",")),
        {
          allowIncomplete: flagBoolean(flags, "incomplete"),
        },
      ),
    );
    context.success(`Revoked "${recipient}" from ${environments.join(", ")}`);
    reportRevoke(context, recipient, result);
  },
};

const syncCommand: Command = {
  name: "sync",
  args: "",
  summary: "Re-encrypt values whose recipients changed",
  async run(context, _args, flags) {
    const identities = await context.requireIdentities();
    const environments = flagList(flags, "env");
    const result = context.update((document) =>
      sync(document, identities, environments.length ? { environments } : {}),
    );
    if (!result.updated.length && !result.skipped.length) {
      context.success("Everything is up to date");
    }
    reportSync(context, result);
    return result.skipped.length ? 1 : 0;
  },
};

// Runtime

async function decryptEnvironment(
  context: Context,
  flags: Flags,
): Promise<{ environment: string; values: Readonly<Record<string, string>> }> {
  const document = context.document();
  const environment = singleEnvironment(context, document, flags);
  const loaded = await context.loadedIdentities();
  const source: IdentitySource = { label: "msecrets CLI", load: () => loaded };
  return {
    environment,
    values: createClient(document, { env: environment, identities: [source] }),
  };
}

const run: Command = {
  name: "run",
  args: "[--env NAME] -- <COMMAND> [ARGS...]",
  summary: "Run a command with the secrets of an environment as environment variables",
  passthrough: true,
  options: {
    override: {
      type: "boolean",
      description: "Let secrets override variables that are already set",
    },
  },
  async run(context, args, flags) {
    if (!args.length) {
      throw new MsecretsError(
        "USAGE",
        "No command given; usage: msecrets run [--env NAME] -- <command> [args...]",
      );
    }
    const { environment, values } = await decryptEnvironment(context, flags);

    const env = await context.childEnv();
    const override = flagBoolean(flags, "override");
    const injected = Object.entries(values).filter(([name]) => override || env[name] === undefined);
    for (const [name, value] of injected) {
      env[name] = value;
    }
    if (context.io.stderr.isTTY) {
      context.note(context.err.dim(`msecrets: ${injected.length} secret(s) from "${environment}"`));
    }

    return runToCompletion(
      spawnCommand(args, { env, cwd: context.io.cwd }),
      Boolean(context.io.stdin.isTTY),
    );
  },
};

const FORMATS: Record<string, (values: Readonly<Record<string, string>>) => string> = {
  dotenv: formatDotenv,
  json: (values) => `${JSON.stringify(values, null, 2)}\n`,
  shell: formatShell,
  powershell: formatPowerShell,
};

const exportCommand: Command = {
  name: "export",
  args: "",
  summary: "Print the decrypted environment (dotenv, json, shell, powershell)",
  options: {
    format: {
      type: "string",
      description: "dotenv (default), json, shell, or powershell",
      placeholder: "FORMAT",
    },
  },
  async run(context, _args, flags) {
    const format = flagString(flags, "format") ?? "dotenv";
    const render = FORMATS[format];
    if (!render) {
      throw new MsecretsError(
        "USAGE",
        `Unknown --format "${format}"; use ${Object.keys(FORMATS).join(", ")}`,
      );
    }
    context.io.stdout.write(render((await decryptEnvironment(context, flags)).values));
  },
};

const importCommand: Command = {
  name: "import",
  args: "<FILE | ->",
  summary: "Import a dotenv file into an environment",
  options: { overwrite: { type: "boolean", description: "Replace values that already exist" } },
  async run(context, args, flags) {
    requireArgs(args, 1, "import <FILE | -> [--env NAME]");
    const text =
      args[0] === "-"
        ? await readAll(context.io.stdin)
        : readFileSync(resolve(context.io.cwd, args[0] ?? ""), "utf8");
    const entries = parseDotenv(text);
    const identities = await context.requireIdentities();
    const overwrite = flagBoolean(flags, "overwrite");

    const { environment, imported, skipped } = context.update((document) => {
      const target = singleEnvironment(context, document, flags);
      const done: string[] = [];
      const kept: string[] = [];
      for (const [name, value] of entries) {
        const existing = own(document.secrets, name);
        if (existing && own(existing.values, target) && !overwrite) {
          kept.push(name);
          continue;
        }
        setValue(document, identities, {
          secret: name,
          environment: target,
          value,
          ...(context.options.as ? { as: context.options.as } : {}),
        });
        done.push(name);
      }
      return { environment: target, imported: done, skipped: kept };
    });

    context.success(`Imported ${imported.length} secret(s) into "${environment}"`);
    if (skipped.length) {
      context.note(`Kept existing values (use --overwrite to replace): ${skipped.join(", ")}`);
    }
  },
};

// Git

function git(context: Context, args: string[]): string {
  return execFileSync("git", args, {
    cwd: context.io.cwd,
    env: context.io.env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

/** Reads a text file, or returns undefined when it does not exist (no separate existence check to race with). */
function readIfExists(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

/** How git should invoke this CLI: the same Node.js binary and script that runs now. */
function selfCommand(): string {
  const script = process.argv[1] ? realpathSync(process.argv[1]) : "";
  return [process.execPath, script].map((part) => `"${part.replace(/\\/g, "/")}"`).join(" ");
}

const gitSetup: Command = {
  name: "git setup",
  args: "",
  summary: "Configure readable diffs and a structural merge driver for this repository",
  async run(context) {
    const root = git(context, ["rev-parse", "--show-toplevel"]);
    const attributes = join(root, ".gitattributes");
    const line = `${DEFAULT_FILENAME} diff=msecrets merge=msecrets`;
    const current = readIfExists(attributes) ?? "";
    if (!current.split(/\r?\n/).includes(line)) {
      appendFileSync(attributes, `${current && !current.endsWith("\n") ? "\n" : ""}${line}\n`);
    }

    const command = selfCommand();
    git(context, ["config", "diff.msecrets.textconv", `${command} git textconv`]);
    git(context, ["config", "merge.msecrets.name", "msecrets structural merge"]);
    git(context, ["config", "merge.msecrets.driver", `${command} git merge-driver %O %A %B %P`]);

    context.success("Configured .gitattributes (commit it) and this clone's git config");
    if (/[\\/]_npx[\\/]/.test(command)) {
      context.warn(
        "msecrets runs from the temporary npx cache, which npm may delete. Install it (`npm install --save-dev @msecrets/ui`) and run `msecrets git setup` again.",
      );
    }
    context.note(
      context.err.dim(
        "Every clone runs `msecrets git setup` once; git config is not shared through the repository.",
      ),
    );
  },
};

const gitTextconv: Command = {
  name: "git textconv",
  args: "<FILE>",
  summary: "Render a secrets file readably (used by git diff)",
  async run(context, args) {
    requireArgs(args, 1, "git textconv <FILE>");
    context.io.stdout.write(
      renderForDiff(readFileSync(resolve(context.io.cwd, args[0] ?? ""), "utf8")),
    );
  },
};

const gitMergeDriver: Command = {
  name: "git merge-driver",
  args: "<BASE> <OURS> <THEIRS> [PATH]",
  summary: "Three-way structural merge (used by git merge)",
  async run(context, args) {
    requireArgs(args, 3, "git merge-driver <BASE> <OURS> <THEIRS> [PATH]");
    const [base = "", ours = "", theirs = "", path = DEFAULT_FILENAME] = args;
    const read = (file: string) => readFileSync(resolve(context.io.cwd, file), "utf8");
    const result = mergeDocuments(read(base), read(ours), read(theirs));
    writeFileSync(resolve(context.io.cwd, ours), result.text);
    if (result.conflicts.length) {
      context.note(
        `msecrets: conflicting changes in ${path} (kept your side):\n${result.conflicts.map((conflict) => `  ${conflict}`).join("\n")}\nResolve them with msecrets commands, then \`git add ${path}\`.`,
      );
      return 1;
    }
    return 0;
  },
};

// AI agents

/** Published next to dist/ and src/, so the same relative URL works from source and from the bundle. */
const SKILL_FILE = new URL("../skills/msecrets/SKILL.md", import.meta.url);
/** Claude Code reads .claude/skills; Codex, Cursor, GitHub Copilot, Gemini CLI, and others read .agents/skills. */
const SKILL_DIRECTORIES = [".claude/skills", ".agents/skills"];

function projectRoot(context: Context): string {
  try {
    return git(context, ["rev-parse", "--show-toplevel"]);
  } catch {
    // Not a git repository (or no git): the working directory is the project.
    return context.io.cwd;
  }
}

const skill: Command = {
  name: "skill",
  args: "",
  summary:
    "Install the msecrets skill for AI coding agents (Claude Code, Codex, Cursor, Copilot, …)",
  options: {
    global: {
      type: "boolean",
      description: "Install for your user account instead of this project",
    },
    print: { type: "boolean", description: "Print the skill instead of installing it" },
  },
  async run(context, _args, flags) {
    const content = readFileSync(SKILL_FILE, "utf8");
    if (flagBoolean(flags, "print")) {
      context.io.stdout.write(content);
      return;
    }

    const global = flagBoolean(flags, "global");
    const root = global
      ? (context.io.env["HOME"] ?? context.io.env["USERPROFILE"] ?? homedir())
      : projectRoot(context);
    for (const directory of SKILL_DIRECTORIES) {
      const path = join(root, directory, "msecrets", "SKILL.md");
      const current = readIfExists(path);
      if (current === content) {
        context.note(`Up to date: ${displayPath(context, path)}`);
        continue;
      }
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      context.success(
        `${current === undefined ? "Installed" : "Updated"} ${displayPath(context, path)}`,
      );
    }
    context.note(
      context.err.dim(
        global
          ? "Agents now know msecrets in every project. Run `msecrets skill --global` again after upgrading."
          : "Commit these files so every teammate's agent knows msecrets. Run `msecrets skill` again after upgrading.",
      ),
    );
  },
};

export const COMMANDS: readonly Command[] = [
  init,
  joinCommand,
  whoami,
  identityNew,
  identityShow,
  identityExport,
  identityUse,
  ls,
  check,
  get,
  set,
  unset,
  rm,
  mv,
  describe,
  scope,
  envLs,
  envAdd,
  envRm,
  envMv,
  recipientLs,
  recipientAdd,
  recipientRm,
  recipientMv,
  recipientRotate,
  grant,
  revoke,
  syncCommand,
  run,
  exportCommand,
  importCommand,
  gitSetup,
  gitTextconv,
  gitMergeDriver,
  skill,
];
