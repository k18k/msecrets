import { parseArgs } from "node:util";

import { MsecretsError, suggest } from "../../core/src/index.ts";
import packageJson from "../package.json" with { type: "json" };
import {
  COMMANDS,
  type Command,
  type Flags,
  type OptionSpec,
  flagList,
  flagString,
} from "./commands.ts";
import { Context } from "./context.ts";
import { CancelledError, type Io, createColors, colorsEnabled, table } from "./terminal.ts";
import { runTui } from "./tui/app.ts";

export const VERSION: string = packageJson.version;

const GLOBAL_OPTIONS: Record<string, OptionSpec> = {
  file: {
    type: "string",
    short: "f",
    description:
      "Secrets file (default: MSECRETS_FILE, else .env.ms.json here or in a parent directory)",
    placeholder: "PATH",
  },
  env: {
    type: "string",
    short: "e",
    multiple: true,
    description: "Environment (default: MSECRETS_ENV, else development, else the only one)",
    placeholder: "NAME",
  },
  identity: {
    type: "string",
    short: "i",
    multiple: true,
    description: "Identity source or key to use instead of the defaults",
    placeholder: "SOURCE",
  },
  as: { type: "string", description: "Sign changes as this recipient", placeholder: "RECIPIENT" },
  help: { type: "boolean", short: "h", description: "Show help" },
};

const GROUPS: [string, string[]][] = [
  [
    "Get started",
    ["init", "join", "whoami", "identity new", "identity show", "identity use", "identity export"],
  ],
  ["Secrets", ["ls", "get", "set", "unset", "rm", "mv", "describe", "scope"]],
  ["Environments", ["env ls", "env add", "env rm", "env mv"]],
  [
    "Access",
    [
      "recipient ls",
      "recipient add",
      "recipient rm",
      "recipient mv",
      "recipient rotate",
      "grant",
      "revoke",
      "sync",
    ],
  ],
  ["Run your app", ["run", "export", "import"]],
  ["CI and git", ["check", "git setup", "git textconv", "git merge-driver"]],
];

function optionRows(options: Record<string, OptionSpec>): string[][] {
  return Object.entries(options).map(([name, spec]) => [
    `  ${spec.short ? `-${spec.short}, ` : "    "}--${name}${spec.type === "string" ? ` ${spec.placeholder ?? "VALUE"}` : ""}`,
    spec.description,
  ]);
}

function generalHelp(io: Io): string {
  const c = createColors(colorsEnabled(io.stdout, io.env));
  const byName = new Map(COMMANDS.map((command) => [command.name, command]));
  const lines = [
    `${c.bold("msecrets")} ${VERSION}: encrypted secrets that live in your repository`,
    "",
    `${c.bold("Usage:")} msecrets <command> [options]`,
    `       msecrets              ${c.dim("open the interactive terminal UI")}`,
  ];
  for (const [title, names] of GROUPS) {
    lines.push("", c.bold(`${title}:`));
    lines.push(
      ...table(
        names.flatMap((name) => {
          const command = byName.get(name);
          return command
            ? [
                [
                  `  ${command.name}${command.args ? ` ${command.args}` : ""}`,
                  c.dim(command.summary),
                ],
              ]
            : [];
        }),
      ),
    );
  }
  lines.push("", c.bold("Global options:"), ...table(optionRows(GLOBAL_OPTIONS)));
  lines.push(
    "",
    `Run ${c.cyan("msecrets <command> --help")} for details. Docs: https://k18k.github.io/msecrets/`,
  );
  return `${lines.join("\n")}\n`;
}

function commandHelp(io: Io, command: Command): string {
  const c = createColors(colorsEnabled(io.stdout, io.env));
  const lines = [
    `${c.bold("Usage:")} msecrets ${command.name}${command.args ? ` ${command.args}` : ""} [options]`,
    "",
    command.summary,
  ];
  if (command.options && Object.keys(command.options).length) {
    lines.push("", c.bold("Options:"), ...table(optionRows(command.options)));
  }
  lines.push("", c.bold("Global options:"), ...table(optionRows(GLOBAL_OPTIONS)));
  return `${lines.join("\n")}\n`;
}

function findCommand(argv: readonly string[]): { command: Command; rest: string[] } {
  const words = argv.slice(0, 2);
  const command =
    COMMANDS.find((candidate) => candidate.name === words.join(" ")) ??
    COMMANDS.find((candidate) => candidate.name === words[0]);
  if (!command) {
    const groups = new Set(
      COMMANDS.filter((candidate) => candidate.name.includes(" ")).map(
        (candidate) => candidate.name.split(" ")[0],
      ),
    );
    const first = words[0] ?? "";
    const hint = groups.has(first)
      ? ` (try: ${COMMANDS.filter((candidate) => candidate.name.startsWith(`${first} `))
          .map((candidate) => candidate.name)
          .join(", ")})`
      : suggest(
          first,
          COMMANDS.map((candidate) => candidate.name.split(" ")[0] ?? ""),
        );
    throw new MsecretsError(
      "USAGE",
      `Unknown command "${words.join(" ")}"${hint}. Run \`msecrets --help\``,
    );
  }
  return { command, rest: argv.slice(command.name.split(" ").length) };
}

type ParseOptions = Record<
  string,
  { type: "string" | "boolean"; short?: string; multiple?: boolean }
>;

function toParseOptions(options: Record<string, OptionSpec>): ParseOptions {
  return Object.fromEntries(
    Object.entries(options).map(([name, spec]) => [
      name,
      {
        type: spec.type,
        ...(spec.short ? { short: spec.short } : {}),
        ...(spec.multiple ? { multiple: true } : {}),
      },
    ]),
  );
}

/** For pass-through commands: options up to `--` or the first positional, then the command verbatim. */
function splitPassthrough(
  rest: readonly string[],
  options: ParseOptions,
): { optionArgs: string[]; passthrough: string[] } {
  const takesValue = (token: string) => {
    if (token.includes("=")) {
      return false;
    }
    const spec = token.startsWith("--")
      ? options[token.slice(2)]
      : Object.values(options).find((candidate) => candidate.short === token.slice(1));
    return spec?.type === "string";
  };

  for (let index = 0; index < rest.length; index++) {
    const token = rest[index] ?? "";
    if (token === "--") {
      return { optionArgs: rest.slice(0, index), passthrough: rest.slice(index + 1) };
    }
    if (!token.startsWith("-") || token === "-") {
      return { optionArgs: rest.slice(0, index), passthrough: rest.slice(index) };
    }
    if (takesValue(token)) {
      index++;
    }
  }
  return { optionArgs: [...rest], passthrough: [] };
}

/** Leading global options, e.g. `msecrets -f other.json ls`. */
function splitLeadingGlobals(argv: readonly string[]): { globals: string[]; rest: string[] } {
  const options = toParseOptions(GLOBAL_OPTIONS);
  const { optionArgs, passthrough } = splitPassthrough(argv, options);
  return { globals: optionArgs, rest: passthrough };
}

function errorExitCode(error: unknown): number {
  if (error instanceof CancelledError) {
    return 130;
  }
  return error instanceof MsecretsError && error.code === "USAGE" ? 2 : 1;
}

export async function main(argv: readonly string[], io: Io): Promise<number> {
  const c = createColors(colorsEnabled(io.stderr, io.env));
  try {
    if (argv[0] === "--version" || argv[0] === "-v" || argv[0] === "version") {
      io.stdout.write(`${VERSION}\n`);
      return 0;
    }
    if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
      const topic = argv.slice(1);
      io.stdout.write(topic.length ? commandHelp(io, findCommand(topic).command) : generalHelp(io));
      return 0;
    }

    const { globals, rest: commandArgv } = splitLeadingGlobals(argv);
    const [first] = commandArgv;
    if (first === undefined && globals.some((token) => token === "-h" || token === "--help")) {
      io.stdout.write(generalHelp(io));
      return 0;
    }
    if (first === undefined || first === "tui") {
      const { values } = parseArgs({
        args: [...globals, ...commandArgv.slice(1)],
        options: toParseOptions(GLOBAL_OPTIONS),
        strict: true,
      });
      if (!io.stdin.isTTY || !io.stdout.isTTY) {
        if (first === "tui") {
          throw new MsecretsError("USAGE", "The terminal UI needs an interactive terminal");
        }
        io.stdout.write(generalHelp(io));
        return 0;
      }
      const flags = values as Flags;
      return await runTui(new Context(io, contextOptions(flags)));
    }

    const { command, rest } = findCommand(commandArgv);
    const options = toParseOptions({ ...GLOBAL_OPTIONS, ...command.options });
    const { optionArgs, passthrough } = command.passthrough
      ? splitPassthrough(rest, options)
      : { optionArgs: rest, passthrough: [] };

    let parsed: { values: Flags; positionals: string[] };
    try {
      parsed = parseArgs({
        args: [...globals, ...optionArgs],
        options,
        allowPositionals: !command.passthrough,
        strict: true,
      }) as {
        values: Flags;
        positionals: string[];
      };
    } catch (error) {
      throw new MsecretsError(
        "USAGE",
        `${(error as Error).message}. Run \`msecrets ${command.name} --help\``,
        {
          cause: error,
        },
      );
    }

    if (parsed.values["help"] === true) {
      io.stdout.write(commandHelp(io, command));
      return 0;
    }

    const context = new Context(io, contextOptions(parsed.values));
    return (
      (await command.run(
        context,
        command.passthrough ? passthrough : parsed.positionals,
        parsed.values,
      )) ?? 0
    );
  } catch (error) {
    if (error instanceof CancelledError) {
      io.stderr.write("\n");
      return 130;
    }
    const message = error instanceof Error ? error.message : String(error);
    io.stderr.write(`${c.red("msecrets:")} ${message}\n`);
    if (!(error instanceof MsecretsError) && io.env["MSECRETS_DEBUG"] && error instanceof Error) {
      io.stderr.write(`${error.stack ?? ""}\n`);
    }
    return errorExitCode(error);
  }
}

function contextOptions(flags: Flags): ConstructorParameters<typeof Context>[1] {
  return {
    file: flagString(flags, "file"),
    env: flagList(flags, "env")[0],
    identity: flagList(flags, "identity").length ? (flags["identity"] as string[]) : undefined,
    as: flagString(flags, "as"),
  };
}
