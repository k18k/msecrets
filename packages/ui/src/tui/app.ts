import { constants } from "node:os";
import { isAbsolute, relative } from "node:path";

import {
  type CellState,
  type Identity,
  MsecretsError,
  type Report,
  type RevokeResult,
  type SecretsDocument,
  type SyncResult,
  addEnvironment,
  addRecipient,
  deleteSecret,
  describeRecipient,
  describeSecret,
  grantAccess,
  inspect,
  members,
  own,
  recipientKey,
  removeEnvironment,
  removeRecipient,
  renameEnvironment,
  renameRecipient,
  renameSecret,
  requireName,
  revealValue,
  revokeAccess,
  setValue,
  sync,
  unsetValue,
} from "../../../core/src/index.ts";
import type { Context } from "../context.ts";
import { CELL_DESCRIPTIONS, type Symbols, cellStyle } from "../symbols.ts";
import { type Colors, padEnd, sanitize, visibleLength } from "../terminal.ts";
import { type Key, KeyReader, decodeKeys } from "./keys.ts";

type View = "secrets" | "environments" | "recipients" | "checks";

const VIEWS: { id: View; title: string }[] = [
  { id: "secrets", title: "Secrets" },
  { id: "environments", title: "Environments" },
  { id: "recipients", title: "Recipients" },
  { id: "checks", title: "Checks" },
];

type Submit = (value: string) => void;

type Modal =
  | {
      kind: "input";
      title: string;
      hint: string;
      value: string;
      cursor: number;
      hidden: boolean;
      revealed: boolean;
      submit: Submit;
    }
  | { kind: "confirm"; title: string; lines: string[]; accept: () => void }
  | { kind: "message"; title: string; lines: string[]; copy?: string }
  | { kind: "pick"; title: string; options: string[]; index: number; submit: Submit }
  | { kind: "help" };

type Status = { text: string; tone: "success" | "error" | "info" };

const HELP: [string, string][] = [
  ["1-4, tab", "switch view"],
  ["↑↓ ←→, hjkl", "move"],
  ["enter, e", "edit the selected value"],
  ["v", "reveal the selected value (c copies it)"],
  ["a", "add (secret, environment, or recipient)"],
  ["r", "rename"],
  ["d", "delete / remove"],
  ["u", "unset the selected value"],
  ["D", "describe"],
  ["g / x", "grant / revoke access"],
  ["s", "sync: re-encrypt for current recipients"],
  ["/", "filter secrets"],
  ["q, ctrl-c", "quit"],
];

const ANSI_TOKEN = /(\u001b\[[0-9;?]*[A-Za-z]|\u001b\][^\u0007]*\u0007)/;

/** Truncates to a visible width (ANSI-aware) and pads to exactly that width. */
export function fit(text: string, width: number): string {
  if (visibleLength(text) <= width) {
    return padEnd(text, width);
  }
  let result = "";
  let used = 0;
  for (const part of text.split(ANSI_TOKEN)) {
    if (ANSI_TOKEN.test(part)) {
      result += part;
      continue;
    }
    for (const char of part) {
      if (used >= width - 1) {
        return `${result}…\u001b[0m`;
      }
      result += char;
      used++;
    }
  }
  return `${result}\u001b[0m`;
}

function firstLine(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).split("\n")[0] ?? "";
}

export class TuiApp {
  readonly context: Context;
  readonly identities: Identity[];
  readonly identityProblem: string | null;
  readonly c: Colors;
  readonly symbols: Symbols;
  readonly write: (text: string) => void;
  document: SecretsDocument;
  report: Report;
  view: View = "secrets";
  row = 0;
  column = 0;
  scroll = 0;
  filter = "";
  modals: Modal[] = [];
  status: Status | null = null;
  done = false;

  constructor(
    context: Context,
    identities: Identity[],
    identityProblem: string | null,
    write: (text: string) => void,
  ) {
    this.context = context;
    this.identities = identities;
    this.identityProblem = identityProblem;
    this.write = write;
    this.c = context.out;
    this.symbols = context.symbols;
    this.document = context.document();
    this.report = inspect(this.document);
    if (identityProblem) {
      this.status = { text: `Read-only: ${identityProblem}`, tone: "error" };
    }
  }

  // Data

  reload(): void {
    this.document = this.context.document();
    this.report = inspect(this.document);
    this.row = Math.max(0, Math.min(this.row, this.rowCount() - 1));
    this.column = Math.max(0, Math.min(this.column, this.environments().length - 1));
  }

  environments(): string[] {
    return Object.keys(this.document.environments);
  }

  secrets(): string[] {
    const filter = this.filter.toLowerCase();
    return Object.keys(this.document.secrets).filter((name) => name.toLowerCase().includes(filter));
  }

  recipients(): string[] {
    return Object.keys(this.document.recipients);
  }

  mine(): string[] {
    return members(this.document, this.identities).map((member) => member.name);
  }

  rowCount(): number {
    switch (this.view) {
      case "secrets":
        return this.secrets().length;
      case "environments":
        return this.environments().length;
      case "recipients":
        return this.recipients().length;
      case "checks":
        return this.report.findings.length;
    }
  }

  cell(secret: string, environment: string): CellState {
    return (
      this.report.cells.find((cell) => cell.secret === secret && cell.environment === environment)
        ?.state ?? "absent"
    );
  }

  selectedSecret(): string | undefined {
    return this.secrets()[this.row];
  }

  selectedEnvironment(): string | undefined {
    return this.view === "environments"
      ? this.environments()[this.row]
      : this.environments()[this.column];
  }

  selectedRecipient(): string | undefined {
    return this.recipients()[this.row];
  }

  mutate<T>(change: (document: SecretsDocument) => T): T {
    const result = this.context.update(change);
    this.reload();
    return result;
  }

  requireIdentities(): Identity[] {
    if (!this.identities.length) {
      throw new Error(
        this.identityProblem ?? "No identity loaded; run `msecrets identity new` first",
      );
    }
    return this.identities;
  }

  // Feedback

  succeed(text: string): void {
    this.status = { text, tone: "success" };
  }

  fail(error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("\n")) {
      this.modals.push({ kind: "message", title: "Error", lines: message.split("\n") });
    }
    this.status = { text: firstLine(error), tone: "error" };
  }

  reportSync(result: SyncResult, prefix = ""): void {
    const lines = [
      `${prefix}${result.updated.length} value(s) re-encrypted for the current recipients.`,
      ...(result.skipped.length
        ? [
            "",
            `${result.skipped.length} value(s) need a member with access to run sync:`,
            ...result.skipped.map((slot) => `  ${slot.secret} in ${slot.environment}`),
          ]
        : []),
    ];
    if (result.skipped.length) {
      this.modals.push({ kind: "message", title: "Sync", lines });
    }
    this.succeed(lines[0] ?? "");
  }

  reportRevoke(recipient: string, result: RevokeResult): void {
    const secrets = [
      ...new Set(result.rotate.map((slot) => `${slot.secret} (${slot.environment})`)),
    ];
    this.modals.push({
      kind: "message",
      title: "Access revoked",
      lines: [
        `${result.updated.length} value(s) re-encrypted without "${recipient}".`,
        ...(secrets.length
          ? [
              "",
              `"${recipient}" could read these and may have copies. Rotate them:`,
              ...secrets.map((entry) => `  ${entry}`),
            ]
          : []),
      ],
    });
    this.succeed(`Revoked "${recipient}"`);
  }

  input(
    title: string,
    hint: string,
    submit: Submit,
    options: { value?: string; hidden?: boolean } = {},
  ): void {
    const value = options.value ?? "";
    this.modals.push({
      kind: "input",
      title,
      hint,
      value,
      cursor: [...value].length,
      hidden: options.hidden ?? false,
      revealed: false,
      submit,
    });
  }

  confirm(title: string, lines: string[], accept: () => void): void {
    this.modals.push({ kind: "confirm", title, lines, accept });
  }

  pick(title: string, options: string[], submit: Submit): void {
    if (!options.length) {
      this.status = { text: `Nothing to choose for: ${title}`, tone: "info" };
      return;
    }
    this.modals.push({ kind: "pick", title, options, index: 0, submit });
  }

  // Input handling

  async feed(input: string): Promise<void> {
    for (const key of decodeKeys(input)) {
      await this.handle(key);
      if (this.done) {
        return;
      }
    }
  }

  async handle(key: Key): Promise<void> {
    const modal = this.modals[this.modals.length - 1];
    try {
      if (modal) {
        this.handleModal(modal, key);
      } else {
        this.handleView(key);
      }
    } catch (error) {
      this.fail(error);
    }
  }

  closeModal(): void {
    this.modals.pop();
  }

  handleModal(modal: Modal, key: Key): void {
    if (key.name === "ctrl" && key.char === "c") {
      this.modals = [];
      return;
    }

    switch (modal.kind) {
      case "help":
        this.closeModal();
        return;

      case "message":
        if (key.name === "char" && key.char === "c" && modal.copy !== undefined) {
          // OSC 52: most terminals put this on the system clipboard.
          this.write(`\u001b]52;c;${Buffer.from(modal.copy).toString("base64")}\u0007`);
          this.succeed("Copied to the clipboard (if your terminal supports OSC 52)");
        }
        this.closeModal();
        return;

      case "confirm":
        if (key.name === "char" && (key.char === "y" || key.char === "Y")) {
          this.closeModal();
          modal.accept();
        } else if (
          key.name === "escape" ||
          (key.name === "char" && (key.char === "n" || key.char === "N")) ||
          key.name === "enter"
        ) {
          this.closeModal();
        }
        return;

      case "pick":
        if (key.name === "up" || (key.name === "char" && key.char === "k")) {
          modal.index = Math.max(0, modal.index - 1);
        } else if (key.name === "down" || (key.name === "char" && key.char === "j")) {
          modal.index = Math.min(modal.options.length - 1, modal.index + 1);
        } else if (key.name === "enter") {
          this.closeModal();
          modal.submit(modal.options[modal.index] ?? "");
        } else if (key.name === "escape") {
          this.closeModal();
        }
        return;

      case "input": {
        const chars = [...modal.value];
        switch (key.name) {
          case "enter": {
            this.closeModal();
            modal.submit(modal.value);
            return;
          }
          case "escape":
            this.closeModal();
            return;
          case "tab":
            modal.revealed = !modal.revealed;
            return;
          case "left":
            modal.cursor = Math.max(0, modal.cursor - 1);
            return;
          case "right":
            modal.cursor = Math.min(chars.length, modal.cursor + 1);
            return;
          case "home":
            modal.cursor = 0;
            return;
          case "end":
            modal.cursor = chars.length;
            return;
          case "backspace":
            if (modal.cursor > 0) {
              chars.splice(modal.cursor - 1, 1);
              modal.cursor--;
            }
            break;
          case "delete":
            chars.splice(modal.cursor, 1);
            break;
          case "ctrl":
            if (key.char === "u") {
              chars.splice(0, modal.cursor);
              modal.cursor = 0;
            }
            break;
          case "char":
            chars.splice(modal.cursor, 0, key.char);
            modal.cursor++;
            break;
          default:
            return;
        }
        modal.value = chars.join("");
        return;
      }
    }
  }

  handleView(key: Key): void {
    const char = key.name === "char" ? key.char : "";
    const count = this.rowCount();

    if ((key.name === "ctrl" && key.char === "c") || char === "q") {
      this.done = true;
      return;
    }
    if (key.name === "escape" && this.filter) {
      this.filter = "";
      this.reload();
      return;
    }
    if (char === "?") {
      this.modals.push({ kind: "help" });
      return;
    }
    if (key.name === "tab" || key.name === "shift-tab" || /^[1-4]$/.test(char)) {
      const current = VIEWS.findIndex((view) => view.id === this.view);
      const next = /^[1-4]$/.test(char)
        ? Number(char) - 1
        : (current + (key.name === "shift-tab" ? VIEWS.length - 1 : 1)) % VIEWS.length;
      this.view = VIEWS[next]?.id ?? "secrets";
      this.row = 0;
      this.scroll = 0;
      this.status = null;
      return;
    }

    if (key.name === "up" || char === "k") {
      this.row = Math.max(0, this.row - 1);
    } else if (key.name === "down" || char === "j") {
      this.row = Math.min(count - 1, this.row + 1);
    } else if (key.name === "pageup") {
      this.row = Math.max(0, this.row - 10);
    } else if (key.name === "pagedown") {
      this.row = Math.max(0, Math.min(count - 1, this.row + 10));
    } else if (key.name === "home") {
      this.row = 0;
    } else if (key.name === "end") {
      this.row = Math.max(0, count - 1);
    } else if (this.view === "secrets") {
      this.handleSecretsKey(key, char);
    } else if (this.view === "environments") {
      this.handleEnvironmentsKey(char);
    } else if (this.view === "recipients") {
      this.handleRecipientsKey(char);
    } else if (char === "s") {
      this.runSync();
    } else if (key.name === "enter") {
      this.jumpToFinding();
    }
    this.row = Math.max(0, Math.min(this.row, this.rowCount() - 1));
  }

  runSync(): void {
    const identities = this.requireIdentities();
    this.reportSync(this.mutate((document) => sync(document, identities)));
  }

  jumpToFinding(): void {
    const finding = this.report.findings[this.row];
    if (finding?.secret) {
      this.view = "secrets";
      this.filter = "";
      this.row = Math.max(0, this.secrets().indexOf(finding.secret));
      this.column = Math.max(0, this.environments().indexOf(finding.environment ?? ""));
    } else if (finding?.environment) {
      this.view = "environments";
      this.row = Math.max(0, this.environments().indexOf(finding.environment));
    } else if (finding?.recipient) {
      this.view = "recipients";
      this.row = Math.max(0, this.recipients().indexOf(finding.recipient));
    }
  }

  editValue(secret: string, environment: string): void {
    const identities = this.requireIdentities();
    let current = "";
    const value = own(this.document.secrets, secret)?.values[environment];
    const cell = (document: SecretsDocument) => own(document.secrets, secret)?.values[environment];
    if (value) {
      try {
        current = revealValue(this.document, identities, secret, environment);
      } catch {
        // Not readable for us: start from an empty value.
        current = "";
      }
    }
    this.input(
      `${secret} in ${environment}`,
      "enter save · esc cancel · tab show/hide",
      (next) => {
        this.mutate((document) => {
          // The file may have changed since the form opened (another terminal, a git pull).
          if (cell(document)?.data !== value?.data) {
            throw new MsecretsError(
              "CONFLICT",
              `${secret} in ${environment} changed while you were editing it; nothing was saved. Open it again to see the new value`,
            );
          }
          setValue(document, identities, { secret, environment, value: next });
        });
        this.succeed(`Set ${secret} in ${environment}`);
      },
      { value: current, hidden: true },
    );
  }

  handleSecretsKey(key: Key, char: string): void {
    const secret = this.selectedSecret();
    const environment = this.selectedEnvironment();

    if (key.name === "left" || char === "h") {
      this.column = Math.max(0, this.column - 1);
    } else if (key.name === "right" || char === "l") {
      this.column = Math.min(this.environments().length - 1, this.column + 1);
    } else if (char === "/") {
      this.input(
        "Filter secrets",
        "enter apply · empty clears",
        (value) => {
          this.filter = value.trim();
          this.row = 0;
        },
        { value: this.filter },
      );
    } else if (char === "a") {
      this.input("New secret name", "letters, digits, underscores", (name) => {
        const secretName = requireName("secret", name.trim());
        if (own(this.document.secrets, secretName)) {
          throw new Error(`Secret ${secretName} already exists`);
        }
        const target = environment ?? this.environments()[0];
        if (!target) {
          throw new Error("Add an environment first (view 2)");
        }
        this.editValue(secretName, target);
      });
    } else if (char === "s") {
      this.runSync();
    } else if (!secret || !environment) {
      return;
    } else if (key.name === "enter" || char === "e") {
      this.editValue(secret, environment);
    } else if (char === "v") {
      const value = revealValue(this.document, this.requireIdentities(), secret, environment);
      this.modals.push({
        kind: "message",
        title: `${secret} in ${environment}`,
        lines: [...value.split("\n").map(sanitize), "", "c copy · any other key closes"],
        copy: value,
      });
    } else if (char === "r") {
      this.input(
        `Rename ${secret}`,
        "enter rename · esc cancel",
        (next) => {
          this.mutate((document) => renameSecret(document, this.identities, secret, next.trim()));
          this.succeed(`Renamed ${secret} to ${next.trim()}`);
        },
        { value: secret },
      );
    } else if (char === "d") {
      this.confirm(`Delete ${secret}?`, [`This removes ${secret} from every environment.`], () => {
        this.mutate((document) => deleteSecret(document, secret));
        this.succeed(`Deleted ${secret}`);
      });
    } else if (char === "u") {
      this.confirm(
        `Unset ${secret} in ${environment}?`,
        [`The value in ${environment} will be removed.`],
        () => {
          this.mutate((document) => unsetValue(document, secret, environment));
          this.succeed(`Removed ${secret} from ${environment}`);
        },
      );
    } else if (char === "D") {
      this.input(
        `Describe ${secret}`,
        "empty clears",
        (text) => {
          this.mutate((document) => describeSecret(document, secret, text || undefined));
          this.succeed(`Updated the description of ${secret}`);
        },
        { value: own(this.document.secrets, secret)?.description ?? "" },
      );
    }
  }

  handleEnvironmentsKey(char: string): void {
    const environment = this.selectedEnvironment();

    if (char === "a") {
      this.input("New environment name", "lowercase letters, digits, . _ -", (name) => {
        const recipients = this.mine();
        this.mutate((document) => addEnvironment(document, name.trim(), recipients));
        this.succeed(`Added environment ${name.trim()}`);
      });
    } else if (char === "s") {
      this.runSync();
    } else if (!environment) {
      return;
    } else if (char === "r") {
      this.input(
        `Rename ${environment}`,
        "enter rename · esc cancel",
        (next) => {
          this.mutate((document) =>
            renameEnvironment(document, this.identities, environment, next.trim()),
          );
          this.succeed(`Renamed ${environment} to ${next.trim()}`);
        },
        { value: environment },
      );
    } else if (char === "d") {
      this.confirm(
        `Remove ${environment}?`,
        [`All values in ${environment} will be deleted.`],
        () => {
          this.mutate((document) => removeEnvironment(document, environment));
          this.succeed(`Removed environment ${environment}`);
        },
      );
    } else if (char === "g") {
      const current = this.document.environments[environment]?.recipients ?? [];
      this.pick(
        `Grant access to ${environment}`,
        this.recipients().filter((name) => !current.includes(name)),
        (recipient) => {
          this.reportSync(
            this.mutate((document) =>
              grantAccess(document, this.identities, recipient, [environment]),
            ),
            `Granted ${recipient}. `,
          );
        },
      );
    } else if (char === "x") {
      this.pick(
        `Revoke access to ${environment}`,
        this.document.environments[environment]?.recipients ?? [],
        (recipient) => {
          this.reportRevoke(
            recipient,
            this.mutate((document) =>
              revokeAccess(document, this.identities, recipient, [environment]),
            ),
          );
        },
      );
    }
  }

  handleRecipientsKey(char: string): void {
    const recipient = this.selectedRecipient();

    if (char === "a") {
      this.input("New recipient name", "lowercase letters, digits, . _ @ + -", (name) => {
        const recipientName = requireName("recipient", name.trim());
        this.input(
          `Public key of ${recipientName}`,
          "msecrets1…, age1…, or ssh-ed25519 … (paste)",
          (key) => {
            this.mutate((document) => addRecipient(document, recipientName, key.trim()));
            this.succeed(`Added ${recipientName}; grant access with g`);
          },
        );
      });
    } else if (!recipient) {
      return;
    } else if (char === "r") {
      this.input(
        `Rename ${recipient}`,
        "enter rename · esc cancel",
        (next) => {
          this.mutate((document) => renameRecipient(document, recipient, next.trim()));
          this.succeed(`Renamed ${recipient} to ${next.trim()}`);
        },
        { value: recipient },
      );
    } else if (char === "d") {
      this.confirm(
        `Remove ${recipient}?`,
        ["Their access is revoked and values are re-encrypted without them."],
        () => {
          this.reportRevoke(
            recipient,
            this.mutate((document) => removeRecipient(document, this.identities, recipient)),
          );
        },
      );
    } else if (char === "D") {
      this.input(
        `Describe ${recipient}`,
        "empty clears",
        (text) => {
          this.mutate((document) => describeRecipient(document, recipient, text || undefined));
          this.succeed(`Updated the description of ${recipient}`);
        },
        { value: this.document.recipients[recipient]?.description ?? "" },
      );
    } else if (char === "g") {
      this.pick(
        `Grant ${recipient} access to`,
        this.environments().filter(
          (name) => !this.document.environments[name]?.recipients.includes(recipient),
        ),
        (environment) => {
          this.reportSync(
            this.mutate((document) =>
              grantAccess(document, this.identities, recipient, [environment]),
            ),
            `Granted ${environment}. `,
          );
        },
      );
    } else if (char === "x") {
      this.pick(
        `Revoke ${recipient} from`,
        this.environments().filter((name) =>
          this.document.environments[name]?.recipients.includes(recipient),
        ),
        (environment) => {
          this.reportRevoke(
            recipient,
            this.mutate((document) =>
              revokeAccess(document, this.identities, recipient, [environment]),
            ),
          );
        },
      );
    }
  }

  // Rendering

  render(width: number, height: number): string[] {
    const c = this.c;
    const me = this.mine();
    const errors = this.report.findings.filter((finding) => finding.level === "error").length;
    const warnings = this.report.findings.length - errors;

    const header = [
      `${c.inverse(c.bold(" msecrets "))} ${this.fileLabel()}  ${c.dim(me.length ? `you: ${me.join(", ")}` : this.identities.length ? "not a recipient" : "no identity")}`,
      VIEWS.map((view, index) => {
        const label = ` ${index + 1} ${view.title} `;
        return view.id === this.view ? c.inverse(label) : c.dim(label);
      }).join(" ") + (this.filter ? c.yellow(`   filter: ${this.filter}`) : ""),
      c.dim(this.symbols.line.repeat(width)),
    ];

    const health =
      errors || warnings
        ? `${errors ? c.red(`${errors} error(s)`) : ""}${errors && warnings ? c.dim(" · ") : ""}${warnings ? c.yellow(`${warnings} warning(s)`) : ""}`
        : c.green(`${this.symbols.check} all values present, current, and signed`);
    const footer = [
      c.dim(this.symbols.line.repeat(width)),
      `${(["ok", "stale", "missing", "invalid"] as const).map((state) => `${cellStyle(c, state)(this.symbols.cell[state])} ${CELL_DESCRIPTIONS[state]}`).join("  ")}   ${health}`,
      c.dim(this.hints()),
      this.status
        ? (this.status.tone === "error"
            ? c.red
            : this.status.tone === "success"
              ? c.green
              : c.cyan)(this.status.text)
        : "",
    ];

    const bodyHeight = Math.max(1, height - header.length - footer.length);
    const body = this.body(bodyHeight, width);
    while (body.length < bodyHeight) {
      body.push("");
    }

    const lines = [...header, ...body.slice(0, bodyHeight), ...footer]
      .slice(0, height)
      .map((line) => fit(line, width));
    const modal = this.modals[this.modals.length - 1];
    return modal ? this.overlay(lines, modal, width, height) : lines;
  }

  /** The secrets file, relative to the working directory when it is inside it. */
  fileLabel(): string {
    const path = relative(this.context.io.cwd, this.context.path);
    return path && !path.startsWith("..") && !isAbsolute(path) ? path : this.context.path;
  }

  hints(): string {
    switch (this.view) {
      case "secrets":
        return "enter edit · v reveal · a add · r rename · d delete · u unset · D describe · s sync · / filter · ? help · q quit";
      case "environments":
        return "a add · r rename · d remove · g grant · x revoke · s sync · ? help · q quit";
      case "recipients":
        return "a add · r rename · d remove · g grant · x revoke · D describe · ? help · q quit";
      case "checks":
        return "enter go to · s sync · ? help · q quit";
    }
  }

  /** Keeps the selected row visible and returns the visible slice of rows. */
  window(rows: string[], height: number): string[] {
    if (this.row < this.scroll) {
      this.scroll = this.row;
    } else if (this.row >= this.scroll + height) {
      this.scroll = this.row - height + 1;
    }
    this.scroll = Math.max(0, Math.min(this.scroll, Math.max(0, rows.length - height)));
    return rows.slice(this.scroll, this.scroll + height);
  }

  body(height: number, width: number): string[] {
    const c = this.c;
    const marker = (selected: boolean) => (selected ? c.cyan(`${this.symbols.arrow} `) : "  ");

    if (this.view === "secrets") {
      const secrets = this.secrets();
      const environments = this.environments();
      if (!secrets.length) {
        return [
          this.filter
            ? `  No secrets match "${this.filter}" (esc clears the filter)`
            : "  No secrets yet. Press a to add one.",
        ];
      }
      const nameWidth = Math.min(
        Math.max(8, ...secrets.map((name) => name.length)) + 2,
        Math.max(12, Math.floor(width / 3)),
      );
      const columnWidths = environments.map((name) => Math.max(name.length, 3) + 2);
      const head = `  ${padEnd(c.bold("SECRET"), nameWidth)}${environments.map((name, index) => padEnd(c.bold(name), columnWidths[index] ?? 5)).join("")}${c.bold("DESCRIPTION")}`;
      const rows = secrets.map((name, rowIndex) => {
        const cells = environments
          .map((environment, columnIndex) => {
            const state = this.cell(name, environment);
            const glyph = cellStyle(c, state)(this.symbols.cell[state]);
            const selected = rowIndex === this.row && columnIndex === this.column;
            // Brackets keep the selection visible without colors (NO_COLOR, monochrome terminals).
            return padEnd(
              selected ? c.inverse(`[${glyph}]`) : ` ${glyph} `,
              columnWidths[columnIndex] ?? 5,
            );
          })
          .join("");
        const label = fit(name, nameWidth - 1);
        return `${marker(rowIndex === this.row)}${padEnd(rowIndex === this.row ? c.bold(label) : label, nameWidth)}${cells}${c.dim(own(this.document.secrets, name)?.description ?? "")}`;
      });
      return [head, ...this.window(rows, height - 1)];
    }

    if (this.view === "environments") {
      const rows = this.environments().map((name, index) => {
        const cells = this.report.cells.filter(
          (cell) => cell.environment === name && cell.state !== "absent",
        );
        const ok = cells.filter((cell) => cell.state === "ok").length;
        const recipients = this.document.environments[name]?.recipients ?? [];
        const count =
          ok === cells.length
            ? c.green(`${ok}/${cells.length}`)
            : c.yellow(`${ok}/${cells.length}`);
        return `${marker(index === this.row)}${padEnd(name, 20)}${padEnd(count, 10)}${recipients.join(", ") || c.yellow("no recipients")}`;
      });
      return [
        `  ${padEnd(c.bold("ENVIRONMENT"), 20)}${padEnd(c.bold("VALUES"), 10)}${c.bold("RECIPIENTS")}`,
        ...this.window(rows, height - 1),
      ];
    }

    if (this.view === "recipients") {
      const mine = new Set(this.mine());
      const rows = this.recipients().map((name, index) => {
        const key = recipientKey(this.document, name);
        const environments = this.environments().filter((environment) =>
          this.document.environments[environment]?.recipients.includes(name),
        );
        const kind = `${key.kind}${key.signingKey ? "" : " (read-only)"}`;
        return `${marker(index === this.row)}${padEnd(`${name}${mine.has(name) ? c.cyan(" (you)") : ""}`, 26)}${padEnd(kind, 28)}${padEnd(environments.join(", ") || c.dim("none"), 30)}${c.dim(this.document.recipients[name]?.description ?? "")}`;
      });
      return [
        `  ${padEnd(c.bold("RECIPIENT"), 26)}${padEnd(c.bold("KEY"), 28)}${padEnd(c.bold("ENVIRONMENTS"), 30)}${c.bold("DESCRIPTION")}`,
        ...this.window(rows, height - 1),
      ];
    }

    if (!this.report.findings.length) {
      return [c.green(`  ${this.symbols.check} Every value is present, current, and signed.`)];
    }
    return this.window(
      this.report.findings.map(
        (finding, index) =>
          `${marker(index === this.row)}${finding.level === "error" ? c.red("error  ") : c.yellow("warning")} ${finding.message}`,
      ),
      height,
    );
  }

  modalContent(modal: Modal, inner: number): { title: string; lines: string[] } {
    const c = this.c;
    switch (modal.kind) {
      case "help":
        return {
          title: "Keys",
          lines: [
            ...HELP.map(([keys, action]) => `${padEnd(c.cyan(keys), 14)}${action}`),
            "",
            c.dim("any key closes"),
          ],
        };
      case "message":
        return { title: modal.title, lines: modal.lines };
      case "confirm":
        return {
          title: modal.title,
          lines: [...modal.lines, "", c.dim("y confirm · n / esc cancel")],
        };
      case "pick":
        return {
          title: modal.title,
          lines: [
            ...modal.options.map((option, index) =>
              index === modal.index ? c.inverse(` ${option} `) : ` ${option} `,
            ),
            "",
            c.dim("↑↓ choose · enter select · esc cancel"),
          ],
        };
      case "input": {
        // One display character per code point keeps the cursor aligned; control characters
        // in a value (escape sequences) are shown, never sent to the terminal.
        const chars = [
          ...(modal.hidden && !modal.revealed ? "•".repeat([...modal.value].length) : modal.value),
        ].map(sanitize);
        const fieldWidth = Math.max(4, inner - 2);
        const start = Math.max(0, modal.cursor - fieldWidth + 1);
        const visible = chars.slice(start, start + fieldWidth);
        const cursor = modal.cursor - start;
        const field = `${visible.slice(0, cursor).join("")}${c.inverse(visible[cursor] ?? " ")}${visible.slice(cursor + 1).join("")}`;
        return {
          title: modal.title,
          lines: [`${c.cyan(this.symbols.arrow)} ${field}`, "", c.dim(modal.hint)],
        };
      }
    }
  }

  overlay(lines: string[], modal: Modal, width: number, height: number): string[] {
    const boxWidth = Math.max(20, Math.min(width - 2, 76));
    const inner = boxWidth - 4;
    const { title, lines: content } = this.modalContent(modal, inner);
    const unicode = this.symbols.check === "✓";
    const [h, v, tl, tr, bl, br] = unicode
      ? ["─", "│", "┌", "┐", "└", "┘"]
      : ["-", "|", "+", "+", "+", "+"];
    const titleText = ` ${fit(title, inner - 2).trimEnd()} `;
    const box = [
      `${tl}${h}${this.c.bold(titleText)}${h.repeat(Math.max(0, boxWidth - 3 - visibleLength(titleText)))}${tr}`,
      ...content.slice(0, Math.max(1, height - 4)).map((line) => `${v} ${fit(line, inner)} ${v}`),
      `${bl}${h.repeat(boxWidth - 2)}${br}`,
    ];
    const top = Math.max(0, Math.floor((height - box.length) / 2));
    const left = " ".repeat(Math.max(0, Math.floor((width - boxWidth) / 2)));
    return lines.map((line, index) => {
      const boxLine = box[index - top];
      return boxLine === undefined ? line : fit(`${left}${boxLine}`, width);
    });
  }
}

/** Runs the full-screen terminal UI until the user quits. */
export async function runTui(context: Context): Promise<number> {
  const { io } = context;

  // Load identities first: passphrase prompts need the normal terminal mode.
  let identities: Identity[] = [];
  let problem: string | null = null;
  try {
    identities = await context.identities();
    if (!identities.length) {
      problem = "no identity found (run `msecrets identity new`)";
    }
  } catch (error) {
    problem = firstLine(error);
  }

  const write = (text: string) => {
    io.stdout.write(text);
  };
  const app = new TuiApp(context, identities, problem, write);

  const stdin = io.stdin;
  const draw = () => {
    const width = io.stdout.columns ?? 80;
    const height = io.stdout.rows ?? 24;
    const lines = app.render(width, height);
    // Absolute positioning: raw mode disables newline translation. 2026 = synchronized update.
    write(
      `\u001b[?2026h${lines.map((line, index) => `\u001b[${index + 1};1H${line}\u001b[0m`).join("")}\u001b[?2026l`,
    );
  };

  const restore = () => {
    write("\u001b[0m\u001b[?25h\u001b[?1049l");
  };

  return new Promise((resolve) => {
    let queue = Promise.resolve();
    const reader = new KeyReader();
    let escapeTimer: NodeJS.Timeout | undefined;
    const finish = () => {
      clearTimeout(escapeTimer);
      stdin.removeListener("data", onData);
      io.stdout.removeListener("resize", draw);
      process.removeListener("exit", restore);
      process.removeListener("SIGTERM", onSignal);
      process.removeListener("SIGHUP", onSignal);
      stdin.setRawMode?.(false);
      stdin.pause();
      restore();
      resolve(0);
    };
    const handle = (input: string) => {
      queue = queue.then(async () => {
        if (app.done || !input) {
          return;
        }
        await app.feed(input);
        if (app.done) {
          finish();
        } else {
          draw();
        }
      });
    };
    const onData = (chunk: Buffer | string) => {
      clearTimeout(escapeTimer);
      handle(reader.push(chunk));
      if (reader.pending) {
        // The rest of a sequence follows within milliseconds; a lone Escape does not.
        escapeTimer = setTimeout(() => handle(reader.flush()), 30);
      }
    };

    // Leave the terminal usable if the process is terminated while the UI is open.
    const onSignal = (signal: NodeJS.Signals) => {
      stdin.setRawMode?.(false);
      restore();
      process.exit(128 + (constants.signals[signal] ?? 1));
    };
    process.once("exit", restore);
    process.once("SIGTERM", onSignal);
    process.once("SIGHUP", onSignal);
    write("\u001b[?1049h\u001b[?25l\u001b[2J");
    stdin.setRawMode?.(true);
    stdin.on("data", onData);
    stdin.resume();
    io.stdout.on("resize", draw);
    draw();
  });
}
