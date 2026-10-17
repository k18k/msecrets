import { MsecretsError } from "../../core/src/index.ts";

/**
 * Parses dotenv files: `KEY=value`, optional `export ` prefix, `#` comments,
 * single quotes (literal), double quotes (\n, \r, \t, \", \\ escapes), and
 * backticks (literal), each of which may span lines.
 */
export function parseDotenv(text: string): Map<string, string> {
  const values = new Map<string, string>();
  const source = text.replace(/\r\n?/g, "\n");
  let offset = 0;
  let line = 1;

  const fail = (message: string): never => {
    throw new MsecretsError("USAGE", `dotenv line ${line}: ${message}`);
  };

  while (offset < source.length) {
    const end = source.indexOf("\n", offset);
    const rawLine = source.slice(offset, end < 0 ? source.length : end);
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      offset = end < 0 ? source.length : end + 1;
      line++;
      continue;
    }

    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*/.exec(rawLine);
    if (!match) {
      fail(`expected KEY=value, got "${trimmed}"`);
    }
    const name = match?.[1] ?? "";
    let cursor = offset + (match?.[0].length ?? 0);
    const quote = source[cursor];
    let value: string;

    if (quote === '"' || quote === "'" || quote === "`") {
      let closing = cursor + 1;
      for (; closing < source.length; closing++) {
        if (quote === '"' && source[closing] === "\\") {
          closing++;
        } else if (source[closing] === quote) {
          break;
        }
      }
      if (closing >= source.length) {
        fail(`unterminated ${quote} quote for ${name}`);
      }
      const inner = source.slice(cursor + 1, closing);
      value =
        quote === '"'
          ? inner.replace(
              /\\([nrt"\\])/g,
              (_, escape: string) => ({ n: "\n", r: "\r", t: "\t" })[escape] ?? escape,
            )
          : inner;
      line += inner.split("\n").length - 1;
      cursor = closing + 1;
      const rest = source.slice(
        cursor,
        source.indexOf("\n", cursor) < 0 ? source.length : source.indexOf("\n", cursor),
      );
      if (rest.trim() && !rest.trim().startsWith("#")) {
        fail(`unexpected characters after the closing quote of ${name}`);
      }
      cursor += rest.length;
    } else {
      const lineEnd =
        source.indexOf("\n", cursor) < 0 ? source.length : source.indexOf("\n", cursor);
      value = source
        .slice(cursor, lineEnd)
        .replace(/\s+#.*$/, "")
        .trim();
      cursor = lineEnd;
    }

    values.set(name, value);
    offset = cursor + 1;
    line++;
  }
  return values;
}

export function formatDotenv(values: Readonly<Record<string, string>>): string {
  return Object.entries(values)
    .map(([name, value]) => {
      if (/^[A-Za-z0-9_./:@%+,=-]*$/.test(value)) {
        return `${name}=${value}`;
      }
      // Single quotes are literal, but parsers normalize line breaks: CR and LF need escapes.
      if (!/['\n\r]/.test(value)) {
        return `${name}='${value}'`;
      }
      return `${name}="${value.replace(/[\\"\n\r\t]/g, (char) => ({ "\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t" })[char] ?? char)}"`;
    })
    .map((line) => `${line}\n`)
    .join("");
}

export function formatShell(values: Readonly<Record<string, string>>): string {
  return Object.entries(values)
    .map(([name, value]) => `export ${name}='${value.replace(/'/g, "'\\''")}'\n`)
    .join("");
}

export function formatPowerShell(values: Readonly<Record<string, string>>): string {
  return Object.entries(values)
    .map(([name, value]) => `$env:${name} = '${value.replace(/'/g, "''")}'\n`)
    .join("");
}
