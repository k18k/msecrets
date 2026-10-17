import type { CellState } from "../../core/src/index.ts";
import type { Colors } from "./terminal.ts";

/** Legacy Windows consoles lack these glyphs; modern terminals everywhere have them. */
export function supportsUnicode(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== "win32") {
    return env["TERM"] !== "linux";
  }
  return Boolean(
    env["WT_SESSION"] ||
    env["TERMINUS_SUBLIME"] ||
    env["ConEmuTask"] ||
    env["TERM_PROGRAM"] === "vscode" ||
    env["TERM"]?.startsWith("xterm"),
  );
}

export type Symbols = {
  cell: Record<CellState, string>;
  check: string;
  cross: string;
  arrow: string;
  bullet: string;
  line: string;
};

export function createSymbols(unicode: boolean): Symbols {
  return unicode
    ? {
        cell: { ok: "●", stale: "◐", missing: "○", invalid: "✗", unexpected: "!", absent: "·" },
        check: "✓",
        cross: "✗",
        arrow: "›",
        bullet: "•",
        line: "─",
      }
    : {
        cell: { ok: "+", stale: "~", missing: "-", invalid: "x", unexpected: "!", absent: "." },
        check: "+",
        cross: "x",
        arrow: ">",
        bullet: "*",
        line: "-",
      };
}

export function cellStyle(colors: Colors, state: CellState): (text: string) => string {
  switch (state) {
    case "ok":
      return colors.green;
    case "stale":
      return colors.yellow;
    case "absent":
      return colors.dim;
    default:
      return colors.red;
  }
}

export const CELL_DESCRIPTIONS: Record<CellState, string> = {
  ok: "set",
  stale: "needs sync",
  missing: "missing",
  invalid: "bad signature",
  unexpected: "unexpected",
  absent: "n/a",
};
