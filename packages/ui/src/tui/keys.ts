export type Key =
  | { name: "char"; char: string }
  | {
      name:
        | "up"
        | "down"
        | "left"
        | "right"
        | "home"
        | "end"
        | "pageup"
        | "pagedown"
        | "delete"
        | "insert"
        | "enter"
        | "tab"
        | "shift-tab"
        | "backspace"
        | "escape";
    }
  | { name: "ctrl"; char: string };

type NamedKey = Exclude<Key, { name: "char" } | { name: "ctrl" }>["name"];

const SEQUENCES: [string, NamedKey][] = (
  [
    ["\u001b[A", "up"],
    ["\u001b[B", "down"],
    ["\u001b[C", "right"],
    ["\u001b[D", "left"],
    ["\u001bOA", "up"],
    ["\u001bOB", "down"],
    ["\u001bOC", "right"],
    ["\u001bOD", "left"],
    ["\u001b[H", "home"],
    ["\u001b[F", "end"],
    ["\u001bOH", "home"],
    ["\u001bOF", "end"],
    ["\u001b[1~", "home"],
    ["\u001b[4~", "end"],
    ["\u001b[7~", "home"],
    ["\u001b[8~", "end"],
    ["\u001b[2~", "insert"],
    ["\u001b[3~", "delete"],
    ["\u001b[5~", "pageup"],
    ["\u001b[6~", "pagedown"],
    ["\u001b[Z", "shift-tab"],
  ] as [string, NamedKey][]
).toSorted((left, right) => right[0].length - left[0].length);

const UNKNOWN_CSI = /^\u001b\[[0-9;?]*[ -/]*[@-~]/;

/** Decodes raw terminal input into keys. */
export function decodeKeys(input: string): Key[] {
  const keys: Key[] = [];
  let index = 0;

  while (index < input.length) {
    if (input[index] === "\u001b") {
      const sequence = SEQUENCES.find(([text]) => input.startsWith(text, index));
      if (sequence) {
        keys.push({ name: sequence[1] });
        index += sequence[0].length;
        continue;
      }
      const unknown = UNKNOWN_CSI.exec(input.slice(index));
      if (unknown) {
        index += unknown[0].length;
        continue;
      }
      keys.push({ name: "escape" });
      index++;
      continue;
    }

    const char = String.fromCodePoint(input.codePointAt(index) ?? 0);
    index += char.length;

    if (char === "\r" || char === "\n") {
      // Treat CRLF as one Enter.
      if (char === "\r" && input[index] === "\n") {
        index++;
      }
      keys.push({ name: "enter" });
    } else if (char === "\t") {
      keys.push({ name: "tab" });
    } else if (char === "\u007f" || char === "\b") {
      keys.push({ name: "backspace" });
    } else if (char < " ") {
      keys.push({ name: "ctrl", char: String.fromCharCode(char.charCodeAt(0) + 96) });
    } else {
      keys.push({ name: "char", char });
    }
  }
  return keys;
}
