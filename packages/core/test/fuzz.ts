/** Deterministic fuzzing helpers: a seeded generator and mutations of age files. */

export type Random = {
  /** An integer in [0, n). */
  int(n: number): number;
  pick<T>(items: readonly T[]): T;
  bytes(length: number): Buffer;
};

/** mulberry32: small, fast, and reproducible from the seed printed by the tests. */
export function seeded(seed: number): Random {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  return {
    int,
    pick: (items) => items[int(items.length)] as (typeof items)[number],
    bytes: (length) => Buffer.from(Array.from({ length }, () => int(256))),
  };
}

export const FUZZ_SEED: number = Number(process.env["MSECRETS_FUZZ_SEED"] || 20261021);
export const FUZZ_CASES: number = Number(process.env["MSECRETS_FUZZ_CASES"] || 300);
/** Deep runs outlast the default test timeout: allow 50 ms per case. */
export const FUZZ_TIMEOUT: { timeout: number } = { timeout: Math.max(120_000, FUZZ_CASES * 50) };

/** Splits an age file into its header lines (up to and including the MAC line) and the payload. */
function split(file: Buffer): { lines: string[]; payload: Buffer } | null {
  const mac = file.indexOf("\n--- ");
  const end = mac < 0 ? -1 : file.indexOf(0x0a, mac + 1);
  if (end < 0) {
    return null;
  }
  return {
    lines: file.subarray(0, end).toString("latin1").split("\n"),
    payload: file.subarray(end + 1),
  };
}

function join(lines: readonly string[], payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`${lines.join("\n")}\n`, "latin1"), payload]);
}

const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Mutations that keep most of the file intact, so parsing gets deep before anything fails. */
export const MUTATIONS: readonly [string, (file: Buffer, random: Random) => Buffer][] = [
  [
    "flip a bit",
    (file, random) => {
      const copy = Buffer.from(file);
      const index = random.int(copy.length);
      copy[index] = (copy[index] ?? 0) ^ (1 << random.int(8));
      return copy;
    },
  ],
  ["truncate", (file, random) => file.subarray(0, random.int(file.length))],
  [
    "insert a byte",
    (file, random) => {
      const index = random.int(file.length + 1);
      return Buffer.concat([file.subarray(0, index), random.bytes(1), file.subarray(index)]);
    },
  ],
  [
    "delete a byte",
    (file, random) => {
      const index = random.int(file.length);
      return Buffer.concat([file.subarray(0, index), file.subarray(index + 1)]);
    },
  ],
  ["append bytes", (file, random) => Buffer.concat([file, random.bytes(1 + random.int(32))])],
  [
    "duplicate a header line",
    (file, random) => {
      const parts = split(file);
      if (!parts) {
        return file;
      }
      const index = random.int(parts.lines.length);
      parts.lines.splice(index, 0, parts.lines[index] ?? "");
      return join(parts.lines, parts.payload);
    },
  ],
  [
    "drop a header line",
    (file, random) => {
      const parts = split(file);
      if (!parts) {
        return file;
      }
      parts.lines.splice(random.int(parts.lines.length), 1);
      return join(parts.lines, parts.payload);
    },
  ],
  [
    "swap header lines",
    (file, random) => {
      const parts = split(file);
      if (!parts) {
        return file;
      }
      const [a, b] = [random.int(parts.lines.length), random.int(parts.lines.length)];
      [parts.lines[a], parts.lines[b]] = [parts.lines[b] ?? "", parts.lines[a] ?? ""];
      return join(parts.lines, parts.payload);
    },
  ],
  [
    "edit a stanza line",
    (file, random) => {
      const parts = split(file);
      const stanzas = parts?.lines.flatMap((line, index) =>
        line.startsWith("-> ") ? [index] : [],
      );
      if (!parts || !stanzas?.length) {
        return file;
      }
      const index = random.pick(stanzas);
      const args = (parts.lines[index] ?? "").slice(3).split(" ");
      const edit = random.int(4);
      if (edit === 0) {
        args.push(toArgument(random));
      } else if (edit === 1) {
        args.pop();
      } else if (edit === 2) {
        args[random.int(args.length)] = toArgument(random);
      } else {
        args.splice(random.int(args.length + 1), 0, "");
      }
      parts.lines[index] = `-> ${args.join(" ")}`;
      return join(parts.lines, parts.payload);
    },
  ],
  [
    "edit a base64 character",
    (file, random) => {
      const parts = split(file);
      if (!parts) {
        return file;
      }
      const index = random.int(parts.lines.length);
      const line = parts.lines[index] ?? "";
      if (!line.length) {
        return file;
      }
      const position = random.int(line.length);
      parts.lines[index] =
        line.slice(0, position) + random.pick([...BASE64]) + line.slice(position + 1);
      return join(parts.lines, parts.payload);
    },
  ],
  [
    "change line endings",
    (file, random) => {
      const parts = split(file);
      if (!parts) {
        return file;
      }
      const index = random.int(parts.lines.length);
      parts.lines[index] = `${parts.lines[index] ?? ""}${random.pick(["\r", " ", "\t", "="])}`;
      return join(parts.lines, parts.payload);
    },
  ],
  [
    "cut the payload at a chunk boundary",
    (file, random) => {
      const parts = split(file);
      if (!parts) {
        return file;
      }
      const sealed = 64 * 1024 + 16;
      const boundary =
        16 + sealed * random.int(Math.max(1, Math.floor(parts.payload.length / sealed) + 1));
      return join(
        parts.lines,
        parts.payload.subarray(0, boundary + random.pick([-1, 0, 1, 16, 17])),
      );
    },
  ],
];

function toArgument(random: Random): string {
  const length = 1 + random.int(12);
  return Array.from({ length }, () => String.fromCharCode(0x21 + random.int(94))).join("");
}
