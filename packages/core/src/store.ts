import {
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import { randomBytes } from "./crypto/primitives.ts";
import {
  DEFAULT_FILENAME,
  type SecretsDocument,
  parseDocumentText,
  serializeDocument,
} from "./document.ts";
import { MsecretsError } from "./errors.ts";

/** The msecrets 2 and 3 file name, recognized only to point to the migration guide. */
const LEGACY_FILENAME = ".env.ms.json";

/** Finds the secrets file in `start` or the closest parent directory. */
export function findDocumentFile(
  start: string = process.cwd(),
  filename: string = DEFAULT_FILENAME,
): string | null {
  for (let directory = resolve(start); ; directory = dirname(directory)) {
    const candidate = join(directory, filename);
    if (statSync(candidate, { throwIfNoEntry: false })?.isFile()) {
      return candidate;
    }
    if (dirname(directory) === directory) {
      return null;
    }
  }
}

export type ResolveFileOptions = {
  /** Explicit path; wins over everything else. */
  file?: string | undefined;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
};

/** Resolves the secrets file: explicit path, then MSECRETS_FILE, then upward search for msecrets.json. */
export function resolveDocumentFile(options: ResolveFileOptions = {}): string {
  const cwd = options.cwd ?? process.cwd();
  const explicit = options.file ?? (options.env ?? process.env)["MSECRETS_FILE"];
  if (explicit) {
    return resolve(cwd, explicit);
  }

  const found = findDocumentFile(cwd);
  if (!found) {
    const legacy = findDocumentFile(cwd, LEGACY_FILENAME);
    throw new MsecretsError(
      "NOT_FOUND",
      legacy
        ? `No ${DEFAULT_FILENAME} found, but there is ${legacy}, the msecrets 3 file. To migrate, see "Coming from msecrets 3" at https://k18k.github.io/msecrets/file-format/`
        : `No ${DEFAULT_FILENAME} found in ${cwd} or any parent directory. Create one with \`msecrets init\`, or point to it with --file or MSECRETS_FILE`,
    );
  }
  return found;
}

function readText(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new MsecretsError(
        "NOT_FOUND",
        `Secrets file not found: ${path}. Create it with \`msecrets init\``,
        {
          cause: error,
        },
      );
    }
    throw error;
  }
}

export function readDocumentFile(path: string): SecretsDocument {
  return parseDocumentText(readText(path), path);
}

function sleep(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function writeNewFile(path: string, text: string): void {
  const descriptor = openSync(path, "wx", 0o644);
  try {
    writeSync(descriptor, text);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

/** Replaces a file through a temporary file and an atomic rename. */
function atomicReplace(path: string, text: string): void {
  const temporary = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`,
  );
  writeNewFile(temporary, text);

  try {
    for (let attempt = 1; ; attempt++) {
      try {
        renameSync(temporary, path);
        return;
      } catch (error) {
        // Windows refuses to replace files that another process (an editor, an indexer) holds open for a moment.
        const code = (error as NodeJS.ErrnoException).code;
        if (
          process.platform !== "win32" ||
          attempt === 10 ||
          (code !== "EPERM" && code !== "EBUSY" && code !== "EACCES")
        ) {
          throw error;
        }
        sleep(50 * attempt);
      }
    }
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

/** Serializes, re-validates, and writes a document. */
function serializeChecked(path: string, document: SecretsDocument): string {
  const text = serializeDocument(document);
  parseDocumentText(text, `the updated ${path}`);
  return text;
}

/** Creates a new secrets file, failing if one already exists. */
export function createDocumentFile(path: string, document: SecretsDocument): void {
  const text = serializeChecked(path, document);
  try {
    writeNewFile(path, text);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new MsecretsError("CONFLICT", `${path} already exists`, { cause: error });
    }
    throw error;
  }
}

/**
 * Read-modify-write of the secrets file. The mutation runs on a fresh copy; if
 * it throws, nothing is written. Concurrent modification is detected.
 */
export function updateDocumentFile<T>(path: string, mutate: (document: SecretsDocument) => T): T {
  const before = readText(path);
  const document = parseDocumentText(before, path);
  const result = mutate(document);
  const text = serializeChecked(path, document);

  if (text !== before) {
    if (readText(path) !== before) {
      throw new MsecretsError(
        "CONFLICT",
        `${path} changed on disk during the operation; run it again`,
      );
    }
    atomicReplace(path, text);
  }
  return result;
}
