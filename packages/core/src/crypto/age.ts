/**
 * age v1 file format (https://c2sp.org/age), implemented on node:crypto.
 *
 * Parsing is strict: non-canonical encodings are rejected so that the bytes
 * covered by the header MAC are exactly the bytes that were parsed.
 */
import { MsecretsError } from "../errors.ts";
import { fromBase64, toBase64 } from "./encoding.ts";
import {
  chachaOpen,
  chachaSeal,
  constantTimeEqual,
  hkdf,
  hmacSha256,
  randomBytes,
} from "./primitives.ts";

export type Stanza = {
  /** The first argument is the stanza type. */
  args: string[];
  body: Buffer;
};

export type AgeRecipient = {
  wrap(fileKey: Buffer): Stanza[];
};

export type AgeIdentity = {
  /** Returns the file key, null if no stanza is addressed to this identity, or throws on malformed stanzas. */
  unwrap(stanzas: readonly Stanza[]): Buffer | null;
};

const VERSION_LINE = "age-encryption.org/v1";
const ARGUMENT = /^[\x21-\x7e]+$/;
const BODY_LINE = /^[A-Za-z0-9+/]*$/;
const CHUNK_SIZE = 64 * 1024;
const TAG_SIZE = 16;
const FILE_KEY_SIZE = 16;
/** Bounds the work an untrusted file can cause; msecrets writes one stanza per recipient. */
export const MAX_STANZAS = 1024;
const MAX_HEADER_SIZE = 1024 * 1024;
const ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END = "-----END AGE ENCRYPTED FILE-----";

export function headerError(message: string): MsecretsError {
  return new MsecretsError("AGE_HEADER", `Invalid age header: ${message}`);
}

export function stanzaArgument(stanza: Stanza, index: number): string {
  return stanza.args[index] ?? "";
}

/** Validates the body of a stanza that wraps a 16-byte file key, before any decryption attempt. */
export function requireWrappedFileKey(stanza: Stanza): Buffer {
  if (stanza.body.length !== FILE_KEY_SIZE + TAG_SIZE) {
    throw headerError(
      `${stanzaArgument(stanza, 0)} stanza body must be ${FILE_KEY_SIZE + TAG_SIZE} bytes`,
    );
  }
  return stanza.body;
}

export const ZERO_NONCE: Buffer = Buffer.alloc(12);

type ParsedHeader = {
  stanzas: Stanza[];
  mac: Buffer;
  macInput: Buffer;
  payload: Buffer;
};

function parseHeader(data: Buffer): ParsedHeader {
  let offset = 0;
  const readLine = (): string => {
    const end = data.indexOf(0x0a, offset);
    if (end < 0) {
      throw headerError("unexpected end of header");
    }
    if (end >= MAX_HEADER_SIZE) {
      throw headerError("larger than 1 MiB");
    }
    const line = data.subarray(offset, end).toString("latin1");
    offset = end + 1;
    return line;
  };

  const version = readLine();
  if (version !== VERSION_LINE) {
    throw headerError(
      version.startsWith("age-encryption.org/")
        ? `unsupported version "${version}"`
        : "not an age file",
    );
  }

  const stanzas: Stanza[] = [];
  for (;;) {
    const lineStart = offset;
    const line = readLine();

    if (line.startsWith("--- ")) {
      if (!stanzas.length) {
        throw headerError("no recipient stanzas");
      }
      const mac = fromBase64(line.slice(4), "AGE_HEADER", "header MAC");
      if (mac.length !== 32) {
        throw headerError("header MAC must be 32 bytes");
      }
      return {
        stanzas,
        mac,
        macInput: data.subarray(0, lineStart + 3),
        payload: data.subarray(offset),
      };
    }

    if (!line.startsWith("-> ")) {
      throw headerError("expected a recipient stanza or the header MAC");
    }
    if (stanzas.length === MAX_STANZAS) {
      throw headerError(`more than ${MAX_STANZAS} recipient stanzas`);
    }

    const args = line.slice(3).split(" ");
    if (!args.every((arg) => ARGUMENT.test(arg))) {
      throw headerError("invalid stanza argument");
    }

    let body = "";
    for (;;) {
      const bodyLine = readLine();
      if (bodyLine.length > 64 || !BODY_LINE.test(bodyLine)) {
        throw headerError("invalid stanza body line");
      }
      body += bodyLine;
      if (bodyLine.length < 64) {
        break;
      }
    }

    stanzas.push({ args, body: fromBase64(body, "AGE_HEADER", "stanza body") });
  }
}

function encodeStanza(stanza: Stanza): string {
  const body = toBase64(stanza.body);
  const lines: string[] = body.match(/.{1,64}/g) ?? [];
  if (body.length % 64 === 0) {
    lines.push("");
  }
  return `-> ${stanza.args.join(" ")}\n${lines.join("\n")}\n`;
}

function streamNonce(counter: number, last: boolean): Buffer {
  const nonce = Buffer.alloc(12);
  nonce.writeUIntBE(counter, 5, 6);
  nonce[11] = last ? 1 : 0;
  return nonce;
}

function streamSeal(key: Buffer, plaintext: Uint8Array): Buffer {
  const chunks: Buffer[] = [];
  for (let counter = 0; ; counter++) {
    const offset = counter * CHUNK_SIZE;
    const last = offset + CHUNK_SIZE >= plaintext.length;
    chunks.push(
      chachaSeal(key, streamNonce(counter, last), plaintext.subarray(offset, offset + CHUNK_SIZE)),
    );
    if (last) {
      return Buffer.concat(chunks);
    }
  }
}

function payloadError(message: string): MsecretsError {
  return new MsecretsError("AGE_PAYLOAD", `Invalid age payload: ${message}`);
}

function streamOpen(key: Buffer, payload: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;

  for (let counter = 0; ; counter++) {
    if (offset >= payload.length) {
      throw payloadError("missing final chunk");
    }

    const sealed = payload.subarray(offset, offset + CHUNK_SIZE + TAG_SIZE);
    offset += sealed.length;
    const last = offset === payload.length;
    const plaintext = chachaOpen(key, streamNonce(counter, last), sealed);

    if (!plaintext) {
      throw payloadError(
        last ? "final chunk failed to authenticate" : `chunk ${counter} failed to authenticate`,
      );
    }
    if (last && plaintext.length === 0 && counter > 0) {
      throw payloadError("final chunk is empty");
    }

    chunks.push(plaintext);
    if (last) {
      return Buffer.concat(chunks);
    }
  }
}

export function encryptAge(plaintext: Uint8Array, recipients: readonly AgeRecipient[]): Buffer {
  if (!recipients.length) {
    throw new MsecretsError("USAGE", "At least one recipient is required to encrypt");
  }

  const fileKey = randomBytes(FILE_KEY_SIZE);
  const stanzas = recipients.flatMap((recipient) => recipient.wrap(fileKey));
  if (stanzas.length > MAX_STANZAS) {
    throw new MsecretsError("USAGE", `An age file can have at most ${MAX_STANZAS} recipients`);
  }
  if (stanzas.some((stanza) => stanza.args[0] === "scrypt") && stanzas.length > 1) {
    throw new MsecretsError(
      "USAGE",
      "A passphrase recipient cannot be combined with other recipients",
    );
  }

  const header = Buffer.from(`${VERSION_LINE}\n${stanzas.map(encodeStanza).join("")}---`, "latin1");
  const mac = hmacSha256(hkdf(fileKey, Buffer.alloc(0), "header"), header);
  const nonce = randomBytes(16);

  return Buffer.concat([
    header,
    Buffer.from(` ${toBase64(mac)}\n`, "latin1"),
    nonce,
    streamSeal(hkdf(fileKey, nonce, "payload"), plaintext),
  ]);
}

/** Decrypts a binary age file, or an ASCII-armored one (anything not starting with the binary version line). */
export function decryptAge(data: Uint8Array, identities: readonly AgeIdentity[]): Buffer {
  const input = Buffer.from(data);
  const text = input.toString("latin1");
  const binary =
    !text.startsWith("age-encryption.org/") && text.includes("-----") ? dearmor(text) : input;
  const { stanzas, mac, macInput, payload } = parseHeader(binary);

  if (stanzas.some((stanza) => stanza.args[0] === "scrypt") && stanzas.length !== 1) {
    throw headerError("an scrypt stanza must be the only stanza");
  }

  let fileKey: Buffer | null = null;
  for (const identity of identities) {
    fileKey = identity.unwrap(stanzas);
    if (fileKey) {
      break;
    }
  }

  if (!fileKey) {
    throw new MsecretsError(
      "AGE_NO_MATCH",
      "No identity matched any of the recipients of this age file",
    );
  }

  if (!constantTimeEqual(hmacSha256(hkdf(fileKey, Buffer.alloc(0), "header"), macInput), mac)) {
    throw new MsecretsError("AGE_HMAC", "The age header MAC does not match");
  }

  if (payload.length < 16) {
    throw headerError("missing payload nonce");
  }

  const nonce = payload.subarray(0, 16);
  return streamOpen(hkdf(fileKey, nonce, "payload"), payload.subarray(16));
}

/** Strict PEM encoding (RFC 7468) with the "AGE ENCRYPTED FILE" label. */
export function armor(data: Uint8Array): string {
  const lines =
    Buffer.from(data)
      .toString("base64")
      .match(/.{1,64}/g) ?? [];
  return [ARMOR_BEGIN, ...lines, ARMOR_END, ""].join("\n");
}

function armorError(message: string): MsecretsError {
  return new MsecretsError("AGE_ARMOR", `Invalid age armor: ${message}`);
}

/** Removes leading and trailing spaces, tabs, and line breaks (in linear time, unlike a `\s+$` regex). */
function trimArmor(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && " \t\r\n".includes(text.charAt(start))) {
    start++;
  }
  while (end > start && " \t\r\n".includes(text.charAt(end - 1))) {
    end--;
  }
  return text.slice(start, end);
}

export function dearmor(text: string): Buffer {
  const lines = trimArmor(text)
    .split("\n")
    .map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line));

  if (lines[0] !== ARMOR_BEGIN) {
    throw armorError("missing begin line");
  }
  if (lines[lines.length - 1] !== ARMOR_END) {
    throw armorError("missing end line");
  }

  const body = lines.slice(1, -1);
  body.forEach((line, index) => {
    const isLast = index === body.length - 1;
    if (!/^[A-Za-z0-9+/=]+$/.test(line) || line.length > 64 || (!isLast && line.length !== 64)) {
      throw armorError(`invalid line ${index + 2}`);
    }
  });

  const encoded = body.join("");
  const bytes = Buffer.from(encoded, "base64");
  if (encoded.length % 4 !== 0 || bytes.toString("base64") !== encoded) {
    throw armorError("non-canonical base64");
  }

  return bytes;
}
