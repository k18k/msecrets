import { type ErrorCode, MsecretsError } from "../errors.ts";

const BASE64_ALPHABET = /^[A-Za-z0-9+/]*$/;

/** Standard base64 without padding (RFC 4648, Section 4), as used by age. */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "");
}

/** Decodes unpadded base64, rejecting padding and non-canonical encodings. */
export function fromBase64(text: string, code: ErrorCode, what: string): Buffer {
  if (!BASE64_ALPHABET.test(text) || text.length % 4 === 1) {
    throw new MsecretsError(code, `Invalid base64 in ${what}`);
  }

  const bytes = Buffer.from(text, "base64");
  if (toBase64(bytes) !== text) {
    throw new MsecretsError(code, `Non-canonical base64 in ${what}`);
  }

  return bytes;
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: readonly number[]): number {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    BECH32_GENERATORS.forEach((generator, bit) => {
      if ((top >>> bit) & 1) {
        checksum ^= generator;
      }
    });
  }
  return checksum;
}

function bech32HrpExpand(hrp: string): number[] {
  const codes = [...hrp].map((char) => char.charCodeAt(0));
  return [...codes.map((code) => code >> 5), 0, ...codes.map((code) => code & 31)];
}

function convertBits(data: Iterable<number>, from: number, to: number, pad: boolean): number[] {
  const max = (1 << to) - 1;
  const out: number[] = [];
  let accumulator = 0;
  let bits = 0;

  for (const value of data) {
    accumulator = (accumulator << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((accumulator >> bits) & max);
    }
    accumulator &= (1 << bits) - 1;
  }

  if (pad) {
    if (bits > 0) {
      out.push((accumulator << (to - bits)) & max);
    }
  } else if (bits >= from || accumulator !== 0) {
    throw new MsecretsError("INVALID_KEY", "Invalid Bech32 padding");
  }

  return out;
}

/** Bech32 (BIP173) without the 90 character length limit, as used by age. */
export function bech32Encode(hrp: string, bytes: Uint8Array): string {
  const lowerHrp = hrp.toLowerCase();
  const data = convertBits(bytes, 8, 5, true);
  const polymod = bech32Polymod([...bech32HrpExpand(lowerHrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [0, 1, 2, 3, 4, 5].map((index) => (polymod >>> (5 * (5 - index))) & 31);
  return `${lowerHrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET.charAt(value)).join("")}`;
}

export function bech32Decode(text: string): { hrp: string; bytes: Buffer } {
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) {
    throw new MsecretsError("INVALID_KEY", "Bech32 string mixes upper and lower case");
  }

  const lower = text.toLowerCase();
  const separator = lower.lastIndexOf("1");
  if (separator < 1 || separator + 7 > lower.length) {
    throw new MsecretsError("INVALID_KEY", "Malformed Bech32 string");
  }

  const hrp = lower.slice(0, separator);
  if ([...hrp].some((char) => char.charCodeAt(0) < 33 || char.charCodeAt(0) > 126)) {
    throw new MsecretsError("INVALID_KEY", "Invalid Bech32 human-readable part");
  }

  const data = Array.from(lower.slice(separator + 1), (char) => {
    const value = BECH32_CHARSET.indexOf(char);
    if (value < 0) {
      throw new MsecretsError("INVALID_KEY", `Invalid Bech32 character "${char}"`);
    }
    return value;
  });

  if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) {
    throw new MsecretsError("INVALID_KEY", "Invalid Bech32 checksum");
  }

  return { hrp, bytes: Buffer.from(convertBits(data.slice(0, -6), 5, 8, false)) };
}
