import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";

function derLength(length: number): Buffer {
  if (length < 128) return Buffer.from([length]);

  const bytes: number[] = [];
  let value = length;

  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }

  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function seq(...items: Buffer[]): Buffer {
  return der(0x30, Buffer.concat(items));
}

function set(...items: Buffer[]): Buffer {
  return der(0x31, Buffer.concat(items));
}

function explicit(tag: number, content: Buffer): Buffer {
  return der(0xa0 + tag, content);
}

function integer(value: number | Buffer): Buffer {
  const body =
    typeof value === "number"
      ? Buffer.from([value])
      : value[0] & 0x80
        ? Buffer.concat([Buffer.from([0x00]), value])
        : value;

  return der(0x02, body);
}

function bool(value: boolean): Buffer {
  return der(0x01, Buffer.from([value ? 0xff : 0x00]));
}

function nullValue(): Buffer {
  return der(0x05, Buffer.alloc(0));
}

function bitString(content: Buffer): Buffer {
  return der(0x03, Buffer.concat([Buffer.from([0x00]), content]));
}

function octetString(content: Buffer): Buffer {
  return der(0x04, content);
}

function utf8String(value: string): Buffer {
  return der(0x0c, Buffer.from(value, "utf8"));
}

// function ia5String(value: string): Buffer {
//   return der(0x16, Buffer.from(value, "ascii"));
// }

function utcTime(date: Date): Buffer {
  const yy = String(date.getUTCFullYear()).slice(-2);
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const mi = String(date.getUTCMinutes()).padStart(2, "0");
  const ss = String(date.getUTCSeconds()).padStart(2, "0");

  return der(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${mi}${ss}Z`, "ascii"));
}

function oid(value: string): Buffer {
  const parts = value.split(".").map(Number);
  const first = 40 * parts[0] + parts[1];

  const body = [first];

  for (const part of parts.slice(2)) {
    const encoded: number[] = [];
    let n = part;

    encoded.unshift(n & 0x7f);
    n >>= 7;

    while (n > 0) {
      encoded.unshift((n & 0x7f) | 0x80);
      n >>= 7;
    }

    body.push(...encoded);
  }

  return der(0x06, Buffer.from(body));
}

function algorithmIdentifierSha256WithRsa(): Buffer {
  return seq(
    oid("1.2.840.113549.1.1.11"), // sha256WithRSAEncryption
    nullValue(),
  );
}

function name(commonName: string): Buffer {
  return seq(
    set(
      seq(
        oid("2.5.4.3"), // commonName
        utf8String(commonName),
      ),
    ),
  );
}

function extension(id: string, value: Buffer, critical = false): Buffer {
  return seq(oid(id), ...(critical ? [bool(true)] : []), octetString(value));
}

function dnsName(value: string): Buffer {
  return der(0x82, Buffer.from(value, "ascii")); // [2] dNSName
}

function ipAddressV4(value: string): Buffer {
  return der(
    0x87, // [7] iPAddress
    Buffer.from(value.split(".").map(Number)),
  );
}

function subjectAltName(): Buffer {
  return seq(dnsName("localhost"), ipAddressV4("127.0.0.1"));
}

function basicConstraints(): Buffer {
  return seq(); // CA=false by omission
}

function keyUsage(): Buffer {
  // digitalSignature + keyEncipherment
  // bits 0 and 2 => 10100000, with 5 unused bits
  return der(0x03, Buffer.from([0x05, 0xa0]));
}

function extendedKeyUsageServerAuth(): Buffer {
  return seq(
    oid("1.3.6.1.5.5.7.3.1"), // serverAuth
  );
}

function extensions(): Buffer {
  return explicit(
    3,
    seq(
      extension("2.5.29.19", basicConstraints(), true), // basicConstraints
      extension("2.5.29.15", keyUsage(), true), // keyUsage
      extension("2.5.29.37", extendedKeyUsageServerAuth()), // extKeyUsage
      extension("2.5.29.17", subjectAltName()), // subjectAltName
    ),
  );
}

function pem(label: string, derBytes: Buffer): string {
  const base64 = derBytes.toString("base64");
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;

  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

export function createThrowawayCertificate() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  const privateKeyPem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;

  const publicKeySpkiDer = publicKey.export({
    type: "spki",
    format: "der",
  }) as Buffer;

  const now = new Date();
  const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  const serial = randomBytes(16);
  serial[0] &= 0x7f; // force positive INTEGER

  const signatureAlgorithm = algorithmIdentifierSha256WithRsa();

  const tbsCertificate = seq(
    explicit(0, integer(2)), // version v3
    integer(serial),
    signatureAlgorithm,
    name("localhost"), // issuer
    seq(utcTime(now), utcTime(tomorrow)),
    name("localhost"), // subject
    publicKeySpkiDer,
    extensions(),
  );

  const signature = createSign("RSA-SHA256").update(tbsCertificate).sign(privateKey);

  const certificateDer = seq(tbsCertificate, signatureAlgorithm, bitString(signature));

  return {
    key: privateKeyPem,
    cert: pem("CERTIFICATE", certificateDer),
  };
}
