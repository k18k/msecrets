import * as openpgp from "openpgp";

import type { PrivateKey, PublicKey } from "./providers/types.ts";

export type ParsedArmoredKey =
  | ({ kind: "public" } & PublicKey)
  | ({ kind: "private" } & PrivateKey);

function normalizeArmoredKey(value: string): string {
  const normalized = value.trim();

  if (!normalized) {
    throw new Error("Armored PGP key is required");
  }

  return normalized;
}

function getParseErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown parse failure";
}

export async function parseArmoredKeyMaterial(armoredKey: string): Promise<ParsedArmoredKey> {
  const normalizedArmoredKey = normalizeArmoredKey(armoredKey);

  try {
    const privateKey = await openpgp.readPrivateKey({
      armoredKey: normalizedArmoredKey,
    });

    return {
      fingerprint: privateKey.getFingerprint(),
      kind: "private",
      privateKey: normalizedArmoredKey,
      userIds: privateKey.getUserIDs(),
    };
  } catch {
    try {
      const publicKey = await openpgp.readKey({
        armoredKey: normalizedArmoredKey,
      });

      return {
        fingerprint: publicKey.getFingerprint(),
        kind: "public",
        publicKey: normalizedArmoredKey,
        userIds: publicKey.getUserIDs(),
      };
    } catch (error) {
      throw new Error(`Failed to parse armored PGP key: ${getParseErrorMessage(error)}`);
    }
  }
}
