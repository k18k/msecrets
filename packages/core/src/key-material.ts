import { readKey, readPrivateKey } from "node-rpgp";

import type { MSecretsPublicKey, MSecretsPrivateKey } from "./providers/types.ts";

export type ParsedArmoredKey =
  | ({ kind: "public" } & MSecretsPublicKey)
  | ({ kind: "private" } & MSecretsPrivateKey);

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

export function parseArmoredKeyMaterial(armoredKey: string): ParsedArmoredKey {
  const normalizedArmoredKey = normalizeArmoredKey(armoredKey);

  try {
    const privateKey = readPrivateKey({
      armoredKey: normalizedArmoredKey,
    });

    if (!privateKey.fingerprint) {
      throw new Error("Failed to parse armored PGP private key: missing fingerprint");
    }

    return {
      fingerprint: privateKey.fingerprint,
      kind: "private",
      privateKey: normalizedArmoredKey,
      userIds: [],
    };
  } catch {
    try {
      const publicKey = readKey({
        armoredKey: normalizedArmoredKey,
      });

      if (!publicKey.fingerprint) {
        throw new Error("Failed to parse armored PGP public key: missing fingerprint");
      }

      return {
        fingerprint: publicKey.fingerprint,
        kind: "public",
        publicKey: normalizedArmoredKey,
        userIds: [],
      };
    } catch (error) {
      throw new Error(`Failed to parse armored PGP key: ${getParseErrorMessage(error)}`);
    }
  }
}
