import type { KeyIdentity } from "./keys/types.ts";

export function parseKeys(raw: string): KeyIdentity[] {
  const lines = raw.split("\n");
  const keys: KeyIdentity[] = [];
  let current: Partial<KeyIdentity> | null = null;

  for (const line of lines) {
    const parts = line.split(":");
    const type = parts[0];

    if (type === "sec") {
      if (current?.fingerprint) {
        keys.push({
          fingerprint: current.fingerprint,
          userIds: current.userIds ?? [],
        });
      }
      current = { userIds: [] };
    }

    if (!current) {
      continue;
    }

    if (type === "uid" && parts[9]) {
      current.userIds ??= [];
      current.userIds.push(parts[9]);
    }

    if (type === "fpr" && parts[9]) {
      current.fingerprint = parts[9];
    }
  }

  if (current?.fingerprint) {
    keys.push({
      fingerprint: current.fingerprint,
      userIds: current.userIds ?? [],
    });
  }

  return keys;
}
