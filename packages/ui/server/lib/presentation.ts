import { formatKeyLabel } from "@msecrets/core/secret-helpers";

import type { WorkspaceFile } from "./types.ts";

export function getKeyTitle(userIds: string[], fallback: string): string {
  return userIds[0] || fallback;
}

export function getShortFingerprint(fingerprint: string): string {
  return fingerprint.slice(-8);
}

export function getOwnerLabel(keys: WorkspaceFile["keys"], fingerprint: string): string {
  const key = keys.find((candidate) => candidate.fingerprint === fingerprint);

  if (!key) {
    return getShortFingerprint(fingerprint);
  }

  return getKeyTitle(key.userIds, getShortFingerprint(fingerprint));
}

export function getKeyOptions(
  keys: WorkspaceFile["keys"],
  options: { includeEmpty?: boolean; emptyLabel?: string } = {},
) {
  const entries = keys.map((key) => ({
    label: formatKeyLabel(key),
    value: key.fingerprint,
  }));

  if (!options.includeEmpty) {
    return entries;
  }

  return [
    {
      label: options.emptyLabel ?? "Select an option",
      value: "",
    },
    ...entries,
  ];
}
