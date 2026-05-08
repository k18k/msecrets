import type { KeyIdentity } from "./keys/types.ts";
import {
  createSecretValue,
  getSecretEnvironments,
  getSecretNames,
  getSecretValue,
} from "./domain/secrets.ts";
import {
  getConfiguredKey,
  getConfiguredKeyFingerprints,
  getRequiredConfiguredKeys,
} from "./domain/keys.ts";

export function formatKeyLabel(key: Pick<KeyIdentity, "fingerprint" | "userIds">): string {
  const userIds = key.userIds.length ? key.userIds.join(", ") : "Unnamed key";
  return `${userIds} (${key.fingerprint})`;
}

export const createSecretDef = createSecretValue;
export {
  getConfiguredKey,
  getConfiguredKeyFingerprints,
  getRequiredConfiguredKeys,
  getSecretEnvironments,
  getSecretNames,
  getSecretValue,
};
