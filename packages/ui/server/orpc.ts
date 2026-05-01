import {
  addEnvironment,
  createSecret,
  deleteSecret,
  importConfiguredArmoredKey,
  importConfiguredKey,
  initializeSecretsFile,
  peekSecretValue,
  removeConfiguredKey,
  removeEnvironment,
  removeSecretValue,
  renameEnvironment,
  renameSecret,
  revokeSecretValue,
  setSecretValue,
  shareSecretValue,
} from "@msecrets/core/workflows";
import { parseArmoredKeyMaterial } from "@msecrets/core/key-material";
import { os } from "@orpc/server";

import { getConfigPath } from "./lib/config-path.server.ts";
import { getSecretsPageData, getWorkspacePageData } from "./lib/page-data.server.ts";
import {
  clearRuntimePrivateKey,
  clearRuntimePrivateKeys,
  listRuntimePrivateKeyIdentities,
  upsertRuntimePrivateKey,
} from "./lib/runtime-private-keys.server.ts";
import {
  getOptionalGpgPrivateKey,
  hasOptionalGpgImport,
  listOptionalGpgKeys,
  uiKeyAccess,
} from "./lib/ui-key-access.server.ts";

export type PageDataInput =
  | string
  | URLSearchParams
  | Record<string, string | string[] | null | undefined>
  | null
  | undefined;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getSearchParamsInput(input: unknown): URLSearchParams {
  if (input instanceof URLSearchParams) {
    return input;
  }

  if (typeof input === "string") {
    return new URLSearchParams(input.startsWith("?") ? input.slice(1) : input);
  }

  if (input === null || input === undefined) {
    return new URLSearchParams();
  }

  if (!isRecord(input)) {
    throw new Error("Expected search params input");
  }

  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(input)) {
    if (value === null || value === undefined) {
      continue;
    }

    if (typeof value === "string") {
      params.append(key, value);
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (typeof entry !== "string") {
          throw new Error(`Invalid search params value for ${key}`);
        }

        params.append(key, entry);
      }

      continue;
    }

    throw new Error(`Invalid search params value for ${key}`);
  }

  return params;
}

function getInputObject(input: unknown): Record<string, unknown> {
  if (!isRecord(input)) {
    throw new Error("Expected input object");
  }

  return input;
}

function getOptionalString(input: Record<string, unknown>, key: string): string | undefined {
  const value = input[key];

  if (value === null || value === undefined) {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new Error(`${key} must be a string`);
  }

  const normalized = value.trim();
  return normalized ? normalized : undefined;
}

function getRequiredString(input: Record<string, unknown>, key: string): string {
  const value = getOptionalString(input, key);

  if (!value) {
    throw new Error(`${key} is required`);
  }

  return value;
}

function getStringInput(input: unknown, key = "value"): string {
  if (typeof input === "string") {
    return input;
  }

  return getRequiredString(getInputObject(input), key);
}

async function importRuntimePrivateKey(input: unknown) {
  const source = getInputObject(input);
  const armoredKey = getOptionalString(source, "armoredKey");
  const gpgFingerprint = getOptionalString(source, "gpgFingerprint");

  if (Boolean(armoredKey) === Boolean(gpgFingerprint)) {
    throw new Error("Provide exactly one private key source");
  }

  if (armoredKey) {
    const privateKey = await parseArmoredKeyMaterial(armoredKey);

    if (privateKey.kind !== "private") {
      throw new Error("Expected an armored private key, but received a public key");
    }

    upsertRuntimePrivateKey({
      fingerprint: privateKey.fingerprint,
      privateKey: privateKey.privateKey,
      userIds: privateKey.userIds,
    });

    return {
      fingerprint: privateKey.fingerprint,
      userIds: privateKey.userIds,
    };
  }

  const privateKey = await getOptionalGpgPrivateKey(gpgFingerprint ?? "");

  if (!privateKey) {
    throw new Error(`Private key not found: ${gpgFingerprint}`);
  }

  upsertRuntimePrivateKey(privateKey);

  return {
    fingerprint: privateKey.fingerprint,
    userIds: privateKey.userIds,
  };
}

export const router = {
  workspace: {
    get: os.handler(() => getWorkspacePageData(new URLSearchParams())),
  },

  file: {
    initialize: os.handler(() => initializeSecretsFile(getConfigPath())),
  },

  environments: {
    add: os.handler(({ input }) => {
      const object = getInputObject(input);
      return addEnvironment(getConfigPath(), getRequiredString(object, "environment"));
    }),

    remove: os.handler(({ input }) => {
      const object = getInputObject(input);
      return removeEnvironment(getConfigPath(), getRequiredString(object, "environment"));
    }),

    rename: os.handler(({ input }) => {
      const object = getInputObject(input);
      return renameEnvironment(getConfigPath(), {
        environment: getRequiredString(object, "environment"),
        nextEnvironment: getRequiredString(object, "nextEnvironment"),
      });
    }),
  },

  recipientKeys: {
    importPublic: os.handler(({ input }) => {
      const object = getInputObject(input);
      const armoredKey = getOptionalString(object, "armoredKey");
      const gpgFingerprint = getOptionalString(object, "gpgFingerprint");

      if (Boolean(armoredKey) === Boolean(gpgFingerprint)) {
        throw new Error("Provide exactly one public key source");
      }

      return armoredKey
        ? importConfiguredArmoredKey(getConfigPath(), armoredKey)
        : importConfiguredKey(getConfigPath(), gpgFingerprint ?? "", { keyAccess: uiKeyAccess });
    }),

    remove: os.handler(({ input }) => {
      const object = getInputObject(input);
      return removeConfiguredKey(getConfigPath(), getRequiredString(object, "fingerprint"), {
        keyAccess: uiKeyAccess,
      });
    }),
  },

  runtimeKeys: {
    clear: os.handler(({ input }) => {
      return clearRuntimePrivateKey(getStringInput(input, "fingerprint"));
    }),

    clearAll: os.handler(() => {
      clearRuntimePrivateKeys();
      return { ok: true };
    }),

    importPrivate: os.handler(({ input }) => importRuntimePrivateKey(input)),

    listGpgKeys: os.handler(() => listOptionalGpgKeys()),

    listIdentities: os.handler(() => listRuntimePrivateKeyIdentities()),
  },

  secrets: {
    create: os.handler(({ input }) => {
      const object = getInputObject(input);
      return createSecret(
        getConfigPath(),
        {
          description: getOptionalString(object, "description"),
          environment: getOptionalString(object, "environment"),
          fingerprint: getOptionalString(object, "fingerprint"),
          name: getRequiredString(object, "name"),
          plaintextValue: getOptionalString(object, "plaintextValue"),
        },
        { keyAccess: uiKeyAccess },
      );
    }),

    delete: os.handler(({ input }) => {
      const object = getInputObject(input);
      return deleteSecret(getConfigPath(), getRequiredString(object, "name"));
    }),

    rename: os.handler(({ input }) => {
      const object = getInputObject(input);
      return renameSecret(getConfigPath(), {
        name: getRequiredString(object, "name"),
        nextName: getRequiredString(object, "nextName"),
      });
    }),
  },

  values: {
    peek: os.handler(({ input }) => {
      const object = getInputObject(input);
      return peekSecretValue(
        getConfigPath(),
        {
          environment: getRequiredString(object, "environment"),
          name: getRequiredString(object, "name"),
        },
        { keyAccess: uiKeyAccess },
      );
    }),

    remove: os.handler(({ input }) => {
      const object = getInputObject(input);
      return removeSecretValue(getConfigPath(), {
        environment: getRequiredString(object, "environment"),
        name: getRequiredString(object, "name"),
      });
    }),

    revoke: os.handler(({ input }) => {
      const object = getInputObject(input);
      return revokeSecretValue(
        getConfigPath(),
        {
          environment: getRequiredString(object, "environment"),
          fingerprint: getRequiredString(object, "fingerprint"),
          name: getRequiredString(object, "name"),
        },
        { keyAccess: uiKeyAccess },
      );
    }),

    set: os.handler(({ input }) => {
      const object = getInputObject(input);
      return setSecretValue(
        getConfigPath(),
        {
          environment: getRequiredString(object, "environment"),
          fingerprint: getRequiredString(object, "fingerprint"),
          name: getRequiredString(object, "name"),
          plaintextValue: getRequiredString(object, "plaintextValue"),
        },
        { keyAccess: uiKeyAccess },
      );
    }),

    share: os.handler(({ input }) => {
      const object = getInputObject(input);
      return shareSecretValue(
        getConfigPath(),
        {
          environment: getRequiredString(object, "environment"),
          fingerprint: getRequiredString(object, "fingerprint"),
          name: getRequiredString(object, "name"),
        },
        { keyAccess: uiKeyAccess },
      );
    }),
  },

  pageData: {
    getWorkspacePageData: os.handler(({ input }) => {
      return getWorkspacePageData(getSearchParamsInput(input));
    }),

    getSecretsPageData: os.handler(({ input }) => {
      return getSecretsPageData(getSearchParamsInput(input));
    }),
  },

  keyAccess: {
    hasOptionalGpgImport: os.handler(() => {
      return hasOptionalGpgImport();
    }),

    listOptionalGpgKeys: os.handler(() => {
      return listOptionalGpgKeys();
    }),
  },
};
