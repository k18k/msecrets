import type { MSecretsAdapter } from "../runtime.ts";

import { decryptWithGpg } from "./shared.ts";

export type GpgAdapterOptions = {
  homedir?: string;
};

export function gpg(options: GpgAdapterOptions = {}): MSecretsAdapter {
  return {
    name: "gpg",
    decrypt({ value }) {
      return decryptWithGpg(value.encryptedValue, options);
    },
  };
}
