import sdk from "./index.cjs";

export const {
  MsecretsError,
  autoSource,
  createClient,
  fromCommand,
  fromEnv,
  fromFile,
  fromKeychain,
  fromString,
  injectEnv,
  isMsecretsError,
  parseSourceSpec,
} = sdk;
