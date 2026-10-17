export type ErrorCode =
  /** The age header is malformed or a recipient stanza is invalid. */
  | "AGE_HEADER"
  /** None of the provided identities can unwrap the file key. */
  | "AGE_NO_MATCH"
  /** The file key was unwrapped, but the header MAC does not match. */
  | "AGE_HMAC"
  /** The encrypted payload is truncated, tampered with, or malformed. */
  | "AGE_PAYLOAD"
  /** The ASCII armor is malformed. */
  | "AGE_ARMOR"
  /** A key, identity, or recipient string is malformed. */
  | "INVALID_KEY"
  /** The secrets file does not match the v4 format. */
  | "INVALID_FILE"
  /** A value signature is missing, malformed, or does not verify. */
  | "SIGNATURE"
  /** None of the loaded identities is allowed to perform the operation. */
  | "ACCESS_DENIED"
  /** A secret, environment, recipient, or file does not exist. */
  | "NOT_FOUND"
  /** The operation conflicts with existing state. */
  | "CONFLICT"
  /** An identity source (env, file, keychain, password manager) failed. */
  | "IDENTITY_SOURCE"
  /** The runtime lacks a required capability. */
  | "UNSUPPORTED"
  /** The caller passed invalid arguments. */
  | "USAGE";

export class MsecretsError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "MsecretsError";
    this.code = code;
  }
}

export function isMsecretsError(error: unknown, code?: ErrorCode): error is MsecretsError {
  return error instanceof MsecretsError && (code === undefined || error.code === code);
}
