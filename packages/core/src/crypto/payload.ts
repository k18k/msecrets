export function normalizeDecryptedPayload(data: string | Uint8Array): string {
  if (typeof data === "string") {
    return data;
  }

  return new TextDecoder().decode(data);
}
