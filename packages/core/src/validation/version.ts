export const CURRENT_SECRETS_FILE_VERSION = "2.0.0";
export const SUPPORTED_SECRETS_FILE_MAJOR = 2;

export type SemverVersion = {
  major: number;
  minor: number;
  patch: number;
};

export function parseSemverVersion(value: string): SemverVersion | null {
  const match = value.match(/^(\d+)\.(\d+)\.(\d+)$/);

  if (!match) {
    return null;
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

export function getIncompatibleVersionMessage(version: string): string {
  return `Incompatible msecrets file version: expected ${SUPPORTED_SECRETS_FILE_MAJOR}.x.x, got ${version}`;
}
