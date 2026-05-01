import { randomUUID } from "node:crypto";
import { readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import type { SecretDef, SecretsFile } from "./types.ts";
import { assertValidSecretsFile } from "./validation.ts";

export function readSecretsFileData(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf-8")) as unknown;
}

export function getSecretsFile(path: string): SecretsFile {
  const value = readSecretsFileData(path);
  assertValidSecretsFile(value);
  return value;
}

export function hasSecretsFile(path: string): boolean {
  return Boolean(statSync(path, { throwIfNoEntry: false }));
}

export function writeSecretsFile(path: string, file: SecretsFile) {
  assertValidSecretsFile(file);

  const tempPath = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);

  writeFileSync(tempPath, `${JSON.stringify(file, null, 2)}\n`);

  try {
    renameSync(tempPath, path);
  } catch (error) {
    unlinkSync(tempPath);
    throw error;
  }
}

export async function modFile(
  path: string,
  cb: (current: SecretsFile) => Promise<SecretsFile | void>,
) {
  const current = getSecretsFile(path);
  const updated = (await cb(current)) ?? current;
  writeSecretsFile(path, updated);
}

export async function modSecret(
  path: string,
  name: string,
  env: string,
  cb: (current: SecretDef) => Promise<SecretDef>,
) {
  await modFile(path, async (file) => {
    const current = file.secrets[name]?.values[env];
    if (!current) {
      throw new Error(`Missing ${name}.${env}`);
    }

    file.secrets[name]!.values[env] = await cb(current);
    return file;
  });
}
