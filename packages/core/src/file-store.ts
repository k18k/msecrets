import { randomUUID } from "node:crypto";
import { readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import type { SecretValue, SecretsFile } from "./model.ts";
import { assertValidSecretsFile } from "./validation/index.ts";

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

export async function modifySecretsFile(
  path: string,
  cb: (draft: SecretsFile) => Promise<SecretsFile | void>,
) {
  const current = getSecretsFile(path);
  const draft = structuredClone(current);
  const updated = (await cb(draft)) ?? draft;
  writeSecretsFile(path, updated);
}

export const modFile = modifySecretsFile;

export async function modSecret(
  path: string,
  name: string,
  environment: string,
  cb: (current: SecretValue) => Promise<SecretValue>,
) {
  await modifySecretsFile(path, async (file) => {
    const current = file.secrets[name]?.values[environment];
    if (!current) {
      throw new Error(`Missing ${name}.${environment}`);
    }

    file.secrets[name]!.values[environment] = await cb(current);
  });
}
