export function normalizeName(value: string): string {
  return value.trim();
}

export function requireName(value: string, label: string): string {
  const normalized = normalizeName(value);
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}
