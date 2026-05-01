import { useCallback, useState } from "react";

export function useDisclosureState<T>() {
  const [value, setValue] = useState<T | null>(null);
  const close = useCallback(() => setValue(null), []);
  const open = useCallback((nextValue: T) => setValue(nextValue), []);

  return { close, opened: value !== null, open, value };
}
