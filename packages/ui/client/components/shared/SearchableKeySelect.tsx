import { Select } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";

function labelForKey(key: WorkspaceFile["keys"][number]) {
  const user = key.userIds[0] ? `${key.userIds[0]} - ` : "";
  return `${user}${key.fingerprint}`;
}

export function SearchableKeySelect({
  exclude = [],
  file,
  label = "Recipient key",
  onChange,
  required,
  value,
}: {
  exclude?: string[];
  file: WorkspaceFile;
  label?: string;
  onChange: (value: string | null) => void;
  required?: boolean;
  value: string | null;
}) {
  const excluded = new Set(exclude);
  const data = file.keys
    .filter((key) => !excluded.has(key.fingerprint))
    .map((key) => ({ label: labelForKey(key), value: key.fingerprint }));

  return (
    <Select
      clearable={!required}
      data={data}
      label={label}
      onChange={onChange}
      placeholder="Select recipient"
      required={required}
      searchable
      value={value}
    />
  );
}
