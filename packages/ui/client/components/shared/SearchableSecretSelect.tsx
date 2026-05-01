import { Select } from "@mantine/core";

export function SearchableSecretSelect({
  label = "Secret",
  onChange,
  required,
  secrets,
  value,
}: {
  label?: string;
  onChange: (value: string | null) => void;
  required?: boolean;
  secrets: string[];
  value: string | null;
}) {
  return (
    <Select
      clearable={!required}
      data={secrets}
      label={label}
      onChange={onChange}
      placeholder="Select secret"
      required={required}
      searchable
      value={value}
    />
  );
}
