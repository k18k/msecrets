import { Select } from "@mantine/core";

export function SearchableEnvironmentSelect({
  environments,
  label = "Environment",
  onChange,
  required,
  value,
}: {
  environments: string[];
  label?: string;
  onChange: (value: string | null) => void;
  required?: boolean;
  value: string | null;
}) {
  return (
    <Select
      clearable={!required}
      data={environments}
      label={label}
      onChange={onChange}
      placeholder="Select environment"
      required={required}
      searchable
      value={value}
    />
  );
}
