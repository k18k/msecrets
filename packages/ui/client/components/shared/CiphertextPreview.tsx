import { Code, Tooltip } from "@mantine/core";

export function CiphertextPreview({ value }: { value?: string }) {
  if (!value) {
    return <Code c="dimmed">-</Code>;
  }

  return (
    <Tooltip label={value.slice(0, 160)}>
      <Code>{value.replace(/\s+/g, " ").slice(0, 44)}...</Code>
    </Tooltip>
  );
}
