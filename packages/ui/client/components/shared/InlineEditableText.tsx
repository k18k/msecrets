import { useEffect, useState } from "react";
import { Button, Group, Stack, Textarea } from "@mantine/core";

export function InlineEditableText({
  disabled,
  label,
  onSave,
  value,
}: {
  disabled?: boolean;
  label: string;
  onSave?: (value: string) => void;
  value: string;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  if (!editing) {
    return (
      <Stack gap={6}>
        <Textarea autosize disabled label={label} minRows={2} value={value || "No description"} />
        <Group justify="flex-end">
          <Button disabled={disabled} onClick={() => setEditing(true)} size="xs" variant="light">
            Edit
          </Button>
        </Group>
      </Stack>
    );
  }

  return (
    <Stack gap={6}>
      <Textarea
        autosize
        label={label}
        minRows={3}
        onChange={(event) => setDraft(event.currentTarget.value)}
        value={draft}
      />
      <Group justify="flex-end">
        <Button
          onClick={() => {
            setDraft(value);
            setEditing(false);
          }}
          size="xs"
          variant="default"
        >
          Cancel
        </Button>
        <Button
          disabled={!onSave}
          onClick={() => {
            onSave?.(draft);
            setEditing(false);
          }}
          size="xs"
        >
          Save
        </Button>
      </Group>
    </Stack>
  );
}
