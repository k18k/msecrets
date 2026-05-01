import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Alert, Button, Group, Modal, Stack, TextInput } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";

export function ConfirmDangerModal({
  children,
  confirmLabel = "Confirm",
  loading,
  onClose,
  onConfirm,
  opened,
  target,
  title,
}: {
  children: ReactNode;
  confirmLabel?: string;
  loading?: boolean;
  onClose: () => void;
  onConfirm: () => void;
  opened: boolean;
  target: string;
  title: string;
}) {
  const [confirmation, setConfirmation] = useState("");

  useEffect(() => {
    if (!opened) {
      setConfirmation("");
    }
  }, [opened]);

  return (
    <Modal centered onClose={onClose} opened={opened} size="lg" title={title}>
      <Stack>
        <Alert color="red" icon={<IconAlertTriangle size={16} />} variant="light">
          {children}
        </Alert>
        <TextInput
          label={`Type ${target} to confirm`}
          onChange={(event) => setConfirmation(event.currentTarget.value)}
          value={confirmation}
        />
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            color="red"
            disabled={confirmation !== target}
            loading={loading}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
