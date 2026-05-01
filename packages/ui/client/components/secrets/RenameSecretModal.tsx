import { useEffect, useState } from "react";
import { Alert, Button, Group, Modal, Stack, TextInput } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";

export function RenameSecretModal({
  file,
  onClose,
  opened,
  secretName,
}: {
  file: WorkspaceFile;
  onClose: () => void;
  opened: boolean;
  secretName: string | null;
}) {
  const renameSecret = useOrpcMutation<
    { name: string | null; nextName: string },
    { name: string; previousName: string; renamed: boolean }
  >({
    mutationFn: (input) => orpcClient.secrets.rename(input),
    onSuccess: onClose,
  });
  const [nextName, setNextName] = useState("");
  const collision = Boolean(nextName.trim() && file.secrets[nextName.trim()]);

  useEffect(() => {
    setNextName(secretName ?? "");
  }, [secretName]);

  return (
    <Modal onClose={onClose} opened={opened} title="Rename secret">
      <Stack>
        <TextInput disabled label="Current name" value={secretName ?? ""} />
        <TextInput
          error={collision ? "A secret with this name already exists" : undefined}
          label="New name"
          onChange={(event) => setNextName(event.currentTarget.value)}
          required
          value={nextName}
        />
        {renameSecret.error ? <Alert color="red">{renameSecret.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            disabled={!secretName || !nextName.trim() || collision}
            loading={renameSecret.isPending}
            onClick={() => renameSecret.mutate({ name: secretName, nextName })}
          >
            Rename
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
