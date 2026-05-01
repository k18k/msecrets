import { useEffect, useState } from "react";
import { Alert, Button, Group, Modal, Stack, TextInput } from "@mantine/core";
import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";

export function RenameEnvironmentModal({
  environment,
  file,
  onClose,
  opened,
}: {
  environment: string | null;
  file: WorkspaceFile;
  onClose: () => void;
  opened: boolean;
}) {
  const rename = useOrpcMutation<
    { environment: string | null; nextEnvironment: string },
    { environment: string; nextEnvironment: string; renamed: boolean }
  >({
    mutationFn: (input) => orpcClient.environments.rename(input),
    onSuccess: onClose,
  });
  const [nextEnvironment, setNextEnvironment] = useState("");
  const collision = Boolean(
    nextEnvironment.trim() &&
    file.environments.includes(nextEnvironment.trim()) &&
    nextEnvironment.trim() !== environment,
  );

  useEffect(() => {
    setNextEnvironment(environment ?? "");
  }, [environment]);

  return (
    <Modal onClose={onClose} opened={opened} title="Rename environment">
      <Stack>
        <Alert color="blue" variant="light">
          Renaming moves every secret value from the old environment key to the new environment key.
        </Alert>
        <TextInput disabled label="Old environment" value={environment ?? ""} />
        <TextInput
          error={collision ? "Environment already exists" : undefined}
          label="New environment"
          onChange={(event) => setNextEnvironment(event.currentTarget.value)}
          required
          value={nextEnvironment}
        />
        {rename.error ? <Alert color="red">{rename.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            disabled={!environment || !nextEnvironment.trim() || collision}
            loading={rename.isPending}
            onClick={() => rename.mutate({ environment, nextEnvironment })}
          >
            Rename
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
