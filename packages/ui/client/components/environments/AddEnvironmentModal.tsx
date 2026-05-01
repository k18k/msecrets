import { useEffect, useState } from "react";
import { Alert, Button, Group, Modal, Stack, TextInput } from "@mantine/core";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";

export function AddEnvironmentModal({ onClose, opened }: { onClose: () => void; opened: boolean }) {
  const add = useOrpcMutation<{ environment: string }, { added: boolean; environment: string }>({
    mutationFn: (input) => orpcClient.environments.add(input),
    onSuccess: onClose,
  });
  const [environment, setEnvironment] = useState("");

  useEffect(() => {
    if (!opened) setEnvironment("");
  }, [opened]);

  return (
    <Modal onClose={onClose} opened={opened} title="Add environment">
      <Stack>
        <TextInput
          label="Environment name"
          onChange={(event) => setEnvironment(event.currentTarget.value)}
          required
          value={environment}
        />
        {add.error ? <Alert color="red">{add.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            disabled={!environment.trim()}
            loading={add.isPending}
            onClick={() => add.mutate({ environment })}
          >
            Add
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
