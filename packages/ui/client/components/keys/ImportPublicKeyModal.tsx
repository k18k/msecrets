import { useEffect, useState } from "react";
import { Alert, Button, Group, Modal, Stack, Textarea } from "@mantine/core";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";

export function ImportPublicKeyModal({
  onClose,
  opened,
}: {
  onClose: () => void;
  opened: boolean;
}) {
  const importKey = useOrpcMutation<{ armoredKey: string }, unknown>({
    mutationFn: (input) => orpcClient.recipientKeys.importPublic(input),
    onSuccess: onClose,
  });
  const [armoredKey, setArmoredKey] = useState("");

  useEffect(() => {
    if (!opened) setArmoredKey("");
  }, [opened]);

  return (
    <Modal onClose={onClose} opened={opened} size="lg" title="Import public recipient key">
      <Stack>
        <Textarea
          autosize
          label="ASCII-armored public key"
          minRows={10}
          onChange={(event) => setArmoredKey(event.currentTarget.value)}
          placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
          required
          value={armoredKey}
        />
        {importKey.error ? <Alert color="red">{importKey.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            disabled={!armoredKey.trim()}
            loading={importKey.isPending}
            onClick={() => importKey.mutate({ armoredKey })}
          >
            Import
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
