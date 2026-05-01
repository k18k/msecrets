import { useEffect, useState } from "react";
import { Alert, Button, Group, Modal, Stack, Textarea } from "@mantine/core";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";

export function ImportPrivateKeyModal({
  onClose,
  opened,
}: {
  onClose: () => void;
  opened: boolean;
}) {
  const importKey = useOrpcMutation<
    { armoredKey: string },
    { fingerprint: string; userIds: string[] }
  >({
    invalidateRuntimeKeys: true,
    mutationFn: (input) => orpcClient.runtimeKeys.importPrivate(input),
    onSuccess: onClose,
  });
  const [armoredKey, setArmoredKey] = useState("");

  useEffect(() => {
    if (!opened) setArmoredKey("");
  }, [opened]);

  return (
    <Modal onClose={onClose} opened={opened} size="lg" title="Import runtime/private key">
      <Stack>
        <Alert color="blue" variant="light">
          Runtime/private keys are local only and stay in server memory. They are not written to
          `.env.ms.json`.
        </Alert>
        <Textarea
          autosize
          label="ASCII-armored private key"
          minRows={10}
          onChange={(event) => setArmoredKey(event.currentTarget.value)}
          placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
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
            Import runtime key
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
