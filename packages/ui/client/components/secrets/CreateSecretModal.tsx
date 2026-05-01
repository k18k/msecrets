import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  Group,
  Modal,
  PasswordInput,
  Stack,
  TextInput,
  Textarea,
} from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { SearchableEnvironmentSelect } from "../shared/SearchableEnvironmentSelect";
import { SearchableKeySelect } from "../shared/SearchableKeySelect";

export function CreateSecretModal({
  file,
  onClose,
  opened,
}: {
  file: WorkspaceFile;
  onClose: () => void;
  opened: boolean;
}) {
  const createSecret = useOrpcMutation<
    {
      description?: string;
      environment?: string | null;
      fingerprint?: string | null;
      name: string;
      plaintextValue?: string;
    },
    { hasInitialValue: boolean; name: string }
  >({
    mutationFn: (input) => orpcClient.secrets.create(input),
    onSuccess: onClose,
  });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [withInitialValue, setWithInitialValue] = useState(false);
  const [environment, setEnvironment] = useState<string | null>(file.environments[0] ?? null);
  const [fingerprint, setFingerprint] = useState<string | null>(file.keys[0]?.fingerprint ?? null);
  const [plaintextValue, setPlaintextValue] = useState("");

  useEffect(() => {
    if (!opened) {
      setName("");
      setDescription("");
      setWithInitialValue(false);
      setPlaintextValue("");
    }
  }, [opened]);

  return (
    <Modal onClose={onClose} opened={opened} size="lg" title="Create secret">
      <Stack>
        <TextInput
          label="Secret name"
          onChange={(event) => setName(event.currentTarget.value)}
          required
          value={name}
        />
        <Textarea
          autosize
          label="Description"
          minRows={2}
          onChange={(event) => setDescription(event.currentTarget.value)}
          value={description}
        />
        <Checkbox
          checked={withInitialValue}
          label="Set an initial encrypted value"
          onChange={(event) => setWithInitialValue(event.currentTarget.checked)}
        />
        {withInitialValue ? (
          <>
            <SearchableEnvironmentSelect
              environments={file.environments}
              onChange={setEnvironment}
              required
              value={environment}
            />
            <SearchableKeySelect
              file={file}
              onChange={setFingerprint}
              required
              value={fingerprint}
            />
            <PasswordInput
              label="Plaintext value"
              onChange={(event) => setPlaintextValue(event.currentTarget.value)}
              required
              value={plaintextValue}
            />
          </>
        ) : null}
        {createSecret.error ? <Alert color="red">{createSecret.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            disabled={
              !name.trim() ||
              (withInitialValue && (!environment || !fingerprint || !plaintextValue))
            }
            loading={createSecret.isPending}
            onClick={() =>
              createSecret.mutate({
                description,
                environment: withInitialValue ? environment : undefined,
                fingerprint: withInitialValue ? fingerprint : undefined,
                name,
                plaintextValue: withInitialValue ? plaintextValue : undefined,
              })
            }
          >
            Create
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
