import { useEffect, useState } from "react";
import { Alert, Button, Group, Modal, PasswordInput, Stack, Switch, Textarea } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { SearchableEnvironmentSelect } from "../shared/SearchableEnvironmentSelect";
import { SearchableKeySelect } from "../shared/SearchableKeySelect";
import { SearchableSecretSelect } from "../shared/SearchableSecretSelect";
import type { SecretValueTarget } from "./secretTypes";

export function SetSecretValueModal({
  file,
  onClose,
  opened,
  target,
}: {
  file: WorkspaceFile;
  onClose: () => void;
  opened: boolean;
  target: SecretValueTarget | null;
}) {
  const setSecretValue = useOrpcMutation<
    {
      environment: string | null;
      fingerprint: string | null;
      name: string | null;
      plaintextValue: string;
    },
    { environment: string; name: string }
  >({
    mutationFn: (input) => orpcClient.values.set(input),
    onSuccess: onClose,
  });
  const [secretName, setSecretName] = useState<string | null>(target?.secretName ?? null);
  const [environment, setEnvironment] = useState<string | null>(target?.environment ?? null);
  const [fingerprint, setFingerprint] = useState<string | null>(file.keys[0]?.fingerprint ?? null);
  const [plaintextValue, setPlaintextValue] = useState("");
  const [showPlaintext, setShowPlaintext] = useState(false);

  useEffect(() => {
    if (opened) {
      setSecretName(target?.secretName ?? null);
      setEnvironment(target?.environment ?? file.environments[0] ?? null);
      setFingerprint(file.keys[0]?.fingerprint ?? null);
    } else {
      setPlaintextValue("");
      setShowPlaintext(false);
    }
  }, [file.environments, file.keys, opened, target]);

  const ValueInput = showPlaintext ? Textarea : PasswordInput;

  return (
    <Modal onClose={onClose} opened={opened} size="lg" title="Set encrypted value">
      <Stack>
        <SearchableSecretSelect
          onChange={setSecretName}
          required
          secrets={Object.keys(file.secrets).sort()}
          value={secretName}
        />
        <SearchableEnvironmentSelect
          environments={file.environments}
          onChange={setEnvironment}
          required
          value={environment}
        />
        <SearchableKeySelect file={file} onChange={setFingerprint} required value={fingerprint} />
        <Switch
          checked={showPlaintext}
          label="Show plaintext while editing"
          onChange={(event) => setShowPlaintext(event.currentTarget.checked)}
        />
        <ValueInput
          label="Plaintext value"
          onChange={(event) => setPlaintextValue(event.currentTarget.value)}
          required
          value={plaintextValue}
        />
        {setSecretValue.error ? <Alert color="red">{setSecretValue.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={onClose} variant="default">
            Cancel
          </Button>
          <Button
            disabled={!secretName || !environment || !fingerprint || !plaintextValue}
            loading={setSecretValue.isPending}
            onClick={() =>
              setSecretValue.mutate({
                environment,
                fingerprint,
                name: secretName,
                plaintextValue,
              })
            }
          >
            Encrypt and save
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
