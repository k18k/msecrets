import { Alert, List, Text } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { ConfirmDangerModal } from "../shared/ConfirmDangerModal";

export function RemoveConfiguredKeyModal({
  derived,
  file,
  fingerprint,
  onClose,
  opened,
}: {
  derived: DerivedSecretsFileState;
  file: WorkspaceFile;
  fingerprint: string | null;
  onClose: () => void;
  opened: boolean;
}) {
  const remove = useOrpcMutation<
    { fingerprint: string | null },
    { fingerprint: string; removed: boolean; updatedValues: number }
  >({
    mutationFn: (input) => orpcClient.recipientKeys.remove(input),
    onSuccess: onClose,
  });
  const key = fingerprint
    ? file.keys.find((candidate) => candidate.fingerprint === fingerprint)
    : undefined;
  const ownedValues = fingerprint ? (derived.valuesByOwner.get(fingerprint) ?? []) : [];
  const soleOwnerValues = fingerprint
    ? derived.soleOwnerValues.filter((cell) => cell.owners.includes(fingerprint))
    : [];

  return (
    <ConfirmDangerModal
      confirmLabel="Remove configured key"
      loading={remove.isPending}
      onClose={onClose}
      onConfirm={() => remove.mutate({ fingerprint })}
      opened={opened && Boolean(fingerprint)}
      target={fingerprint ?? ""}
      title="Remove configured key"
    >
      <Text size="sm">{key?.userIds.join(", ") || fingerprint}</Text>
      <Text size="sm">
        This key owns {ownedValues.length} encrypted value{ownedValues.length === 1 ? "" : "s"}.
        Removing a key requires decrypting and re-encrypting affected values to remaining owners.
      </Text>
      {soleOwnerValues.length ? (
        <Alert color="red" mt="xs">
          This key is the sole owner of {soleOwnerValues.length} value
          {soleOwnerValues.length === 1 ? "" : "s"}; backend validation will block removal.
        </Alert>
      ) : null}
      <List size="sm">
        {ownedValues.slice(0, 8).map((cell) => (
          <List.Item key={`${cell.secretName}.${cell.environment}`}>
            {cell.secretName}.{cell.environment}
          </List.Item>
        ))}
      </List>
    </ConfirmDangerModal>
  );
}
