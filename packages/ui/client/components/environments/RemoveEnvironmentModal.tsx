import { List, Text } from "@mantine/core";
import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { ConfirmDangerModal } from "../shared/ConfirmDangerModal";

export function RemoveEnvironmentModal({
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
  const remove = useOrpcMutation<
    { environment: string | null },
    { environment: string; removed: boolean; removedSecrets: string[]; removedValues: number }
  >({
    mutationFn: (input) => orpcClient.environments.remove(input),
    onSuccess: onClose,
  });
  const affected = environment
    ? Object.keys(file.secrets).filter((secretName) =>
        Boolean(file.secrets[secretName]?.values[environment]),
      )
    : [];

  return (
    <ConfirmDangerModal
      confirmLabel="Remove environment"
      loading={remove.isPending}
      onClose={onClose}
      onConfirm={() => remove.mutate({ environment })}
      opened={opened && Boolean(environment)}
      target={environment ?? ""}
      title="Remove environment"
    >
      <Text size="sm">
        This removes {environment} and {affected.length} encrypted value
        {affected.length === 1 ? "" : "s"}. Secrets with no values afterward may be deleted.
      </Text>
      <List size="sm">
        {affected.slice(0, 8).map((secret) => (
          <List.Item key={secret}>{secret}</List.Item>
        ))}
      </List>
    </ConfirmDangerModal>
  );
}
