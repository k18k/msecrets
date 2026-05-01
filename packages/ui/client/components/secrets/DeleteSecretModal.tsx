import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { ConfirmDangerModal } from "../shared/ConfirmDangerModal";

export function DeleteSecretModal({
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
  const deleteSecret = useOrpcMutation<
    { name: string | null },
    { name: string; removed: boolean; removedValues: number }
  >({
    mutationFn: (input) => orpcClient.secrets.delete(input),
    onSuccess: onClose,
  });
  const environments = secretName ? Object.keys(file.secrets[secretName]?.values ?? {}) : [];

  return (
    <ConfirmDangerModal
      confirmLabel="Delete secret"
      loading={deleteSecret.isPending}
      onClose={onClose}
      onConfirm={() => deleteSecret.mutate({ name: secretName })}
      opened={opened && Boolean(secretName)}
      target={secretName ?? ""}
      title="Delete secret"
    >
      This deletes {secretName} and all encrypted values for:{" "}
      {environments.join(", ") || "no environments"}.
    </ConfirmDangerModal>
  );
}
