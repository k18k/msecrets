import type { WorkspacePageData } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { ConfirmDangerModal } from "../shared/ConfirmDangerModal";

export function ClearRuntimePrivateKeyModal({
  data,
  fingerprint,
  onClose,
  opened,
}: {
  data: WorkspacePageData;
  fingerprint: string | null;
  onClose: () => void;
  opened: boolean;
}) {
  const clear = useOrpcMutation<{ fingerprint: string | null }, boolean>({
    invalidateRuntimeKeys: true,
    mutationFn: (input) => orpcClient.runtimeKeys.clear({ fingerprint: input.fingerprint }),
    onSuccess: onClose,
  });
  const key = fingerprint
    ? data.keyManagement.runtimePrivateKeys.find(
        (candidate) => candidate.fingerprint === fingerprint,
      )
    : undefined;

  return (
    <ConfirmDangerModal
      confirmLabel="Clear runtime key"
      loading={clear.isPending}
      onClose={onClose}
      onConfirm={() => clear.mutate({ fingerprint })}
      opened={opened && Boolean(fingerprint)}
      target={fingerprint ?? ""}
      title="Clear runtime/private key"
    >
      This clears {key?.userIds.join(", ") || fingerprint} from local runtime memory only. The
      committed `.env.ms.json` file is unchanged.
    </ConfirmDangerModal>
  );
}
