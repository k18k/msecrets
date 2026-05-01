import { Code, Modal, Stack, Text } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";

export function InspectPublicKeyModal({
  file,
  fingerprint,
  onClose,
  opened,
}: {
  file: WorkspaceFile;
  fingerprint: string | null;
  onClose: () => void;
  opened: boolean;
}) {
  const key = fingerprint
    ? file.keys.find((candidate) => candidate.fingerprint === fingerprint)
    : undefined;

  return (
    <Modal onClose={onClose} opened={opened} size="lg" title="Inspect recipient key">
      <Stack>
        <Text fw={600}>{key?.userIds.join(", ") || "No user IDs"}</Text>
        <Text ff="monospace" size="sm">
          {key?.fingerprint}
        </Text>
        <Code block mah="55vh" style={{ overflow: "auto", whiteSpace: "pre" }}>
          {key?.publicKey ?? ""}
        </Code>
      </Stack>
    </Modal>
  );
}
