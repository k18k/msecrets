import { Badge, Group, Tooltip } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";

export function getKeyLabel(file: WorkspaceFile, fingerprint: string): string {
  const key = file.keys.find((candidate) => candidate.fingerprint === fingerprint);
  return key?.userIds[0] ?? fingerprint.slice(-12);
}

export function OwnerBadges({ file, owners }: { file: WorkspaceFile; owners: string[] }) {
  if (!owners.length) {
    return <Badge color="red">no owners</Badge>;
  }

  return (
    <Group gap={4}>
      {owners.map((owner) => {
        const known = file.keys.some((key) => key.fingerprint === owner);
        return (
          <Tooltip key={owner} label={owner}>
            <Badge color={known ? "blue" : "red"} variant="light">
              {getKeyLabel(file, owner)}
            </Badge>
          </Tooltip>
        );
      })}
    </Group>
  );
}
