import { Badge, Button, Group, ScrollArea, Table, Text } from "@mantine/core";

import type { WorkspaceFile, WorkspacePageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";

export function RecipientKeysTable({
  data,
  derived,
  file,
  onInspect,
  onRemove,
}: {
  data: WorkspacePageData;
  derived: DerivedSecretsFileState;
  file: WorkspaceFile;
  onInspect: (fingerprint: string) => void;
  onRemove: (fingerprint: string) => void;
}) {
  const runtime = new Set(data.keyManagement.runtimePrivateKeys.map((key) => key.fingerprint));

  return (
    <ScrollArea>
      <Table highlightOnHover striped>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Actions</Table.Th>
            <Table.Th>Recipient</Table.Th>
            <Table.Th>Fingerprint</Table.Th>
            <Table.Th>Usage</Table.Th>
            <Table.Th>Runtime status</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {file.keys.map((key) => {
            const ownership = derived.keyOwnershipCounts.get(key.fingerprint) ?? 0;
            const sole = derived.soleOwnerValues.filter((cell) =>
              cell.owners.includes(key.fingerprint),
            ).length;
            return (
              <Table.Tr key={key.fingerprint}>
                <Table.Td>
                  <Group gap={4}>
                    <Button
                      onClick={() => onInspect(key.fingerprint)}
                      size="compact-xs"
                      variant="light"
                    >
                      Inspect
                    </Button>
                    <Button
                      color="red"
                      onClick={() => onRemove(key.fingerprint)}
                      size="compact-xs"
                      variant="light"
                    >
                      Remove
                    </Button>
                  </Group>
                </Table.Td>
                <Table.Td>{key.userIds[0] ?? <Badge color="yellow">No user ID</Badge>}</Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {key.fingerprint}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {ownership} value{ownership === 1 ? "" : "s"}
                  {sole ? (
                    <Text c="red" size="xs">
                      Sole owner of {sole} value{sole === 1 ? "" : "s"}
                    </Text>
                  ) : null}
                </Table.Td>
                <Table.Td>
                  <Badge color={runtime.has(key.fingerprint) ? "green" : "yellow"}>
                    {runtime.has(key.fingerprint) ? "Available" : "Runtime key missing"}
                  </Badge>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}
