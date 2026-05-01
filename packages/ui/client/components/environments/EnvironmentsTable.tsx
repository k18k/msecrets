import { Badge, Button, Group, ScrollArea, Table, Text } from "@mantine/core";
import type { WorkspaceFile } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";

export function EnvironmentsTable({
  derived,
  file,
  onRemove,
  onRename,
  onView,
}: {
  derived: DerivedSecretsFileState;
  file: WorkspaceFile;
  onRemove: (environment: string) => void;
  onRename: (environment: string) => void;
  onView: (environment: string) => void;
}) {
  return (
    <ScrollArea>
      <Table highlightOnHover striped>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Actions</Table.Th>
            <Table.Th>Environment</Table.Th>
            <Table.Th>Values</Table.Th>
            <Table.Th>Missing</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {file.environments.map((environment) => {
            const valueCount = Object.values(file.secrets).filter((secret) =>
              Boolean(secret.values[environment]),
            ).length;
            const missing = derived.missingValuesByEnvironment.get(environment) ?? 0;
            return (
              <Table.Tr key={environment}>
                <Table.Td>
                  <Group gap={4}>
                    <Button onClick={() => onView(environment)} size="compact-xs" variant="light">
                      Affected secrets
                    </Button>
                    <Button onClick={() => onRename(environment)} size="compact-xs">
                      Rename
                    </Button>
                    <Button
                      color="red"
                      onClick={() => onRemove(environment)}
                      size="compact-xs"
                      variant="light"
                    >
                      Remove
                    </Button>
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text fw={600}>{environment}</Text>
                </Table.Td>
                <Table.Td>{valueCount}</Table.Td>
                <Table.Td>
                  <Badge color={missing ? "yellow" : "green"}>{missing}</Badge>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}
