import { Badge, Button, Card, Group, ScrollArea, Table, Text, Title } from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import type {
  DerivedSecretsFileState,
  SecretMatrixCell,
} from "../../hooks/useDerivedSecretsFileState";

function color(status: SecretMatrixCell["status"]) {
  if (status === "encrypted") return "green";
  if (status === "missing") return "gray";
  return "red";
}

function label(status: SecretMatrixCell["status"] | undefined) {
  if (status === "encrypted") return "Encrypted";
  if (status === "missing" || !status) return "Set value";
  return "Issue";
}

export function SecretEnvironmentMatrix({
  derived,
  file,
  onOpenSecret,
  onSetValue,
  onValueActions,
}: {
  derived: DerivedSecretsFileState;
  file: WorkspaceFile;
  onOpenSecret: (secretName: string) => void;
  onSetValue: (secretName: string, environment: string) => void;
  onValueActions: (secretName: string, environment: string) => void;
}) {
  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm">
        <div>
          <Title order={3}>Coverage</Title>
          <Text c="dimmed" size="sm">
            Declared environments by secret.
          </Text>
        </div>
      </Group>
      <ScrollArea>
        <Table fz="sm" highlightOnHover striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Secret name</Table.Th>
              {file.environments.map((environment) => (
                <Table.Th key={environment}>{environment}</Table.Th>
              ))}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {derived.secretNames.map((secretName) => (
              <Table.Tr key={secretName}>
                <Table.Td>
                  <Button
                    onClick={() => onOpenSecret(secretName)}
                    size="compact-xs"
                    variant="subtle"
                  >
                    {secretName}
                  </Button>
                </Table.Td>
                {file.environments.map((environment) => {
                  const cell = derived.matrixCells.find(
                    (candidate) =>
                      candidate.secretName === secretName && candidate.environment === environment,
                  );
                  return (
                    <Table.Td key={environment}>
                      <Badge
                        color={cell ? color(cell.status) : "gray"}
                        onClick={() =>
                          cell?.status === "missing"
                            ? onSetValue(secretName, environment)
                            : onValueActions(secretName, environment)
                        }
                        style={{ cursor: "pointer" }}
                      >
                        {label(cell?.status)}
                      </Badge>
                    </Table.Td>
                  );
                })}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </ScrollArea>
    </Card>
  );
}
