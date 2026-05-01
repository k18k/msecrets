import { Badge, Button, Group, Menu, ScrollArea, Table, Text } from "@mantine/core";
import { IconDotsVertical } from "@tabler/icons-react";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import type { SecretTableFilters } from "../../hooks/useTableFilters";
import { OwnerBadges } from "../shared/OwnerBadges";
import type { SecretValueTarget } from "./secretTypes";

function getCoverage(file: WorkspaceFile, secretName: string) {
  const count = Object.keys(file.secrets[secretName]?.values ?? {}).length;
  return `${count}/${file.environments.length}`;
}

function getOwners(file: WorkspaceFile, secretName: string) {
  return [
    ...new Set(
      Object.values(file.secrets[secretName]?.values ?? {}).flatMap((value) => value.owners),
    ),
  ];
}

export function SecretsTable({
  derived,
  file,
  filters,
  onDelete,
  onOpen,
  onPeek,
  onRemoveValue,
  onRename,
  onRevoke,
  onSetValue,
  onShare,
}: {
  derived: DerivedSecretsFileState;
  file: WorkspaceFile;
  filters: SecretTableFilters;
  onDelete: (secretName: string) => void;
  onOpen: (secretName: string) => void;
  onPeek: (target: SecretValueTarget) => void;
  onRemoveValue: (target: SecretValueTarget) => void;
  onRename: (secretName: string) => void;
  onRevoke: (target: SecretValueTarget) => void;
  onSetValue: (target: SecretValueTarget) => void;
  onShare: (target: SecretValueTarget) => void;
}) {
  const visibleSecretNames = derived.secretNames.filter((secretName) => {
    const normalizedSearch = filters.search.trim().toLowerCase();
    const values = file.secrets[secretName]?.values ?? {};
    const cells = derived.matrixCells.filter((cell) => cell.secretName === secretName);

    if (normalizedSearch && !secretName.toLowerCase().includes(normalizedSearch)) {
      return false;
    }

    if (filters.environment && !values[filters.environment]) {
      return false;
    }

    if (
      filters.owner &&
      !Object.values(values).some((value) => value.owners.includes(filters.owner ?? ""))
    ) {
      return false;
    }

    if (filters.missingOnly && !cells.some((cell) => cell.status === "missing")) {
      return false;
    }

    if (
      filters.issueOnly &&
      !cells.some((cell) => cell.status !== "encrypted" && cell.status !== "missing")
    ) {
      return false;
    }

    return true;
  });

  return (
    <ScrollArea>
      <Table fz="sm" highlightOnHover striped stickyHeader>
        <Table.Thead>
          <Table.Tr>
            <Table.Th miw={230}>Actions</Table.Th>
            <Table.Th miw={220}>Secret</Table.Th>
            <Table.Th miw={120}>Coverage</Table.Th>
            <Table.Th miw={260}>Owners</Table.Th>
            <Table.Th miw={160}>Issues</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {visibleSecretNames.map((secretName) => {
            const secret = file.secrets[secretName];
            const owners = getOwners(file, secretName);
            const cells = derived.matrixCells.filter((cell) => cell.secretName === secretName);
            const issueCount = cells.filter(
              (cell) => !["encrypted", "missing"].includes(cell.status),
            ).length;

            return (
              <Table.Tr key={secretName}>
                <Table.Td>
                  <Group gap={4} wrap="nowrap">
                    <Button onClick={() => onOpen(secretName)} size="compact-xs">
                      Open
                    </Button>
                    <Button
                      onClick={() =>
                        onSetValue({ environment: file.environments[0] ?? "", secretName })
                      }
                      size="compact-xs"
                      variant="light"
                    >
                      Set value
                    </Button>
                    <Menu withinPortal>
                      <Menu.Target>
                        <Button
                          leftSection={<IconDotsVertical size={14} />}
                          size="compact-xs"
                          variant="default"
                        >
                          More
                        </Button>
                      </Menu.Target>
                      <Menu.Dropdown>
                        <Menu.Item onClick={() => onRename(secretName)}>Rename</Menu.Item>
                        <Menu.Item
                          disabled={!Object.keys(secret?.values ?? {}).length}
                          onClick={() =>
                            onPeek({
                              environment: Object.keys(secret?.values ?? {})[0] ?? "",
                              secretName,
                            })
                          }
                        >
                          Peek first value
                        </Menu.Item>
                        <Menu.Item
                          disabled={!Object.keys(secret?.values ?? {}).length}
                          onClick={() =>
                            onShare({
                              environment: Object.keys(secret?.values ?? {})[0] ?? "",
                              secretName,
                            })
                          }
                        >
                          Share first value
                        </Menu.Item>
                        <Menu.Item
                          disabled={!Object.keys(secret?.values ?? {}).length}
                          onClick={() =>
                            onRevoke({
                              environment: Object.keys(secret?.values ?? {})[0] ?? "",
                              secretName,
                            })
                          }
                        >
                          Revoke first value
                        </Menu.Item>
                        <Menu.Item
                          disabled={!Object.keys(secret?.values ?? {}).length}
                          onClick={() =>
                            onRemoveValue({
                              environment: Object.keys(secret?.values ?? {})[0] ?? "",
                              secretName,
                            })
                          }
                        >
                          Remove first value
                        </Menu.Item>
                        <Menu.Divider />
                        <Menu.Item color="red" onClick={() => onDelete(secretName)}>
                          Delete secret
                        </Menu.Item>
                      </Menu.Dropdown>
                    </Menu>
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text fw={600}>{secretName}</Text>
                  {secret?.description ? (
                    <Text c="dimmed" lineClamp={1} size="xs">
                      {secret.description}
                    </Text>
                  ) : null}
                </Table.Td>
                <Table.Td>
                  <Badge variant="light">{getCoverage(file, secretName)}</Badge>
                </Table.Td>
                <Table.Td>
                  {owners.length ? (
                    <OwnerBadges file={file} owners={owners} />
                  ) : (
                    <Badge color="red">no owners</Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  {issueCount ? (
                    <Badge color="red">
                      {issueCount} issue{issueCount === 1 ? "" : "s"}
                    </Badge>
                  ) : (
                    <Text c="dimmed" size="xs">
                      None
                    </Text>
                  )}
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </ScrollArea>
  );
}
