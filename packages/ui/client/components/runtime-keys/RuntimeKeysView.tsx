import { useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Select,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import { queryKeys } from "../../hooks/queryKeys";
import { useDisclosureState } from "../../hooks/useDisclosureState";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { ClearRuntimePrivateKeyModal } from "./ClearRuntimePrivateKeyModal";
import { ImportPrivateKeyModal } from "./ImportPrivateKeyModal";

function shortFingerprint(fingerprint: string) {
  return `${fingerprint.slice(0, 4)}...${fingerprint.slice(-4)}`;
}

export function RuntimeKeysView({ data }: { data: WorkspacePageData }) {
  const file = data.snapshot.file;
  const importPrivate = useDisclosureState<true>();
  const clear = useDisclosureState<string>();
  const importFromGpg = useOrpcMutation<
    { gpgFingerprint: string | null },
    { fingerprint: string; userIds: string[] }
  >({
    invalidateRuntimeKeys: true,
    mutationFn: (input) => orpcClient.runtimeKeys.importPrivate(input),
    onSuccess: () => setSelectedGpgFingerprint(null),
  });
  const [selectedGpgFingerprint, setSelectedGpgFingerprint] = useState<string | null>(null);
  const runtimeQuery = useQuery({
    queryFn: () => orpcClient.runtimeKeys.listIdentities(),
    queryKey: queryKeys.runtimeKeys,
  });
  const runtime = runtimeQuery.data ?? data.keyManagement.runtimePrivateKeys;
  const available = new Set(runtime.map((key) => key.fingerprint));
  const gpgKeys = useQuery({
    queryFn: () => orpcClient.runtimeKeys.listGpgKeys(),
    queryKey: queryKeys.gpgKeys,
  });
  const relevantGpgKeys = useMemo(() => {
    const configured = new Set(file?.keys.map((key) => key.fingerprint) ?? []);
    return (gpgKeys.data ?? []).filter((key) => configured.has(key.fingerprint));
  }, [file?.keys, gpgKeys.data]);
  const gpgOptions = relevantGpgKeys.map((key) => ({
    label: `${key.userIds[0] ?? "Local key"} - ${shortFingerprint(key.fingerprint)}`,
    value: key.fingerprint,
  }));

  return (
    <Stack>
      <Alert color="blue" variant="light">
        Configured recipient keys are committed in `.env.ms.json`. Runtime/private keys are local
        only and are used for decrypting and re-encrypting values.
      </Alert>
      {!runtime.length ? (
        <Alert color="yellow">Workspace has no runtime/private keys available.</Alert>
      ) : null}
      <Card withBorder>
        <Stack>
          <Group justify="space-between">
            <div>
              <Title order={2}>Runtime Keys</Title>
              <Text c="dimmed" size="sm">
                Local-only private key availability for peek/share/revoke/remove-key flows.
              </Text>
            </div>
            <Button leftSection={<IconPlus size={16} />} onClick={() => importPrivate.open(true)}>
              Import private key
            </Button>
          </Group>
          <Title order={3}>Configured keys</Title>
          <Table highlightOnHover striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>User ID</Table.Th>
                <Table.Th>Fingerprint</Table.Th>
                <Table.Th>Local status</Table.Th>
                <Table.Th>Actions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(file?.keys ?? []).map((key) => {
                const localGpgAvailable = relevantGpgKeys.some(
                  (candidate) => candidate.fingerprint === key.fingerprint,
                );
                return (
                  <Table.Tr key={key.fingerprint}>
                    <Table.Td>{key.userIds[0] ?? "No user ID"}</Table.Td>
                    <Table.Td>
                      <Text ff="monospace" size="sm">
                        {shortFingerprint(key.fingerprint)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {available.has(key.fingerprint) ? (
                        <Badge color="green">Available</Badge>
                      ) : localGpgAvailable ? (
                        <Badge color="blue">GPG key found</Badge>
                      ) : (
                        <Badge color="yellow">Missing</Badge>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {available.has(key.fingerprint) ? (
                          <Button
                            color="red"
                            onClick={() => clear.open(key.fingerprint)}
                            size="compact-xs"
                            variant="light"
                          >
                            Clear
                          </Button>
                        ) : localGpgAvailable ? (
                          <Button
                            loading={importFromGpg.isPending}
                            onClick={() =>
                              importFromGpg.mutate({ gpgFingerprint: key.fingerprint })
                            }
                            size="compact-xs"
                          >
                            Use
                          </Button>
                        ) : (
                          <Button
                            onClick={() => importPrivate.open(true)}
                            size="compact-xs"
                            variant="light"
                          >
                            Import
                          </Button>
                        )}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Stack>
      </Card>
      <Card withBorder>
        <Stack>
          <Title order={3}>Available local GPG/private keys</Title>
          {gpgKeys.isError ? (
            <Alert color="yellow">
              Local GPG key listing is not exposed by the current backend.
            </Alert>
          ) : (
            <Group align="end">
              <Select
                data={gpgOptions}
                disabled={!gpgOptions.length || gpgKeys.isLoading}
                label="Matching local key"
                onChange={setSelectedGpgFingerprint}
                placeholder={gpgKeys.isLoading ? "Loading local keys" : "Select a matching key"}
                searchable
                value={selectedGpgFingerprint}
              />
              <Button
                disabled={!selectedGpgFingerprint}
                loading={importFromGpg.isPending}
                onClick={() => importFromGpg.mutate({ gpgFingerprint: selectedGpgFingerprint })}
              >
                Use selected key
              </Button>
              <Button onClick={() => importPrivate.open(true)} variant="light">
                Import armored private key manually
              </Button>
            </Group>
          )}
          {!gpgKeys.isError && !gpgOptions.length ? (
            <Text c="dimmed" size="sm">
              No matching local GPG private keys were discovered for the configured recipients.
            </Text>
          ) : null}
        </Stack>
      </Card>
      <ImportPrivateKeyModal onClose={importPrivate.close} opened={importPrivate.opened} />
      <ClearRuntimePrivateKeyModal
        data={data}
        fingerprint={clear.value}
        onClose={clear.close}
        opened={clear.opened}
      />
    </Stack>
  );
}
