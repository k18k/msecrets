import { Button, Card, Group, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconKey, IconPlus, IconSearch } from "@tabler/icons-react";
import { useMemo, useState } from "react";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { useDisclosureState } from "../../hooks/useDisclosureState";
import { EmptyStateCard } from "../shared/EmptyStateCard";
import { ImportPrivateKeyModal } from "../runtime-keys/ImportPrivateKeyModal";
import { InspectPublicKeyModal } from "./InspectPublicKeyModal";
import { ImportPublicKeyModal } from "./ImportPublicKeyModal";
import { RecipientKeysTable } from "./RecipientKeysTable";
import { RemoveConfiguredKeyModal } from "./RemoveConfiguredKeyModal";

export function RecipientKeysView({
  data,
  derived,
}: {
  data: WorkspacePageData;
  derived: DerivedSecretsFileState;
}) {
  const file = data.snapshot.file;
  const importPublic = useDisclosureState<true>();
  const importPrivate = useDisclosureState<true>();
  const inspect = useDisclosureState<string>();
  const remove = useDisclosureState<string>();
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    if (!file) return null;
    const query = search.toLowerCase();
    return {
      ...file,
      keys: file.keys.filter(
        (key) =>
          key.fingerprint.toLowerCase().includes(query) ||
          key.userIds.some((id) => id.toLowerCase().includes(query)),
      ),
    };
  }, [file, search]);

  if (!file || !filtered) return null;

  return (
    <Stack>
      {file.keys.length === 0 ? (
        <EmptyStateCard
          action={<Button onClick={() => importPublic.open(true)}>Import public key</Button>}
          description="Secrets cannot be encrypted without configured recipient keys."
          title="No recipient keys configured"
        />
      ) : null}
      <Card withBorder>
        <Stack>
          <Group justify="space-between">
            <div>
              <Title order={2}>Recipient Keys</Title>
              <Text c="dimmed" size="sm">
                Committed OpenPGP public keys and ownership impact.
              </Text>
            </div>
            <Group>
              <Button leftSection={<IconPlus size={16} />} onClick={() => importPublic.open(true)}>
                Import public key
              </Button>
              <Button
                leftSection={<IconKey size={16} />}
                onClick={() => importPrivate.open(true)}
                variant="light"
              >
                Import runtime key
              </Button>
            </Group>
          </Group>
          <TextInput
            leftSection={<IconSearch size={16} />}
            onChange={(event) => setSearch(event.currentTarget.value)}
            placeholder="Search fingerprint or user ID"
            value={search}
          />
          <RecipientKeysTable
            data={data}
            derived={derived}
            file={filtered}
            onInspect={inspect.open}
            onRemove={remove.open}
          />
        </Stack>
      </Card>
      <ImportPublicKeyModal onClose={importPublic.close} opened={importPublic.opened} />
      <ImportPrivateKeyModal onClose={importPrivate.close} opened={importPrivate.opened} />
      <InspectPublicKeyModal
        file={file}
        fingerprint={inspect.value}
        onClose={inspect.close}
        opened={inspect.opened}
      />
      <RemoveConfiguredKeyModal
        derived={derived}
        file={file}
        fingerprint={remove.value}
        onClose={remove.close}
        opened={remove.opened}
      />
    </Stack>
  );
}
