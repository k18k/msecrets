import { Button, Card, Drawer, Group, List, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconPlus, IconSearch } from "@tabler/icons-react";
import { useMemo, useState } from "react";

import type { DashboardPageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { useDisclosureState } from "../../hooks/useDisclosureState";
import { EmptyStateCard } from "../shared/EmptyStateCard";
import { AddEnvironmentModal } from "./AddEnvironmentModal";
import { EnvironmentsTable } from "./EnvironmentsTable";
import { RemoveEnvironmentModal } from "./RemoveEnvironmentModal";
import { RenameEnvironmentModal } from "./RenameEnvironmentModal";

export function EnvironmentsView({
  data,
  derived,
}: {
  data: DashboardPageData;
  derived: DerivedSecretsFileState;
}) {
  const file = data.snapshot.file;
  const add = useDisclosureState<true>();
  const rename = useDisclosureState<string>();
  const remove = useDisclosureState<string>();
  const affected = useDisclosureState<string>();
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    if (!file) return null;
    return {
      ...file,
      environments: file.environments.filter((environment) =>
        environment.toLowerCase().includes(search.toLowerCase()),
      ),
    };
  }, [file, search]);

  if (!file || !filtered) return null;

  return (
    <Stack>
      {file.environments.length === 0 ? (
        <EmptyStateCard
          action={<Button onClick={() => add.open(true)}>Add environment</Button>}
          description="At least one declared environment is needed before values can be set."
          title="No environments configured"
        />
      ) : null}
      <Card withBorder>
        <Stack>
          <Group justify="space-between">
            <div>
              <Title order={2}>Environments</Title>
              <Text c="dimmed" size="sm">
                Declared environment names and value coverage.
              </Text>
            </div>
            <Button leftSection={<IconPlus size={16} />} onClick={() => add.open(true)}>
              Add environment
            </Button>
          </Group>
          <TextInput
            leftSection={<IconSearch size={16} />}
            onChange={(event) => setSearch(event.currentTarget.value)}
            placeholder="Search environments"
            value={search}
          />
          <EnvironmentsTable
            derived={derived}
            file={filtered}
            onRemove={remove.open}
            onRename={rename.open}
            onView={affected.open}
          />
        </Stack>
      </Card>
      <AddEnvironmentModal onClose={add.close} opened={add.opened} />
      <RenameEnvironmentModal
        environment={rename.value}
        file={file}
        onClose={rename.close}
        opened={rename.opened}
      />
      <RemoveEnvironmentModal
        environment={remove.value}
        file={file}
        onClose={remove.close}
        opened={remove.opened}
      />
      <Drawer
        onClose={affected.close}
        opened={affected.opened}
        position="right"
        title="Affected secrets"
      >
        <Stack>
          <Text c="dimmed" size="sm">
            {affected.value}
          </Text>
          <List>
            {Object.keys(file.secrets)
              .filter((secretName) =>
                Boolean(file.secrets[secretName]?.values[affected.value ?? ""]),
              )
              .map((secretName) => (
                <List.Item key={secretName}>{secretName}</List.Item>
              ))}
          </List>
        </Stack>
      </Drawer>
    </Stack>
  );
}
