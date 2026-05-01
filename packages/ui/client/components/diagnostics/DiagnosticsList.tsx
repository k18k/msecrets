import { Badge, Card, Group, Stack, Text, Title } from "@mantine/core";

import type { Diagnostic } from "../../hooks/useDerivedSecretsFileState";

const groups: Diagnostic["group"][] = [
  "file/root",
  "environments",
  "keys",
  "secrets",
  "owners",
  "runtime/private keys",
];

export function DiagnosticsList({ diagnostics }: { diagnostics: Diagnostic[] }) {
  const groupsWithItems = groups
    .map((group) => ({
      group,
      items: diagnostics.filter((diagnostic) => diagnostic.group === group),
    }))
    .filter((entry) => entry.items.length > 0);

  return (
    <Stack>
      {groupsWithItems.length ? (
        groupsWithItems.map(({ group, items }) => (
          <Card key={group} withBorder>
            <Title order={3} tt="capitalize">
              {group}
            </Title>
            <Stack gap="xs" mt="sm">
              {items.map((item, index) => (
                <Group key={`${item.path}-${index}`} align="flex-start" justify="space-between">
                  <div>
                    <Group gap="xs">
                      <Badge color={item.severity === "error" ? "red" : "yellow"}>
                        {item.severity}
                      </Badge>
                      <Text c="dimmed" size="xs">
                        {item.path}
                      </Text>
                    </Group>
                    <Text size="sm">{item.message}</Text>
                    {item.action ? (
                      <Text c="dimmed" size="xs">
                        Suggested fix: {item.action}
                      </Text>
                    ) : null}
                  </div>
                </Group>
              ))}
            </Stack>
          </Card>
        ))
      ) : (
        <Text c="dimmed" size="sm">
          No diagnostics.
        </Text>
      )}
    </Stack>
  );
}
