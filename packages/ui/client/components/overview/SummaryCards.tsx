import { Card, SimpleGrid, Stack, Text, Title } from "@mantine/core";

import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";

export function SummaryCards({
  derived,
  runtimeKeyCount,
}: {
  derived: DerivedSecretsFileState;
  runtimeKeyCount: number;
}) {
  const items = [
    ["Secrets", derived.secretCount],
    ["Environments", derived.environmentCount],
    ["Recipient keys", derived.keysCount],
    ["Runtime keys", runtimeKeyCount],
  ] as const;

  return (
    <SimpleGrid cols={{ base: 2, lg: 4 }}>
      {items.map(([label, value]) => (
        <Card key={label} p="md" withBorder>
          <Stack gap={2}>
            <Text c="dimmed" size="xs" tt="uppercase">
              {label}
            </Text>
            <Title order={3}>{value}</Title>
          </Stack>
        </Card>
      ))}
    </SimpleGrid>
  );
}
