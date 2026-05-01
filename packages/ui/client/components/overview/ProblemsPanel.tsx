import { Alert, Badge, Button, Card, Group, Stack, Text, Title } from "@mantine/core";

import type { Diagnostic } from "../../hooks/useDerivedSecretsFileState";

export function ProblemsPanel({
  diagnostics,
  onAction,
}: {
  diagnostics: Diagnostic[];
  onAction: (action: NonNullable<Diagnostic["action"]>) => void;
}) {
  if (!diagnostics.length) {
    return (
      <Alert color="green" variant="light">
        No actionable warnings or errors need attention.
      </Alert>
    );
  }

  return (
    <Card withBorder>
      <Stack>
        <Title order={3}>Attention Needed</Title>
        {diagnostics.map((diagnostic, index) => (
          <Group
            key={`${diagnostic.path}-${diagnostic.message}-${index}`}
            align="flex-start"
            justify="space-between"
          >
            <div>
              <Group gap="xs">
                <Badge color={diagnostic.severity === "error" ? "red" : "yellow"}>
                  {diagnostic.severity}
                </Badge>
                <Text c="dimmed" size="xs">
                  {diagnostic.path}
                </Text>
              </Group>
              <Text size="sm">{diagnostic.message}</Text>
            </div>
            {diagnostic.action ? (
              <Button
                onClick={() => onAction(diagnostic.action!)}
                size="compact-xs"
                variant="light"
              >
                Fix
              </Button>
            ) : null}
          </Group>
        ))}
      </Stack>
    </Card>
  );
}
