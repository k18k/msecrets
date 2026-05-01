import type { ReactNode } from "react";
import { Alert, Button, Code, Group, Stack, Text, Title } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";

const initialJson = `{
  "version": "2.0.0",
  "environments": ["development"],
  "keys": [],
  "secrets": {}
}`;

export function EmptyStateCard({
  action,
  description,
  title,
  withInitialJson,
}: {
  action?: ReactNode;
  description: string;
  title: string;
  withInitialJson?: boolean;
}) {
  return (
    <Alert color="yellow" icon={<IconAlertTriangle size={18} />} p="lg" variant="light">
      <Stack gap="sm">
        <Group justify="space-between" wrap="nowrap">
          <div>
            <Title order={3}>{title}</Title>
            <Text size="sm">{description}</Text>
          </div>
          {action ? <div>{action}</div> : null}
        </Group>
        {withInitialJson ? (
          <Code block fz="sm">
            {initialJson}
          </Code>
        ) : null}
      </Stack>
    </Alert>
  );
}

export function DisabledBackendButton({ label }: { label: string }) {
  return (
    <Button disabled variant="light">
      {label}
    </Button>
  );
}
