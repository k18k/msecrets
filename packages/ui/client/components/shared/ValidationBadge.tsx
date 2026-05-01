import { Badge, Group, Tooltip } from "@mantine/core";
import { IconAlertTriangle, IconCircleCheck, IconCircleX } from "@tabler/icons-react";

export function ValidationBadge({
  errorCount,
  valid,
  warningCount,
}: {
  errorCount: number;
  valid: boolean;
  warningCount: number;
}) {
  if (errorCount > 0 || !valid) {
    return (
      <Tooltip label={`${errorCount} validation error${errorCount === 1 ? "" : "s"}`}>
        <Badge color="red" leftSection={<IconCircleX size={12} />} variant="light">
          invalid
        </Badge>
      </Tooltip>
    );
  }

  if (warningCount > 0) {
    return (
      <Tooltip label={`${warningCount} warning${warningCount === 1 ? "" : "s"}`}>
        <Badge color="yellow" leftSection={<IconAlertTriangle size={12} />} variant="light">
          warnings
        </Badge>
      </Tooltip>
    );
  }

  return (
    <Group gap={4}>
      <Badge color="green" leftSection={<IconCircleCheck size={12} />} variant="light">
        valid
      </Badge>
    </Group>
  );
}
