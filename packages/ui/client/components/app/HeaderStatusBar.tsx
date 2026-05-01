import { Badge, Button, Group, Text, Tooltip } from "@mantine/core";
import { IconDatabase, IconKey, IconRefresh, IconSquareRoundedPlus } from "@tabler/icons-react";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { ValidationBadge } from "../shared/ValidationBadge";

export function HeaderStatusBar({
  data,
  derived,
}: {
  data: WorkspacePageData;
  derived: DerivedSecretsFileState;
}) {
  const initialize = useOrpcMutation<void, { created: boolean }>({
    mutationFn: () => orpcClient.file.initialize(),
  });
  const file = data.snapshot.file;
  const runtimeKeys = data.keyManagement.runtimePrivateKeys.length;

  return (
    <Group h="100%" justify="space-between" px="md" wrap="nowrap">
      <Group gap="sm" wrap="nowrap">
        <IconDatabase size={20} />
        <div>
          <Text fw={700} lh={1.1}>
            msecrets
          </Text>
          <Text c="dimmed" fz="xs" lh={1.1}>
            {data.configPath.endsWith(".env.ms.json") ? ".env.ms.json" : data.configPath}
          </Text>
        </div>
        <Badge color={data.snapshot.exists ? "green" : "yellow"} variant="light">
          {data.snapshot.exists ? "file loaded" : "no file"}
        </Badge>
        {file ? <Badge variant="outline">v{file.version}</Badge> : null}
        <ValidationBadge
          errorCount={derived.errorCount}
          valid={data.audit.valid}
          warningCount={derived.warningCount}
        />
        <Tooltip label={`${runtimeKeys} runtime/private key${runtimeKeys === 1 ? "" : "s"} loaded`}>
          <Badge
            color={runtimeKeys ? "green" : "gray"}
            leftSection={<IconKey size={12} />}
            variant="light"
          >
            runtime {runtimeKeys}
          </Badge>
        </Tooltip>
      </Group>

      <Group gap="xs" wrap="nowrap">
        {!data.snapshot.exists ? (
          <Button
            leftSection={<IconSquareRoundedPlus size={16} />}
            loading={initialize.isPending}
            onClick={() => initialize.mutate()}
            size="xs"
          >
            Initialize
          </Button>
        ) : null}
        <Button
          leftSection={<IconRefresh size={16} />}
          onClick={() => window.location.reload()}
          size="xs"
          variant="default"
        >
          Validate/Refresh
        </Button>
      </Group>
    </Group>
  );
}
