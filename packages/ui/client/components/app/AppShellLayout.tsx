import type { ReactNode } from "react";
import { Alert, AppShell, Box, Loader, Stack, Text } from "@mantine/core";
import { IconAlertCircle } from "@tabler/icons-react";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import { useDerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { useSecretsFileQuery } from "../../hooks/useSecretsFileQuery";
import { SessionGpgKeyImportPrompt } from "../runtime-keys/SessionGpgKeyImportPrompt";
import { EmptyStateCard } from "../shared/EmptyStateCard";
import { HeaderStatusBar } from "./HeaderStatusBar";
import { SidebarNav } from "./SidebarNav";

export function AppShellLayout({
  children,
}: {
  children: (
    data: WorkspacePageData,
    derived: ReturnType<typeof useDerivedSecretsFileState>,
  ) => ReactNode;
}) {
  const query = useSecretsFileQuery();
  const data = query.data;
  const derived = useDerivedSecretsFileState(
    data?.snapshot.file ?? null,
    data?.audit ?? {
      exists: false,
      file: null,
      findings: [],
      importableKeys: [],
      localKeys: [],
      path: "",
      summary: {
        configuredKeyCount: 0,
        emptySecrets: [],
        environmentCount: 0,
        environmentUsage: [],
        importableKeyCount: 0,
        localKeyCount: 0,
        secretCount: 0,
        valueCount: 0,
      },
      valid: false,
    },
  );

  if (query.isLoading) {
    return (
      <Box p="xl">
        <Loader />
      </Box>
    );
  }

  if (query.isError || !data) {
    return (
      <Alert color="red" icon={<IconAlertCircle size={18} />} m="md" title="Failed to load UI data">
        {query.error instanceof Error ? query.error.message : "Unknown UI data error"}
      </Alert>
    );
  }

  return (
    <AppShell header={{ height: 58 }} navbar={{ breakpoint: "sm", width: 260 }}>
      <AppShell.Header>
        <HeaderStatusBar data={data} derived={derived} />
      </AppShell.Header>
      <SidebarNav derived={derived} />
      <AppShell.Main>
        <SessionGpgKeyImportPrompt data={data} />
        <Stack gap="md" p="md">
          {data.notice ? (
            <Alert color={data.notice.tone === "error" ? "red" : "green"} variant="light">
              <Text size="sm">{data.notice.message}</Text>
            </Alert>
          ) : null}
          {!data.snapshot.exists ? (
            <EmptyStateCard
              action={null}
              description="No `.env.ms.json` file found in the configured workspace."
              title="No `.env.ms.json` file found"
              withInitialJson
            />
          ) : null}
          {children(data, derived)}
        </Stack>
      </AppShell.Main>
    </AppShell>
  );
}
