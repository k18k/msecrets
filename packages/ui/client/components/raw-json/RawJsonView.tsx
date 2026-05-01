import { Button, Card, Code, CopyButton, Group, Stack, Text, Title } from "@mantine/core";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { ValidationBadge } from "../shared/ValidationBadge";

export function RawJsonView({
  data,
  derived,
}: {
  data: WorkspacePageData;
  derived: DerivedSecretsFileState;
}) {
  const file = data.snapshot.file;
  const raw = file ? `${JSON.stringify(file, null, 2)}\n` : "";

  return (
    <Card withBorder>
      <Stack>
        <Group justify="space-between">
          <div>
            <Title order={2}>Raw JSON</Title>
            <Text c="dimmed" size="sm">
              Read-only view of `.env.ms.json`; writes stay behind existing workflow actions.
            </Text>
          </div>
          <Group>
            <ValidationBadge
              errorCount={derived.errorCount}
              valid={data.audit.valid}
              warningCount={derived.warningCount}
            />
            <CopyButton value={raw}>
              {({ copied, copy }) => (
                <Button disabled={!file} onClick={copy} variant="light">
                  {copied ? "Copied" : "Copy JSON"}
                </Button>
              )}
            </CopyButton>
          </Group>
        </Group>
        <Text c="dimmed" size="xs">
          {data.configPath}
        </Text>
        <Code block mah="70vh" style={{ overflow: "auto", whiteSpace: "pre" }}>
          {raw || "No file loaded"}
        </Code>
      </Stack>
    </Card>
  );
}
