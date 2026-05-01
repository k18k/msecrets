import { Stack, Text, Title } from "@mantine/core";

import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { DiagnosticsList } from "./DiagnosticsList";

export function DiagnosticsView({ derived }: { derived: DerivedSecretsFileState }) {
  return (
    <Stack>
      <div>
        <Title order={2}>Diagnostics</Title>
        <Text c="dimmed" size="sm">
          Validation findings and runtime/private key warnings grouped by file area.
        </Text>
      </div>
      <DiagnosticsList diagnostics={derived.diagnostics} />
    </Stack>
  );
}
