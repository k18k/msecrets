import { useState } from "react";
import { Alert, Button, Card, Group, Stack, Text, Title } from "@mantine/core";
import { Link } from "@tanstack/react-router";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState, Diagnostic } from "../../hooks/useDerivedSecretsFileState";
import { useDisclosureState } from "../../hooks/useDisclosureState";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { EmptyStateCard } from "../shared/EmptyStateCard";
import { SecretDetailDrawer } from "../secrets/SecretDetailDrawer";
import { SetSecretValueModal } from "../secrets/SetSecretValueModal";
import type { SecretDetailPanel, SecretValueTarget } from "../secrets/secretTypes";
import { ProblemsPanel } from "./ProblemsPanel";
import { SecretEnvironmentMatrix } from "./SecretEnvironmentMatrix";
import { SummaryCards } from "./SummaryCards";

export function OverviewView({
  data,
  derived,
}: {
  data: WorkspacePageData;
  derived: DerivedSecretsFileState;
}) {
  const file = data.snapshot.file;
  const initialize = useOrpcMutation<void, { created: boolean }>({
    mutationFn: () => orpcClient.file.initialize(),
  });
  const drawer = useDisclosureState<string>();
  const setValue = useDisclosureState<SecretValueTarget>();
  const [detailPanel, setDetailPanel] = useState<SecretDetailPanel>({ type: "none" });

  if (!file) {
    return (
      <EmptyStateCard
        action={
          <Button loading={initialize.isPending} onClick={() => initialize.mutate()}>
            Initialize file
          </Button>
        }
        description="Initialize the portable repository-native secrets contract."
        title="No `.env.ms.json` file found"
        withInitialJson
      />
    );
  }

  function handleProblemAction(action: NonNullable<Diagnostic["action"]>) {
    if (action === "add-environment") window.location.assign("/environments");
    if (action === "create-secret") window.location.assign("/secrets");
    if (action === "import-public-key") window.location.assign("/keys");
    if (action === "set-values") window.location.assign("/secrets");
  }

  const actionableDiagnostics = derived.diagnostics.filter((diagnostic) => diagnostic.action);

  return (
    <Stack>
      <div>
        <Title order={2}>Overview</Title>
        <Text c="dimmed" size="sm">
          Workspace health and common file editor workflows.
        </Text>
      </div>
      <Card withBorder>
        <Stack gap="xs">
          <Title order={3}>Workspace Health</Title>
          <Alert
            color={derived.errorCount ? "red" : derived.warningCount ? "yellow" : "green"}
            variant="light"
          >
            {derived.errorCount
              ? `${derived.errorCount} error${derived.errorCount === 1 ? "" : "s"} need attention before the file is healthy.`
              : derived.warningCount
                ? `${derived.warningCount} warning${derived.warningCount === 1 ? "" : "s"} found. Core file validation passed.`
                : "The workspace is valid and no warnings were found."}
          </Alert>
        </Stack>
      </Card>
      <Card withBorder>
        <Stack>
          <Title order={3}>Quick Actions</Title>
          <Group>
            <Button component={Link} to="/secrets">
              Create secret
            </Button>
            <Button component={Link} to="/secrets" variant="light">
              Set value
            </Button>
            <Button component={Link} to="/keys" variant="light">
              Import public key
            </Button>
            <Button component={Link} to="/runtime-keys" variant="light">
              Import runtime/private key
            </Button>
          </Group>
        </Stack>
      </Card>
      <SummaryCards
        derived={derived}
        runtimeKeyCount={data.keyManagement.runtimePrivateKeys.length}
      />
      <SecretEnvironmentMatrix
        derived={derived}
        file={file}
        onOpenSecret={(secretName) => {
          setDetailPanel({ type: "none" });
          drawer.open(secretName);
        }}
        onSetValue={(secretName, environment) => setValue.open({ environment, secretName })}
        onValueActions={(secretName) => {
          setDetailPanel({ type: "none" });
          drawer.open(secretName);
        }}
      />
      <ProblemsPanel diagnostics={actionableDiagnostics} onAction={handleProblemAction} />
      <SetSecretValueModal
        file={file}
        onClose={setValue.close}
        opened={setValue.opened}
        target={setValue.value}
      />
      <SecretDetailDrawer
        activePanel={detailPanel}
        file={file}
        onClose={() => {
          setDetailPanel({ type: "none" });
          drawer.close();
        }}
        onPanelChange={setDetailPanel}
        opened={drawer.opened}
        secretName={drawer.value}
      />
    </Stack>
  );
}
