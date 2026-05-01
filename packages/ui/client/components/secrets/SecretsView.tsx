import { useState } from "react";
import { Alert, Button, Card, Group, Select, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconKey, IconPlus, IconSearch } from "@tabler/icons-react";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";
import { useTableFilters } from "../../hooks/useTableFilters";
import { EmptyStateCard } from "../shared/EmptyStateCard";
import type { SecretDetailPanel, SecretValueTarget } from "./secretTypes";
import { CreateSecretModal } from "./CreateSecretModal";
import { DeleteSecretModal } from "./DeleteSecretModal";
import { RenameSecretModal } from "./RenameSecretModal";
import { SecretDetailDrawer } from "./SecretDetailDrawer";
import { SecretsTable } from "./SecretsTable";
import { SetSecretValueModal } from "./SetSecretValueModal";

type SecretsOverlay =
  | { type: "none" }
  | { panel: SecretDetailPanel; secretName: string; type: "secret-detail" };

type PageModal =
  | { type: "none" }
  | { type: "create-secret" }
  | { secretName: string; type: "rename-secret" }
  | { secretName: string; type: "delete-secret" }
  | { target: SecretValueTarget; type: "set-value" };

export function SecretsView({
  data,
  derived,
}: {
  data: WorkspacePageData;
  derived: DerivedSecretsFileState;
}) {
  const file = data.snapshot.file;
  const { filters, setEnvironment, setOwner, setSearch } = useTableFilters();
  const [overlay, setOverlay] = useState<SecretsOverlay>({ type: "none" });
  const [pageModal, setPageModal] = useState<PageModal>({ type: "none" });
  const [importHint, setImportHint] = useState(false);

  if (!file) {
    return null;
  }

  function openDetail(secretName: string, panel: SecretDetailPanel = { type: "none" }) {
    setPageModal({ type: "none" });
    setOverlay({ panel, secretName, type: "secret-detail" });
  }

  function openPageModal(modal: PageModal) {
    setOverlay({ type: "none" });
    setPageModal(modal);
  }

  return (
    <Stack>
      {file.keys.length === 0 ? (
        <EmptyStateCard
          action={
            <Button component="a" href="/keys" leftSection={<IconKey size={16} />}>
              Import public key
            </Button>
          }
          description="Secrets cannot be encrypted until at least one OpenPGP public recipient key is configured."
          title="No recipient keys configured"
        />
      ) : null}
      {derived.secretCount === 0 ? (
        <EmptyStateCard
          action={
            <Button
              leftSection={<IconPlus size={16} />}
              onClick={() => openPageModal({ type: "create-secret" })}
            >
              Create secret
            </Button>
          }
          description="Create a secret with no plaintext, or include an initial encrypted value."
          title="No secrets configured"
        />
      ) : null}

      <Card withBorder>
        <Stack>
          <Group justify="space-between">
            <div>
              <Title order={2}>Secrets</Title>
              <Text c="dimmed" size="sm">
                Encrypted values and owners. Open a secret for per-environment detail.
              </Text>
            </div>
            <Group gap="xs">
              <Button
                leftSection={<IconPlus size={16} />}
                onClick={() => openPageModal({ type: "create-secret" })}
              >
                Create secret
              </Button>
              <Button
                onClick={() =>
                  openPageModal({
                    target: {
                      environment: file.environments[0] ?? "",
                      secretName: derived.secretNames[0] ?? "",
                    },
                    type: "set-value",
                  })
                }
                variant="light"
              >
                Set value
              </Button>
              <Button
                component="a"
                href="/keys"
                onClick={() => setImportHint(true)}
                variant="default"
              >
                Import public key
              </Button>
            </Group>
          </Group>
          {importHint ? (
            <Alert color="blue">Public key import is available in Recipient Keys.</Alert>
          ) : null}
          <Group align="end">
            <TextInput
              leftSection={<IconSearch size={16} />}
              label="Search"
              onChange={(event) => setSearch(event.currentTarget.value)}
              placeholder="Secret name"
              value={filters.search}
            />
            <Select
              clearable
              data={file.environments}
              label="Environment"
              onChange={setEnvironment}
              searchable
              value={filters.environment}
            />
            <Select
              clearable
              data={file.keys.map((key) => ({
                label: `${key.userIds[0] ?? key.fingerprint.slice(-12)} - ${key.fingerprint}`,
                value: key.fingerprint,
              }))}
              label="Owner fingerprint"
              onChange={setOwner}
              searchable
              value={filters.owner}
            />
          </Group>
          <SecretsTable
            derived={derived}
            file={file}
            filters={filters}
            onDelete={(secretName) => openPageModal({ secretName, type: "delete-secret" })}
            onOpen={(secretName) => openDetail(secretName)}
            onPeek={(target) =>
              openDetail(target.secretName, { environment: target.environment, type: "peek" })
            }
            onRemoveValue={(target) =>
              openDetail(target.secretName, {
                environment: target.environment,
                type: "remove-value",
              })
            }
            onRename={(secretName) => openPageModal({ secretName, type: "rename-secret" })}
            onRevoke={(target) =>
              openDetail(target.secretName, { environment: target.environment, type: "revoke" })
            }
            onSetValue={(target) => openPageModal({ target, type: "set-value" })}
            onShare={(target) =>
              openDetail(target.secretName, { environment: target.environment, type: "share" })
            }
          />
        </Stack>
      </Card>

      <CreateSecretModal
        file={file}
        onClose={() => setPageModal({ type: "none" })}
        opened={pageModal.type === "create-secret"}
      />
      <RenameSecretModal
        file={file}
        onClose={() => setPageModal({ type: "none" })}
        opened={pageModal.type === "rename-secret"}
        secretName={pageModal.type === "rename-secret" ? pageModal.secretName : null}
      />
      <DeleteSecretModal
        file={file}
        onClose={() => setPageModal({ type: "none" })}
        opened={pageModal.type === "delete-secret"}
        secretName={pageModal.type === "delete-secret" ? pageModal.secretName : null}
      />
      <SetSecretValueModal
        file={file}
        onClose={() => setPageModal({ type: "none" })}
        opened={pageModal.type === "set-value"}
        target={pageModal.type === "set-value" ? pageModal.target : null}
      />
      <SecretDetailDrawer
        activePanel={overlay.type === "secret-detail" ? overlay.panel : { type: "none" }}
        file={file}
        onClose={() => setOverlay({ type: "none" })}
        onPanelChange={(panel) => {
          if (overlay.type === "secret-detail") {
            setOverlay({ ...overlay, panel });
          }
        }}
        opened={overlay.type === "secret-detail"}
        secretName={overlay.type === "secret-detail" ? overlay.secretName : null}
      />
    </Stack>
  );
}
