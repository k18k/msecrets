import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Divider,
  Drawer,
  Group,
  PasswordInput,
  ScrollArea,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  Title,
} from "@mantine/core";

import type { WorkspaceFile } from "../../../server/lib/types.ts";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";
import { InlineEditableText } from "../shared/InlineEditableText";
import { getKeyLabel } from "../shared/OwnerBadges";
import { OwnerBadges } from "../shared/OwnerBadges";
import { SearchableKeySelect } from "../shared/SearchableKeySelect";
import type { SecretDetailPanel } from "./secretTypes";

function statusColor(status: string) {
  if (status === "missing") return "gray";
  if (status === "encrypted") return "green";
  return "red";
}

export function SecretDetailDrawer({
  file,
  activePanel,
  onClose,
  onPanelChange,
  opened,
  secretName,
}: {
  file: WorkspaceFile;
  activePanel: SecretDetailPanel;
  onClose: () => void;
  onPanelChange: (panel: SecretDetailPanel) => void;
  opened: boolean;
  secretName: string | null;
}) {
  const secret = secretName ? file.secrets[secretName] : undefined;
  const [visibleCiphertexts, setVisibleCiphertexts] = useState<Set<string>>(new Set());
  const [fingerprint, setFingerprint] = useState<string | null>(file.keys[0]?.fingerprint ?? null);
  const [plaintextValue, setPlaintextValue] = useState("");
  const [showPlaintext, setShowPlaintext] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const setValue = useOrpcMutation<
    {
      environment: string | null;
      fingerprint: string | null;
      name: string | null;
      plaintextValue: string;
    },
    { environment: string; name: string }
  >({
    mutationFn: (input) => orpcClient.values.set(input),
    onSuccess: () => closePanel(),
  });
  const share = useOrpcMutation<
    { environment: string | undefined; fingerprint: string | null; name: string | null },
    { environment: string; name: string; owners: string[] }
  >({
    mutationFn: (input) => orpcClient.values.share(input),
    onSuccess: () => closePanel(),
  });
  const revoke = useOrpcMutation<
    { environment: string | undefined; fingerprint: string | null; name: string | null },
    { environment: string; name: string; owners: string[] }
  >({
    mutationFn: (input) => orpcClient.values.revoke(input),
    onSuccess: () => closePanel(),
  });
  const removeValue = useOrpcMutation<
    { environment: string | undefined; name: string | null },
    { environment: string; name: string; removedSecret: boolean }
  >({
    mutationFn: (input) => orpcClient.values.remove(input),
    onSuccess: () => closePanel(),
  });
  const peek = useOrpcMutation<
    { environment: string; name: string },
    { environment: string; info: string; name: string; payload: string }
  >({
    mutationFn: (input) => orpcClient.values.peek(input),
  });

  useEffect(() => {
    if (!opened) {
      setVisibleCiphertexts(new Set());
      closePanel();
    }
  }, [opened]);

  useEffect(() => {
    if (activePanel.type === "revoke" && secret) {
      setFingerprint(secret.values[activePanel.environment]?.owners[0] ?? null);
    } else if (activePanel.type === "share") {
      setFingerprint(null);
    } else {
      setFingerprint(file.keys[0]?.fingerprint ?? null);
    }

    setPlaintextValue("");
    setShowPlaintext(false);
    setConfirmation("");
    peek.reset();
  }, [activePanel, file.keys, secret]);

  function closePanel() {
    setFingerprint(file.keys[0]?.fingerprint ?? null);
    setPlaintextValue("");
    setShowPlaintext(false);
    setConfirmation("");
    peek.reset();
    onPanelChange({ type: "none" });
  }

  function toggleCiphertext(environment: string) {
    setVisibleCiphertexts((current) => {
      const next = new Set(current);
      if (next.has(environment)) {
        next.delete(environment);
      } else {
        next.add(environment);
      }
      return next;
    });
  }

  return (
    <Drawer
      onClose={onClose}
      opened={opened}
      position="right"
      size="xl"
      title={secretName ? `Secret: ${secretName}` : "Secret"}
    >
      {secretName && secret ? (
        <Stack>
          <InlineEditableText disabled label="Description" value={secret.description ?? ""} />
          <Text c="dimmed" size="xs">
            Description editing is not available in the current backend action set.
          </Text>
          <Title order={4}>Values</Title>
          <ScrollArea>
            <Table highlightOnHover striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Environment</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Owners</Table.Th>
                  <Table.Th>Actions</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {file.environments.map((environment) => {
                  const value = secret.values[environment];
                  // const target = { environment, secretName };
                  const status = value ? "encrypted" : "missing";

                  return (
                    <Table.Tr key={environment}>
                      <Table.Td>{environment}</Table.Td>
                      <Table.Td>
                        <Badge color={statusColor(status)}>{status}</Badge>
                      </Table.Td>
                      <Table.Td>
                        {value ? <OwnerBadges file={file} owners={value.owners} /> : "-"}
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          <Button
                            onClick={() => onPanelChange({ environment, type: "set-value" })}
                            size="compact-xs"
                            variant="light"
                          >
                            {value ? "Overwrite" : "Set"}
                          </Button>
                          <Button
                            disabled={!value}
                            onClick={() => onPanelChange({ environment, type: "peek" })}
                            size="compact-xs"
                            variant="default"
                          >
                            Peek
                          </Button>
                          <Button
                            disabled={!value}
                            onClick={() => onPanelChange({ environment, type: "share" })}
                            size="compact-xs"
                            variant="default"
                          >
                            Share
                          </Button>
                          <Button
                            disabled={!value}
                            onClick={() => onPanelChange({ environment, type: "revoke" })}
                            size="compact-xs"
                            variant="default"
                          >
                            Revoke
                          </Button>
                          <Button
                            color="red"
                            disabled={!value}
                            onClick={() => onPanelChange({ environment, type: "remove-value" })}
                            size="compact-xs"
                            variant="light"
                          >
                            Remove
                          </Button>
                          <Button
                            disabled={!value}
                            onClick={() => toggleCiphertext(environment)}
                            size="compact-xs"
                            variant="subtle"
                          >
                            {visibleCiphertexts.has(environment)
                              ? "Hide ciphertext"
                              : "Show ciphertext"}
                          </Button>
                        </Group>
                        {value && visibleCiphertexts.has(environment) ? (
                          <Code block mt="xs">
                            {value.encryptedValue}
                          </Code>
                        ) : null}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </ScrollArea>
          {activePanel.type !== "none" ? (
            <>
              <Divider />
              <Stack>
                <Title order={4}>{getPanelTitle(activePanel)}</Title>
                <Text c="dimmed" size="sm">
                  {secretName}.{activePanel.environment}
                </Text>
                {activePanel.type === "set-value" ? (
                  <>
                    <SearchableKeySelect
                      file={file}
                      onChange={setFingerprint}
                      required
                      value={fingerprint}
                    />
                    <Switch
                      checked={showPlaintext}
                      label="Show plaintext while editing"
                      onChange={(event) => setShowPlaintext(event.currentTarget.checked)}
                    />
                    {showPlaintext ? (
                      <Textarea
                        label="Plaintext value"
                        onChange={(event) => setPlaintextValue(event.currentTarget.value)}
                        value={plaintextValue}
                      />
                    ) : (
                      <PasswordInput
                        label="Plaintext value"
                        onChange={(event) => setPlaintextValue(event.currentTarget.value)}
                        value={plaintextValue}
                      />
                    )}
                    {setValue.error ? <Alert color="red">{setValue.error.message}</Alert> : null}
                    <Group justify="flex-end">
                      <Button onClick={closePanel} variant="default">
                        Cancel
                      </Button>
                      <Button
                        disabled={
                          !secretName || !activePanel.environment || !fingerprint || !plaintextValue
                        }
                        loading={setValue.isPending}
                        onClick={() =>
                          setValue.mutate({
                            environment: activePanel.environment ?? null,
                            fingerprint,
                            name: secretName,
                            plaintextValue,
                          })
                        }
                      >
                        Encrypt and save
                      </Button>
                    </Group>
                  </>
                ) : null}
                {activePanel.type === "peek" ? (
                  <>
                    <Alert color="yellow" variant="light">
                      Plaintext is only displayed after explicit decrypt.
                    </Alert>
                    {peek.error ? <Alert color="red">{peek.error.message}</Alert> : null}
                    {peek.data ? (
                      <>
                        <Textarea
                          autosize
                          label="Plaintext"
                          minRows={2}
                          readOnly
                          value={peek.data.payload}
                        />
                        <Text c="dimmed" size="xs">
                          {peek.data.info || "No OpenPGP details returned"}
                        </Text>
                      </>
                    ) : null}
                    <Group justify="flex-end">
                      <Button onClick={closePanel} variant="default">
                        Close panel
                      </Button>
                      {peek.data ? (
                        <CopyButton value={peek.data.payload}>
                          {({ copied, copy }) => (
                            <Button onClick={copy} variant="light">
                              {copied ? "Copied" : "Copy plaintext"}
                            </Button>
                          )}
                        </CopyButton>
                      ) : null}
                      <Button
                        disabled={!secretName}
                        loading={peek.isPending}
                        onClick={() =>
                          peek.mutate({
                            environment: activePanel.environment,
                            name: secretName ?? "",
                          })
                        }
                      >
                        Decrypt
                      </Button>
                    </Group>
                  </>
                ) : null}
                {activePanel.type === "share" ? (
                  <>
                    <Alert color="blue" variant="light">
                      Sharing decrypts the value and re-encrypts it to current owners plus the new
                      owner.
                    </Alert>
                    <SearchableKeySelect
                      exclude={secret?.values[activePanel.environment]?.owners ?? []}
                      file={file}
                      label="New recipient"
                      onChange={setFingerprint}
                      required
                      value={fingerprint}
                    />
                    {share.error ? <Alert color="red">{share.error.message}</Alert> : null}
                    <Group justify="flex-end">
                      <Button onClick={closePanel} variant="default">
                        Cancel
                      </Button>
                      <Button
                        disabled={!secretName || !fingerprint}
                        loading={share.isPending}
                        onClick={() =>
                          share.mutate({
                            environment: activePanel.environment,
                            fingerprint,
                            name: secretName,
                          })
                        }
                      >
                        Share
                      </Button>
                    </Group>
                  </>
                ) : null}
                {activePanel.type === "revoke" ? (
                  <>
                    <Alert color="yellow" variant="light">
                      Revoking re-encrypts without the selected owner. It is not retroactive.
                    </Alert>
                    <Select
                      data={(secret?.values[activePanel.environment]?.owners ?? []).map(
                        (owner) => ({
                          label: `${getKeyLabel(file, owner)} - ${owner}`,
                          value: owner,
                        }),
                      )}
                      label="Owner to revoke"
                      onChange={setFingerprint}
                      searchable
                      value={fingerprint}
                    />
                    {revoke.error ? <Alert color="red">{revoke.error.message}</Alert> : null}
                    <Group justify="flex-end">
                      <Button onClick={closePanel} variant="default">
                        Cancel
                      </Button>
                      <Button
                        color="red"
                        disabled={!secretName || !fingerprint}
                        loading={revoke.isPending}
                        onClick={() =>
                          revoke.mutate({
                            environment: activePanel.environment,
                            fingerprint,
                            name: secretName,
                          })
                        }
                      >
                        Revoke
                      </Button>
                    </Group>
                  </>
                ) : null}
                {activePanel.type === "remove-value" ? (
                  <>
                    <Alert color="red" variant="light">
                      This removes one encrypted value. If it is the final value, the backend may
                      delete the secret.
                    </Alert>
                    <Text fw={600}>
                      {secretName}.{activePanel.environment}
                    </Text>
                    <Textarea
                      label="Type the environment name to confirm"
                      onChange={(event) => setConfirmation(event.currentTarget.value)}
                      value={confirmation}
                    />
                    {removeValue.error ? (
                      <Alert color="red">{removeValue.error.message}</Alert>
                    ) : null}
                    <Group justify="flex-end">
                      <Button onClick={closePanel} variant="default">
                        Cancel
                      </Button>
                      <Button
                        color="red"
                        disabled={confirmation !== activePanel.environment || !secretName}
                        loading={removeValue.isPending}
                        onClick={() =>
                          removeValue.mutate({
                            environment: activePanel.environment,
                            name: secretName,
                          })
                        }
                      >
                        Remove value
                      </Button>
                    </Group>
                  </>
                ) : null}
              </Stack>
            </>
          ) : null}
        </Stack>
      ) : null}
    </Drawer>
  );
}

function getPanelTitle(panel: SecretDetailPanel) {
  switch (panel.type) {
    case "set-value":
      return "Set encrypted value";
    case "peek":
      return "Peek decrypted value";
    case "share":
      return "Share value";
    case "revoke":
      return "Revoke owner";
    case "remove-value":
      return "Remove value";
    case "none":
      return "";
  }
}
