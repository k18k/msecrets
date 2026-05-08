import { useEffect, useMemo, useState } from "react";
import { Alert, Button, Group, Modal, PasswordInput, Stack, Text } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";

import type { WorkspacePageData } from "../../../server/lib/types.ts";
import { queryKeys } from "../../hooks/queryKeys";
import { useOrpcMutation } from "../../hooks/useOrpcMutation";
import { orpcClient } from "../../orpc-client";

function shortFingerprint(fingerprint: string) {
  return `${fingerprint.slice(0, 4)}...${fingerprint.slice(-4)}`;
}

function getPromptStorageKey(fingerprints: string[]) {
  return `msecrets:gpg-runtime-import:${fingerprints.sort().join(",")}`;
}

export function SessionGpgKeyImportPrompt({ data }: { data: WorkspacePageData }) {
  const file = data.snapshot.file;
  const [opened, setOpened] = useState(false);
  const [dismissedKey, setDismissedKey] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const gpgKeys = useQuery({
    enabled: Boolean(file),
    queryFn: () => orpcClient.runtimeKeys.listGpgKeys(),
    queryKey: queryKeys.gpgKeys,
  });
  const importKeys = useOrpcMutation<
    { fingerprints: string[]; passphrase?: string },
    { imported: string[] }
  >({
    invalidateRuntimeKeys: true,
    mutationFn: async ({ fingerprints, passphrase: nextPassphrase }) => {
      const imported: string[] = [];

      for (const fingerprint of fingerprints) {
        const result = await orpcClient.runtimeKeys.importPrivate({
          gpgFingerprint: fingerprint,
          passphrase: nextPassphrase,
        });
        imported.push(result.fingerprint);
      }

      return { imported };
    },
    onSuccess: () => {
      setOpened(false);
      setPassphrase("");
    },
  });
  const matches = useMemo(() => {
    const configured = new Set(file?.keys.map((key) => key.fingerprint) ?? []);
    const runtime = new Set(data.keyManagement.runtimePrivateKeys.map((key) => key.fingerprint));

    return (gpgKeys.data ?? []).filter(
      (key) => configured.has(key.fingerprint) && !runtime.has(key.fingerprint),
    );
  }, [data.keyManagement.runtimePrivateKeys, file?.keys, gpgKeys.data]);
  const promptKey = matches.length
    ? getPromptStorageKey(matches.map((key) => key.fingerprint))
    : null;

  useEffect(() => {
    if (!promptKey || gpgKeys.isLoading || dismissedKey === promptKey) {
      setOpened(false);
      return;
    }

    if (window.sessionStorage.getItem(promptKey) === "dismissed") {
      setDismissedKey(promptKey);
      setOpened(false);
      return;
    }

    setOpened(true);
  }, [dismissedKey, gpgKeys.isLoading, promptKey]);

  function dismiss() {
    if (promptKey) {
      window.sessionStorage.setItem(promptKey, "dismissed");
      setDismissedKey(promptKey);
    }
    setOpened(false);
  }

  if (!matches.length) {
    return null;
  }

  return (
    <Modal onClose={dismiss} opened={opened} title="Import matching private keys">
      <Stack>
        <Alert color="blue" variant="light">
          Local GPG private keys match recipients in this secrets file. Importing them loads OpenPGP
          private key material into this UI server session only.
        </Alert>
        <Stack gap={4}>
          {matches.map((key) => (
            <Text key={key.fingerprint} size="sm">
              {key.userIds[0] ?? "Local key"} - {shortFingerprint(key.fingerprint)}
            </Text>
          ))}
        </Stack>
        <PasswordInput
          label="Private key passphrase"
          onChange={(event) => setPassphrase(event.currentTarget.value)}
          placeholder="Required only for protected private keys"
          value={passphrase}
        />
        {importKeys.error ? <Alert color="red">{importKeys.error.message}</Alert> : null}
        <Group justify="flex-end">
          <Button onClick={dismiss} variant="default">
            Not now
          </Button>
          <Button
            loading={importKeys.isPending}
            onClick={() =>
              importKeys.mutate({
                fingerprints: matches.map((key) => key.fingerprint),
                passphrase: passphrase || undefined,
              })
            }
          >
            Import for this session
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
