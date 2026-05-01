import { test } from "node:test";
import assert from "node:assert";

import * as openpgp from "openpgp";

import { rawPKs } from "@msecrets/adapters/raw-pks";

import { MSecrets } from "./index.ts";

function createValidSecretsFile(input: {
  encryptedValue?: string;
  fingerprint?: string;
  mode?: string;
  owners?: string[];
}) {
  const mode = input.mode ?? "development";
  const fingerprint = input.fingerprint ?? "fingerprint-1";

  return {
    environments: [mode],
    version: "2.0.0",
    keys: [
      {
        fingerprint,
        publicKey:
          "-----BEGIN PGP PUBLIC KEY BLOCK-----\nvalid\n-----END PGP PUBLIC KEY BLOCK-----",
        userIds: ["Test User"],
      },
    ],
    secrets: {
      API_KEY: {
        values: {
          [mode]: {
            encryptedValue:
              input.encryptedValue ??
              "-----BEGIN PGP MESSAGE-----\nvalid\n-----END PGP MESSAGE-----",
            owners: input.owners ?? [fingerprint],
          },
        },
      },
    },
  };
}

test("init", () => {
  assert.equal(MSecrets, MSecrets);
});

test("can create client and get secrets", async () => {
  const mode = "development" as const;
  const testSecret = "test";
  const message = "Hello, World!";

  const userIDs: Parameters<typeof openpgp.generateKey>[0]["userIDs"] = [
    {
      name: "Test User",
    },
  ];

  const key = await openpgp.generateKey({
    type: "curve25519",
    userIDs,
  });

  const privateKey = await openpgp.readPrivateKey({
    armoredKey: key.privateKey,
  });

  const fingerprint = privateKey.getFingerprint();

  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: await openpgp.readKey({ armoredKey: key.publicKey }),
  });

  const client = new MSecrets({
    mode,
    adapters: [
      await rawPKs({
        keys: [key.privateKey],
      }),
    ],
    secrets: {
      environments: [mode],
      version: "2.0.0",
      keys: [
        {
          fingerprint,
          publicKey: key.publicKey,
          userIds: userIDs
            .map(({ name }) => name)
            .filter((name): name is string => typeof name === "string"),
        },
      ],
      secrets: {
        [testSecret]: {
          values: {
            [mode]: {
              encryptedValue: encrypted,
              owners: [fingerprint],
            },
          },
        },
      },
    },
  });

  assert.ok(client instanceof MSecrets);
  assert.deepEqual(await client.get(testSecret), message);
});

test("constructor rejects invalid secrets file shapes before runtime use", async () => {
  const adapter = await rawPKs({ keys: [] });

  assert.throws(
    () =>
      new MSecrets({
        mode: "development",
        adapters: [adapter],
        secrets: {
          version: "1",
          environments: ["development"],
          keys: [],
          secrets: {},
        },
      }),
    /Secrets file version must be valid semver/,
  );

  assert.throws(
    () =>
      new MSecrets({
        mode: "development",
        adapters: [adapter],
        secrets: {
          version: "2.0.0",
          environments: ["development"],
          keys: [],
          secrets: {
            API_KEY: {
              values: {
                development: {
                  encryptedValue: "ciphertext",
                  owners: [],
                },
              },
            },
          },
        },
      }),
    /Secret value has an empty owner list/,
  );

  assert.throws(
    () =>
      new MSecrets({
        mode: "development",
        adapters: [adapter],
        secrets: {
          version: "2.0.0",
          environments: ["development"],
          keys: [],
          secrets: {
            API_KEY: {
              values: {
                development: {
                  encryptedValue: "ciphertext",
                  owners: ["missing-owner"],
                },
              },
            },
          },
        },
      }),
    /Owner missing-owner is not present in \$\.keys/,
  );
});

test("constructor still reports empty adapters and missing modes clearly", () => {
  const secrets = createValidSecretsFile({});

  assert.throws(
    () =>
      new MSecrets({
        mode: "development",
        adapters: [],
        secrets,
      }),
    /At least one runtime adapter is required/,
  );

  assert.throws(
    () =>
      new MSecrets({
        mode: "production",
        adapters: [
          {
            name: "noop",
            decrypt() {
              return null;
            },
          },
        ],
        secrets,
      }),
    /Mode production not found in secrets file/,
  );
});

test("get reports aggregated adapter failures", async () => {
  const client = new MSecrets({
    mode: "development",
    adapters: [
      {
        name: "adapter-a",
        decrypt() {
          throw new Error("failed-a");
        },
      },
      {
        name: "adapter-b",
        decrypt() {
          throw new Error("failed-b");
        },
      },
    ],
    secrets: createValidSecretsFile({
      encryptedValue: "ciphertext",
    }),
  });

  await assert.rejects(
    () => client.get("API_KEY"),
    /Failed to decrypt secret API_KEY for mode development\.\n\[adapter-a\] failed-a\n\[adapter-b\] failed-b/,
  );
});
