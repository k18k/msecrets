export type KeyIdentity = {
  fingerprint: string;
  userIds: string[];
};

export type MSecretsPublicKey = KeyIdentity & {
  publicKey: string;
};

export type MSecretsPrivateKey = KeyIdentity & {
  privateKey: string;
};

export type KeyProvider = {
  name: string;
  isAvailable(): boolean;
  listKeys(): Promise<KeyIdentity[]>;
  getPublicKey(fingerprint: string): Promise<MSecretsPublicKey>;
  getPrivateKey(fingerprint: string): Promise<MSecretsPrivateKey>;
};
