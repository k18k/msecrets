export type KeyIdentity = {
  fingerprint: string;
  userIds: string[];
};

export type PublicKey = KeyIdentity & {
  publicKey: string;
};

export type PrivateKey = KeyIdentity & {
  privateKey: string;
};

export type KeyProvider = {
  name: string;
  isAvailable(): boolean;
  listKeys(): Promise<KeyIdentity[]>;
  getPublicKey(fingerprint: string): Promise<PublicKey>;
  getPrivateKey(fingerprint: string): Promise<PrivateKey>;
};
