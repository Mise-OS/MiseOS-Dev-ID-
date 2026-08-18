export type RegistryStatus = "valid" | "revoked" | "suspended" | "unknown";
export interface TrustedKeyRecord {
  keyId: string;
  publicKey: string;
  algorithm: "Ed25519";
  owner: string;
  issuedAt: string;
  expiresAt?: string;
  revokedAt?: string;
}
export interface KeyResolution { status: RegistryStatus; key?: TrustedKeyRecord; }
export interface TrustedKeyRegistry { resolveKey(keyId: string): Promise<KeyResolution>; }
