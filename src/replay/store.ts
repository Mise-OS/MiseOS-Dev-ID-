export type ClaimResult = "claimed" | "replayed" | "indeterminate";
export interface ReplayStore {
  claimNonce(nonce: string, expiresAt: string): Promise<ClaimResult>;
  hasNonce(nonce: string): Promise<boolean>;
}
