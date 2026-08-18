export type RevocationStatus = "valid" | "revoked" | "unknown";
export interface RevocationCheck { status: RevocationStatus; reason?: string; checkedAt: string; }
export interface RevocationRegistry { check(revocationId: string): Promise<RevocationCheck>; }
