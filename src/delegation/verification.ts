import { canonicalize } from "../canonical/jcs.js";
import type { TrustedKeyRegistry } from "../identity/registry.js";
import type { RevocationRegistry } from "../revocation/registry.js";
import { loadPublicKey } from "../crypto/keys.js";
import { verify as cryptoVerify } from "node:crypto";

export interface DelegationCredential {
  schema: "miseos.delegation/v1"; credentialId: string; parentIdentity: string; delegateIdentity: string;
  issuerKeyId: string; issuedAt: string; expiresAt: string; audience: string; scope: string[]; resources: string[];
  depth: number; maxDepth: number; revocationId: string; parentCredentialId?: string; signature: string;
}
export interface DelegationVerificationResult { valid: boolean; reason?: string; chainDepth: number; }

export async function verifyDelegationChain(chain: DelegationCredential[], rootIdentity: string, targetAgent: string, expectedAudience: string, maxDepth: number, keyRegistry: TrustedKeyRegistry, revocationRegistry: RevocationRegistry, maxClockSkewMs: number): Promise<DelegationVerificationResult> {
  if (!chain.length) return { valid: false, reason: "Empty delegation chain", chainDepth: 0 };
  if (chain.length > maxDepth) return { valid: false, reason: "Delegation depth exceeds policy", chainDepth: chain.length };
  if (chain[0]?.parentIdentity !== rootIdentity) return { valid: false, reason: "Chain root mismatch", chainDepth: 0 };
  if (chain.at(-1)?.delegateIdentity !== targetAgent) return { valid: false, reason: "Chain target mismatch", chainDepth: chain.length };
  const now = Date.now();
  for (let i = 0; i < chain.length; i++) {
    const edge = chain[i]!;
    if (i > 0) {
      const parent = chain[i - 1]!;
      if (edge.parentIdentity !== parent.delegateIdentity) return { valid: false, reason: `Edge ${i} parent identity mismatch`, chainDepth: i + 1 };
      if (edge.parentCredentialId !== parent.credentialId) return { valid: false, reason: `Edge ${i} parent credential mismatch`, chainDepth: i + 1 };
      if (edge.scope.some(s => !parent.scope.includes(s))) return { valid: false, reason: `Edge ${i} scope escalation`, chainDepth: i + 1 };
      if (edge.resources.some(r => !parent.resources.includes(r))) return { valid: false, reason: `Edge ${i} resource escalation`, chainDepth: i + 1 };
      if (new Date(edge.expiresAt).getTime() > new Date(parent.expiresAt).getTime()) return { valid: false, reason: `Edge ${i} expiration escalation`, chainDepth: i + 1 };
    }
    if (edge.depth > edge.maxDepth || edge.depth !== i + 1) return { valid: false, reason: `Edge ${i} invalid depth`, chainDepth: i + 1 };
    if (edge.audience !== expectedAudience) return { valid: false, reason: `Edge ${i} audience mismatch`, chainDepth: i + 1 };
    const issued = new Date(edge.issuedAt).getTime(); const expires = new Date(edge.expiresAt).getTime();
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + maxClockSkewMs || expires < now - maxClockSkewMs) return { valid: false, reason: `Edge ${i} temporal violation`, chainDepth: i + 1 };
    const rev = await revocationRegistry.check(edge.revocationId);
    if (rev.status !== "valid") return { valid: false, reason: `Edge ${i} revocation status ${rev.status}`, chainDepth: i + 1 };
    const key = await keyRegistry.resolveKey(edge.issuerKeyId);
    if (key.status !== "valid" || !key.key) return { valid: false, reason: `Edge ${i} issuer key ${edge.issuerKeyId} is ${key.status}`, chainDepth: i + 1 };
    const { signature, ...unsigned } = edge;
    try {
      const valid = cryptoVerify(null, Buffer.from(canonicalize(unsigned), "utf8"), loadPublicKey(key.key.publicKey), Buffer.from(signature, "base64"));
      if (!valid) return { valid: false, reason: `Edge ${i} signature invalid`, chainDepth: i + 1 };
    } catch { return { valid: false, reason: `Edge ${i} signature verification error`, chainDepth: i + 1 }; }
  }
  return { valid: true, chainDepth: chain.length };
}
