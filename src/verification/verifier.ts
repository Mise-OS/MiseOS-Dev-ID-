import { canonicalize } from "../canonical/jcs.js";
import { createHash, verify as cryptoVerify } from "node:crypto";
import type { SignedEnvelopeV1 } from "../crypto/envelope.js";
import { envelopeBytes } from "../crypto/envelope.js";
import type { TrustedKeyRegistry } from "../identity/registry.js";
import type { RevocationRegistry } from "../revocation/registry.js";
import type { ReplayStore } from "../replay/store.js";
import type { GithubIdentityPolicy, GithubOidcClaims } from "../github/oidc.js";
import { verifyOidcToken } from "../github/oidc.js";
import type { DelegationCredential } from "../delegation/verification.js";
import { verifyDelegationChain } from "../delegation/verification.js";
import { loadPublicKey } from "../crypto/keys.js";
import { evaluateResourceAuthorization, type AuthorizationSnapshot } from "../authorization/resources.js";

export type VerificationEffect = "allow" | "deny" | "indeterminate";
export interface VerificationFactor { name: string; status: "satisfied" | "failed" | "unknown"; reason?: string; }
export interface VerificationDecision { effect: VerificationEffect; factors: VerificationFactor[]; reason?: string; }
export interface VerificationContext {
  keyRegistry: TrustedKeyRegistry; revocationRegistry: RevocationRegistry; replayStore: ReplayStore;
  expectedAudience: string; maxDelegationDepth: number; maxClockSkewMs: number;
  oidcToken: string; oidcPolicy: GithubIdentityPolicy;
  trustedIdentityBinding: { githubSubject: string; repository: string; keyId: string };
}
const factor = (f: VerificationFactor[], name: string, status: VerificationFactor["status"], reason?: string) => f.push({ name, status, ...(reason ? { reason } : {}) });

export async function verify(envelope: SignedEnvelopeV1, manifest: unknown, delegationChain: DelegationCredential[] | null, authorization: AuthorizationSnapshot & { requestedOperation: "publish" | "sign" | "delegate" | "access"; resource: string; requestedAt: string }, context: VerificationContext): Promise<VerificationDecision> {
  const factors: VerificationFactor[] = []; const now = Date.now();
  try {
    const digest = createHash("sha256").update(canonicalize(manifest), "utf8").digest("hex");
    factor(factors, "manifest-integrity", digest === envelope.payloadDigest.value ? "satisfied" : "failed", digest === envelope.payloadDigest.value ? undefined : "Manifest hash mismatch");
  } catch (e) { factor(factors, "manifest-integrity", "failed", `Canonicalization error: ${String(e)}`); }

  const oidc = await verifyOidcToken(context.oidcToken, context.oidcPolicy);
  factor(factors, "oidc-cryptographic", oidc.valid ? "satisfied" : "failed", oidc.valid ? undefined : oidc.reason);
  const claims: GithubOidcClaims | undefined = oidc.claims;
  if (!claims) factor(factors, "oidc-identity", "unknown", "No verified OIDC claims available");
  else if (claims.sub !== context.trustedIdentityBinding.githubSubject || claims.repository !== context.trustedIdentityBinding.repository) factor(factors, "oidc-identity", "failed", "OIDC subject/repository binding mismatch");
  else factor(factors, "oidc-identity", "satisfied");

  const keyResolution = await context.keyRegistry.resolveKey(envelope.keyId);
  if (envelope.keyId !== context.trustedIdentityBinding.keyId) factor(factors, "key-binding", "failed", "Envelope keyId is not the exact authorized keyId");
  else if (keyResolution.status === "unknown") factor(factors, "key-registry", "unknown", "Authorized key could not be resolved");
  else if (keyResolution.status !== "valid" || !keyResolution.key) factor(factors, "key-registry", "failed", `Authorized key status is ${keyResolution.status}`);
  else if (keyResolution.key.owner !== context.trustedIdentityBinding.githubSubject) factor(factors, "key-binding", "failed", "Registered key owner does not exactly match GitHub subject");
  else factor(factors, "key-registry", "satisfied");

  if (keyResolution.status === "valid" && keyResolution.key && envelope.keyId === context.trustedIdentityBinding.keyId) {
    try {
      const issued = new Date(envelope.issuedAt).getTime(); const expires = envelope.expiresAt ? new Date(envelope.expiresAt).getTime() : NaN;
      if (!Number.isFinite(issued) || issued > now + context.maxClockSkewMs) factor(factors, "signature", "failed", "Invalid or future issuedAt");
      else if (!Number.isFinite(expires) || expires <= issued || expires < now - context.maxClockSkewMs) factor(factors, "signature", "failed", "Invalid or expired expiresAt");
      else if (envelope.audience !== context.expectedAudience) factor(factors, "signature", "failed", "Audience mismatch");
      else if (!cryptoVerify(null, envelopeBytes(envelope), loadPublicKey(keyResolution.key.publicKey), Buffer.from(envelope.signature, "base64"))) factor(factors, "signature", "failed", "Cryptographic signature invalid");
      else factor(factors, "signature", "satisfied");
    } catch (e) { factor(factors, "signature", "failed", `Signature verification error: ${String(e)}`); }
  } else factor(factors, "signature", "unknown", "Trusted signing key unavailable");

  // Explicitly bind the signed authorization reference to the authorization credential being evaluated.
  if (envelope.authorizationId !== authorization.credentialId) factor(factors, "authorization-binding", "failed", "Envelope authorizationId does not match authorization credentialId");
  if (claims && claims.sub !== authorization.subject) factor(factors, "authorization-subject", "failed", "Authorization subject does not match verified GitHub subject");
  else {
    const decision = evaluateResourceAuthorization(authorization, { subjectId: authorization.subject, operation: authorization.requestedOperation, resource: authorization.resource, audience: context.expectedAudience, requestedAt: authorization.requestedAt }, context.maxClockSkewMs);
    factor(factors, "authorization", decision.authorized ? "satisfied" : "failed", decision.authorized ? undefined : decision.reason);
  }
  if (authorization.revocationId) {
    const rev = await context.revocationRegistry.check(authorization.revocationId);
    if (rev.status === "revoked") factor(factors, "authorization-revocation", "failed", rev.reason ?? "Authorization revoked");
    else if (rev.status === "unknown") factor(factors, "authorization-revocation", "unknown", "Authorization revocation status unknown");
    else factor(factors, "authorization-revocation", "satisfied");
  } else factor(factors, "authorization-revocation", "failed", "Authorization revocationId is required");

  if (envelope.delegationId) {
    if (!delegationChain?.length) factor(factors, "delegation", "failed", "Envelope requires delegation chain but none was supplied");
    else {
      const d = await verifyDelegationChain(delegationChain, context.trustedIdentityBinding.githubSubject, authorization.subject, context.expectedAudience, context.maxDelegationDepth, context.keyRegistry, context.revocationRegistry, context.maxClockSkewMs);
      factor(factors, "delegation", d.valid ? "satisfied" : "failed", d.valid ? undefined : d.reason);
      if (d.valid && delegationChain.at(-1)?.credentialId !== envelope.delegationId) factor(factors, "delegation-binding", "failed", "Envelope delegationId does not match terminal credential");
      else if (d.valid) factor(factors, "delegation-binding", "satisfied");
    }
  } else if (delegationChain?.length) factor(factors, "delegation", "failed", "Unexpected delegation chain supplied without envelope binding");
  else factor(factors, "delegation", "satisfied");

  if (!envelope.nonce) factor(factors, "nonce-format", "failed", "Nonce is required");
  const preReplayFailed = factors.some(x => x.status === "failed"); const preReplayUnknown = factors.some(x => x.status === "unknown");
  if (preReplayFailed) factor(factors, "replay", "satisfied", "Replay claim intentionally not consumed after failed authorization");
  else if (preReplayUnknown) factor(factors, "replay", "unknown", "Replay claim skipped because verification is indeterminate");
  else if (!envelope.expiresAt) factor(factors, "replay", "failed", "Envelope expiration is required for nonce TTL");
  else {
    const claim = await context.replayStore.claimNonce(envelope.nonce, envelope.expiresAt);
    if (claim === "claimed") factor(factors, "replay", "satisfied");
    else if (claim === "replayed") factor(factors, "replay", "failed", "Nonce replay detected");
    else factor(factors, "replay", "unknown", "Replay store unavailable");
  }

  const hasFailed = factors.some(x => x.status === "failed"); const hasUnknown = factors.some(x => x.status === "unknown");
  if (hasFailed) return { effect: "deny", factors, reason: factors.find(x => x.status === "failed")?.reason };
  if (hasUnknown) return { effect: "indeterminate", factors, reason: factors.find(x => x.status === "unknown")?.reason };
  return { effect: "allow", factors };
}
export function authorityDecision(decision: VerificationDecision): "allow" | "deny" { return decision.effect === "allow" ? "allow" : "deny"; }
