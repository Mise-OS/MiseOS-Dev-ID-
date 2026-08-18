import { canonicalize } from "../canonical/jcs.js";
export interface SignedEnvelopeV1 {
  schema: "miseos.signed-envelope/v1";
  algorithm: "Ed25519";
  keyId: string;
  payloadDigest: { algorithm: "sha256"; value: string };
  issuedAt: string;
  expiresAt?: string;
  nonce: string;
  audience: string;
  actionId: string;
  authorizationId: string;
  delegationId?: string;
  signature: string;
}
export function envelopeBytes(envelope: SignedEnvelopeV1): Buffer {
  const { signature: _signature, ...unsigned } = envelope;
  return Buffer.from(canonicalize(unsigned), "utf8");
}
