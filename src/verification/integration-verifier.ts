import type { SignedEnvelopeV1 } from '../crypto/envelope.js';
import type { DelegationCredential } from '../delegation/verification.js';
import type { AuthorizationSnapshot } from '../authorization/resources.js';
import { verify, type VerificationContext, type VerificationDecision } from './verifier.js';
import {
  evaluateCapabilityRequest,
  type CapabilityRequest,
} from '../policy/capability-gateway.js';

/**
 * Integration-facing verifier composition.
 *
 * The existing cryptographic verifier remains authoritative for identity,
 * authorization, revocation, delegation, and replay. This wrapper adds the
 * host-side capability boundary after those checks. External adapters,
 * coordinators, and generated Code Mode cannot invoke an integration unless
 * this composition returns ALLOW.
 */
export async function verifyIntegrationCapability(
  envelope: SignedEnvelopeV1,
  manifest: unknown,
  delegationChain: DelegationCredential[] | null,
  authorization: AuthorizationSnapshot & {
    requestedOperation: 'publish' | 'sign' | 'delegate' | 'access';
    resource: string;
    requestedAt: string;
  },
  context: VerificationContext,
  capability: Omit<CapabilityRequest, 'authorizationVerified' | 'signatureVerified' | 'revocationChecked' | 'replayChecked'>,
): Promise<VerificationDecision> {
  const decision = await verify(envelope, manifest, delegationChain, authorization, context);

  const factor = decision.factors;
  const failed = (name: string) => factor.some(item => item.name === name && item.status === 'failed');
  const unknown = (name: string) => factor.some(item => item.name === name && item.status === 'unknown');
  const passed = (name: string) => !failed(name) && !unknown(name);

  const gateway = evaluateCapabilityRequest({
    ...capability,
    authorizationVerified: passed('authorization') && passed('authorization-binding') && passed('authorization-subject'),
    signatureVerified: passed('signature'),
    revocationChecked: passed('authorization-revocation'),
    replayChecked: passed('replay'),
  });

  if (gateway.decision !== 'ALLOW') {
    return {
      effect: 'deny',
      factors: [
        ...decision.factors,
        { name: 'capability-gateway', status: 'failed', reason: gateway.reason },
      ],
      reason: gateway.reason,
    };
  }

  return {
    ...decision,
    factors: [
      ...decision.factors,
      { name: 'capability-gateway', status: 'satisfied' },
    ],
  };
}
