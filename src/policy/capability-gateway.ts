import { createHash } from 'node:crypto';

export type CapabilityRisk = 'read' | 'compute' | 'review' | 'write' | 'security-critical';
export type CapabilityDecision = 'ALLOW' | 'DENY' | 'INDETERMINATE';

export interface CapabilityRequest {
  capability: string;
  subject: string;
  resource?: string;
  risk: CapabilityRisk;
  input: unknown;
  authorizationVerified: boolean;
  signatureVerified: boolean;
  revocationChecked: boolean;
  replayChecked: boolean;
  deploymentControlSatisfied?: boolean;
}

export interface CapabilityResult<T = unknown> {
  decision: CapabilityDecision;
  capability: string;
  requestDigest: string;
  reason: string;
  output?: T;
}

/**
 * Host-side capability boundary. This is deliberately independent of any
 * model, coordinator, Code Mode runtime, or external integration.
 *
 * A capability cannot become authoritative merely because generated code can
 * call it. Security-critical mutations require every applicable control to
 * have been established before execution.
 */
export function evaluateCapabilityRequest(
  request: CapabilityRequest,
): CapabilityResult {
  const requestDigest = createHash('sha256')
    .update(JSON.stringify(request))
    .digest('hex');

  if (!request.authorizationVerified) {
    return denied(request, requestDigest, 'authorization_not_verified');
  }
  if (!request.signatureVerified) {
    return denied(request, requestDigest, 'signature_not_verified');
  }
  if (!request.revocationChecked) {
    return denied(request, requestDigest, 'revocation_not_checked');
  }
  if (!request.replayChecked) {
    return denied(request, requestDigest, 'replay_not_checked');
  }

  if (request.risk === 'security-critical' && !request.deploymentControlSatisfied) {
    return denied(request, requestDigest, 'deployment_control_not_satisfied');
  }

  return {
    decision: 'ALLOW',
    capability: request.capability,
    requestDigest,
    reason: 'all_required_capability_controls_satisfied',
  };
}

function denied(
  request: CapabilityRequest,
  requestDigest: string,
  reason: string,
): CapabilityResult {
  return {
    decision: 'DENY',
    capability: request.capability,
    requestDigest,
    reason,
  };
}
