import { describe, expect, it } from 'vitest';
import { evaluateCapabilityRequest } from '../../src/policy/capability-gateway.js';
import { createEvidenceEnvelope } from '../../src/provenance/evidence-envelope.js';

describe('capability gateway', () => {
  const base = {
    capability: 'github.listPullRequests',
    subject: 'repo:example',
    resource: 'Mise-OS/MiseOS-Dev-ID-',
    risk: 'read' as const,
    input: { repository: 'Mise-OS/MiseOS-Dev-ID-' },
    authorizationVerified: true,
    signatureVerified: true,
    revocationChecked: true,
    replayChecked: true,
  };

  it('allows a capability only after every mandatory trust check passes', () => {
    expect(evaluateCapabilityRequest(base).decision).toBe('ALLOW');
  });

  it('denies when authorization is bypassed', () => {
    expect(evaluateCapabilityRequest({ ...base, authorizationVerified: false })).toMatchObject({
      decision: 'DENY',
      reason: 'authorization_not_verified',
    });
  });

  it('denies when signing, revocation, or replay controls are missing', () => {
    for (const field of ['signatureVerified', 'revocationChecked', 'replayChecked'] as const) {
      expect(evaluateCapabilityRequest({ ...base, [field]: false }).decision).toBe('DENY');
    }
  });

  it('requires deployment control for security-critical capabilities', () => {
    expect(evaluateCapabilityRequest({
      ...base,
      capability: 'deployment.publish',
      risk: 'security-critical',
    })).toMatchObject({ decision: 'DENY', reason: 'deployment_control_not_satisfied' });

    expect(evaluateCapabilityRequest({
      ...base,
      capability: 'deployment.publish',
      risk: 'security-critical',
      deploymentControlSatisfied: true,
    }).decision).toBe('ALLOW');
  });
});

describe('evidence envelope', () => {
  it('marks external evidence as supporting rather than authoritative', () => {
    const envelope = createEvidenceEnvelope({
      evidenceId: 'e-1',
      subject: 'claim-1',
      source: { sourceId: 'github', retrievedAt: '2026-08-20T00:00:00.000Z' },
      payload: { result: true },
    });

    expect(envelope.authority).toBe('supporting');
    expect(envelope.provenance).toEqual({});
  });
});
