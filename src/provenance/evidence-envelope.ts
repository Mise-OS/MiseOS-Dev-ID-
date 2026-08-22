export interface EvidenceSource {
  sourceId: string;
  uri?: string;
  retrievedAt: string;
  mediaType?: string;
}

export interface EvidenceEnvelope<T = unknown> {
  schemaVersion: '0.1.0';
  evidenceId: string;
  subject: string;
  source: EvidenceSource;
  payload: T;
  provenance: {
    artifactDigest?: string;
    eventDigest?: string;
    signature?: string;
  };
  authority: 'supporting';
}

/**
 * Evidence remains supporting evidence. This envelope intentionally carries
 * provenance metadata without making source availability, hashing, or a
 * signature equivalent to scientific or security validity.
 */
export function createEvidenceEnvelope<T>(input: {
  evidenceId: string;
  subject: string;
  source: EvidenceSource;
  payload: T;
  provenance?: EvidenceEnvelope<T>['provenance'];
}): EvidenceEnvelope<T> {
  return {
    schemaVersion: '0.1.0',
    evidenceId: input.evidenceId,
    subject: input.subject,
    source: input.source,
    payload: input.payload,
    provenance: input.provenance ?? {},
    authority: 'supporting',
  };
}
