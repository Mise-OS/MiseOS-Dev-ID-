export interface AmplitudeCapability {
  readonly kind: 'amplitude';
  readonly mode: 'read';
  query(input: { metric: string; range?: string }): Promise<unknown>;
}
