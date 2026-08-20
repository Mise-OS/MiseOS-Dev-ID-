export interface CoordinatorCapability {
  readonly kind: 'coordinator';
  readonly mode: 'plan';
  plan(input: { objective: string }): Promise<unknown>;
}
