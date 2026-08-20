export interface CodeRabbitCapability {
  readonly kind: 'coderabbit';
  readonly mode: 'review';
  review(input: { repository: string; ref: string }): Promise<unknown>;
}
