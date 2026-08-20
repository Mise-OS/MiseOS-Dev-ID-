export interface HuggingFaceCapability {
  readonly kind: 'hugging-face';
  readonly mode: 'read';
  inspect(input: { query: string }): Promise<unknown>;
}
