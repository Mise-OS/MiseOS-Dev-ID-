export interface ParallelSearchCapability {
  readonly kind: 'parallel-search';
  readonly mode: 'read';
  search(input: { queries: string[] }): Promise<unknown>;
}
