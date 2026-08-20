export interface PostMetadataCapability {
  readonly kind: 'post-metadata';
  readonly mode: 'compute';
  extract(input: { content: string }): Promise<unknown>;
}
