export interface GitHubCapability {
  readonly kind: 'github';
  readonly mode: 'read' | 'review';
  listPullRequests(input: { repository: string }): Promise<unknown>;
}
