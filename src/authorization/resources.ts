export interface ResourcePattern { type: "exact" | "prefix" | "glob"; pattern: string; }
export interface AuthorizationSnapshot {
  schema: "miseos.authorization/v1";
  credentialId: string;
  subject: string;
  scope: string[];
  resources: ResourcePattern[];
  issuedAt: string;
  expiresAt: string;
  state: "SAFE" | "QUIESCING" | "ISOLATED" | "FORENSIC" | "REVOKED" | "DENY_NEW";
  revocationId?: string;
}
export interface AuthorizationRequest { subjectId: string; operation: "publish" | "sign" | "delegate" | "access"; resource: string; audience: string; requestedAt: string; }
export function matchResource(resource: string, pattern: ResourcePattern): boolean {
  if (pattern.type === "exact") return resource === pattern.pattern;
  if (pattern.type === "prefix") return resource.startsWith(pattern.pattern);
  const escaped = pattern.pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`).test(resource);
}
export function isResourceAuthorized(resource: string, patterns: ResourcePattern[]): boolean { return patterns.some(p => matchResource(resource, p)); }
export function evaluateResourceAuthorization(snapshot: AuthorizationSnapshot, request: AuthorizationRequest, maxClockSkewMs: number) {
  const now = new Date(request.requestedAt).getTime();
  if (snapshot.subject !== request.subjectId) return { authorized: false, reason: "Subject mismatch" };
  if (snapshot.state !== "SAFE") return { authorized: false, reason: `Credential state is ${snapshot.state}` };
  const issued = new Date(snapshot.issuedAt).getTime(); const expires = new Date(snapshot.expiresAt).getTime();
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) return { authorized: false, reason: "Invalid authorization timestamps" };
  if (issued > now + maxClockSkewMs) return { authorized: false, reason: "Credential not yet valid" };
  if (expires < now - maxClockSkewMs) return { authorized: false, reason: "Credential expired" };
  if (!snapshot.scope.includes(request.operation)) return { authorized: false, reason: `Operation ${request.operation} not in scope` };
  if (!isResourceAuthorized(request.resource, snapshot.resources)) return { authorized: false, reason: `Resource ${request.resource} not authorized` };
  return { authorized: true as const };
}
