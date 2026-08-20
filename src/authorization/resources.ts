export interface ResourcePattern { type: "exact" | "prefix" | "glob"; pattern: string; }
export interface AuthorizationSnapshot {
  schema: "miseos.authorization/v1";
  credentialId: string;
  subject: string;
  audience: string;
  scope: string[];
  resources: ResourcePattern[];
  issuedAt: string;
  expiresAt: string;
  state: "SAFE" | "QUIESCING" | "ISOLATED" | "FORENSIC" | "REVOKED" | "DENY_NEW";
  revocationId?: string;
}
export interface AuthorizationRequest { subjectId: string; operation: "publish" | "sign" | "delegate" | "access"; resource: string; audience: string; requestedAt: string; }

function validPattern(pattern: ResourcePattern): boolean {
  return !!pattern && ["exact", "prefix", "glob"].includes(pattern.type) && typeof pattern.pattern === "string" && pattern.pattern.length > 0 && pattern.pattern.length <= 2048;
}

export function matchResource(resource: string, pattern: ResourcePattern): boolean {
  if (!validPattern(pattern) || typeof resource !== "string" || resource.length === 0) return false;
  if (pattern.type === "exact") return resource === pattern.pattern;
  if (pattern.type === "prefix") return resource.startsWith(pattern.pattern);
  const escaped = pattern.pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "u").test(resource);
}

export function isResourceAuthorized(resource: string, patterns: ResourcePattern[]): boolean {
  return Array.isArray(patterns) && patterns.every(validPattern) && patterns.some(p => matchResource(resource, p));
}

export function evaluateResourceAuthorization(snapshot: AuthorizationSnapshot, request: AuthorizationRequest, maxClockSkewMs: number) {
  if (snapshot.schema !== "miseos.authorization/v1") return { authorized: false, reason: "Invalid authorization schema" };
  if (snapshot.subject !== request.subjectId) return { authorized: false, reason: "Subject mismatch" };
  if (snapshot.audience !== request.audience) return { authorized: false, reason: "Audience mismatch" };
  if (snapshot.state !== "SAFE") return { authorized: false, reason: `Credential state is ${snapshot.state}` };
  const now = new Date(request.requestedAt).getTime();
  const issued = new Date(snapshot.issuedAt).getTime(); const expires = new Date(snapshot.expiresAt).getTime();
  if (!Number.isFinite(now) || !Number.isFinite(issued) || !Number.isFinite(expires)) return { authorized: false, reason: "Invalid authorization timestamps" };
  if (issued > now + maxClockSkewMs) return { authorized: false, reason: "Credential issued too far in the future" };
  if (expires <= issued || expires < now - maxClockSkewMs) return { authorized: false, reason: "Credential expired or has invalid lifetime" };
  if (!Array.isArray(snapshot.scope) || !snapshot.scope.includes(request.operation)) return { authorized: false, reason: `Operation ${request.operation} not in scope` };
  if (!isResourceAuthorized(request.resource, snapshot.resources)) return { authorized: false, reason: `Resource ${request.resource} not authorized` };
  return { authorized: true as const };
}
