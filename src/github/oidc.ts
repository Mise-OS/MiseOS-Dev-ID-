import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface GithubOidcClaims extends JWTPayload {
  repository: string;
  repository_owner: string;
  repository_id: string;
  actor: string;
  actor_id: string;
  workflow: string;
  workflow_ref: string;
  workflow_sha: string;
  run_id: string;
  run_number: string;
  ref: string;
  ref_type: string;
  environment?: string;
}

export interface GithubIdentityPolicy {
  allowedIssuers: string[];
  allowedAudiences: string[];
  allowedRepositories?: string[];
  allowedRepositoryOwners?: string[];
  allowedRepositoryIds?: string[];
  allowedWorkflows?: string[];
  allowedWorkflowRefs?: string[];
  allowedWorkflowShas?: string[];
  allowedRefs?: string[];
  allowedRefTypes?: string[];
  requireEnvironment?: string;
  maxClockSkewSeconds: number;
  jwksUrl: URL;
}

export interface OidcVerificationResult {
  valid: boolean;
  claims?: GithubOidcClaims;
  reason?: string;
}

const githubJwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(url: URL) {
  const key = url.toString();
  let jwks = githubJwks.get(key);
  if (!jwks) {
    jwks = createRemoteJWKSet(url);
    githubJwks.set(key, jwks);
  }
  return jwks;
}

export async function verifyOidcToken(
  token: string,
  policy: GithubIdentityPolicy,
  trustedClock: () => number = () => Math.floor(Date.now() / 1000),
): Promise<OidcVerificationResult> {
  try {
    if (!token || token.split(".").length !== 3) {
      return { valid: false, reason: "Invalid JWT format" };
    }

    const issuer = policy.allowedIssuers.length === 1 ? policy.allowedIssuers[0] : undefined;
    const audience = policy.allowedAudiences.length === 1 ? policy.allowedAudiences[0] : policy.allowedAudiences;
    if (!issuer || !audience) {
      return { valid: false, reason: "OIDC policy must define issuer and audience" };
    }

    const now = trustedClock();
    const { payload } = await jwtVerify(token, getJwks(policy.jwksUrl), {
      issuer,
      audience,
      algorithms: ["RS256"],
      clockTolerance: policy.maxClockSkewSeconds,
      currentDate: new Date(now * 1000),
    });

    const claims = payload as GithubOidcClaims;
    if (!claims.sub || !claims.repository || !claims.repository_owner || !claims.workflow_ref) {
      return { valid: false, reason: "Required GitHub claims missing" };
    }
    if (typeof claims.iat !== "number" || typeof claims.exp !== "number") {
      return { valid: false, reason: "OIDC iat and exp are required" };
    }

    // GitHub OIDC is an authority input, so temporal validity is strict here.
    // clockTolerance is retained for library-level validation of network-issued JWTs,
    // but a token that is already expired or not yet issued must never reach ALLOW.
    if (claims.iat > now) {
      return { valid: false, reason: "OIDC token issued in the future" };
    }
    if (claims.exp <= now) {
      return { valid: false, reason: "OIDC token is expired" };
    }
    if (claims.exp <= claims.iat) {
      return { valid: false, reason: "OIDC expiration is not after issuance" };
    }

    if (policy.allowedRepositories && !policy.allowedRepositories.includes(claims.repository)) {
      return { valid: false, reason: "Repository not authorized" };
    }
    if (policy.allowedRepositoryOwners && !policy.allowedRepositoryOwners.includes(claims.repository_owner)) {
      return { valid: false, reason: "Repository owner not authorized" };
    }
    if (policy.allowedRepositoryIds && !policy.allowedRepositoryIds.includes(claims.repository_id)) {
      return { valid: false, reason: "Repository ID not authorized" };
    }
    if (policy.allowedWorkflows) {
      const workflowName = claims.workflow_ref.split("/").pop()?.split("@")[0];
      if (!workflowName || !policy.allowedWorkflows.includes(workflowName)) {
        return { valid: false, reason: "Workflow not authorized" };
      }
    }
    if (policy.allowedWorkflowRefs && !policy.allowedWorkflowRefs.includes(claims.workflow_ref)) {
      return { valid: false, reason: "Workflow ref not authorized" };
    }
    if (policy.allowedWorkflowShas && !policy.allowedWorkflowShas.includes(claims.workflow_sha)) {
      return { valid: false, reason: "Workflow SHA not authorized" };
    }
    if (policy.allowedRefs && !policy.allowedRefs.includes(claims.ref)) {
      return { valid: false, reason: "Git ref not authorized" };
    }
    if (policy.allowedRefTypes && !policy.allowedRefTypes.includes(claims.ref_type)) {
      return { valid: false, reason: "Git ref type not authorized" };
    }
    if (policy.requireEnvironment && claims.environment !== policy.requireEnvironment) {
      return { valid: false, reason: "Required environment not present" };
    }

    return { valid: true, claims };
  } catch (error) {
    return { valid: false, reason: `OIDC verification failed: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export function createDefaultPolicy(
  jwksUrl = new URL("https://token.actions.githubusercontent.com/.well-known/jwks"),
): GithubIdentityPolicy {
  return {
    allowedIssuers: ["https://token.actions.githubusercontent.com"],
    allowedAudiences: ["https://miseos.dev"],
    maxClockSkewSeconds: 300,
    jwksUrl,
  };
}
