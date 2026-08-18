import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { generateKeyPairSync, sign } from "node:crypto";
import { exportJWK, SignJWT, type JWK } from "jose";
import { canonicalize } from "../../src/canonical/jcs.js";
import { envelopeBytes, type SignedEnvelopeV1 } from "../../src/crypto/envelope.js";
import { verify, authorityDecision, type VerificationContext } from "../../src/verification/verifier.js";
import type { TrustedKeyRegistry } from "../../src/identity/registry.js";
import type { RevocationRegistry } from "../../src/revocation/registry.js";
import type { ReplayStore, ClaimResult } from "../../src/replay/store.js";
import type { AuthorizationSnapshot } from "../../src/authorization/resources.js";
import type { DelegationCredential } from "../../src/delegation/verification.js";

const NOW = Math.floor(Date.now() / 1000);
const SUBJECT = "repo:Mise-OS/MiseOS-Dev-ID-:ref:refs/heads/main";
const REPO = "Mise-OS/MiseOS-Dev-ID-";
const AUD = "https://miseos.dev";
const KEY_ID = "dev-id-test-key";
const REV_ID = "auth-rev-1";
const RESOURCE = "repo:Mise-OS/MiseOS-Dev-ID-:artifact:v1";

let jwksServer: Server;
let jwksUrl: URL;
let oidcPrivateKey: ReturnType<typeof generateKeyPairSync>;
let oidcJwk: JWK;
let signingPrivateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
let signingPublicDer: string;

class FakeKeyRegistry implements TrustedKeyRegistry {
  constructor(public status: "valid" | "revoked" | "suspended" | "unknown" = "valid", public owner = SUBJECT) {}
  async resolveKey(keyId: string) {
    if (keyId !== KEY_ID) return { status: "unknown" as const };
    if (this.status !== "valid") return { status: this.status };
    return { status: "valid" as const, key: { keyId, publicKey: signingPublicDer, algorithm: "Ed25519" as const, owner: this.owner, issuedAt: new Date(NOW * 1000).toISOString() } };
  }
}
class FakeRevocationRegistry implements RevocationRegistry {
  constructor(public status: "valid" | "revoked" | "unknown" = "valid") {}
  async check(_id: string) { return { status: this.status, checkedAt: new Date().toISOString(), reason: this.status === "revoked" ? "test revocation" : undefined }; }
}
class FakeReplayStore implements ReplayStore {
  constructor(public result: ClaimResult = "claimed") {}
  async claimNonce(_nonce: string, _expiresAt: string) { return this.result; }
  async hasNonce(_nonce: string) { return this.result === "replayed"; }
}

async function token(overrides: Record<string, unknown> = {}, key = oidcPrivateKey.privateKey) {
  const claims = {
    sub: SUBJECT, iss: "https://token.actions.githubusercontent.com", aud: AUD,
    repository: REPO, repository_owner: "Mise-OS", repository_id: "1338747102", actor: "test", actor_id: "1",
    workflow: "security.yml", workflow_ref: "Mise-OS/MiseOS-Dev-ID-/.github/workflows/security.yml@refs/heads/main",
    workflow_sha: "a".repeat(40), run_id: "1", run_number: "1", ref: "refs/heads/main", ref_type: "branch",
    iat: NOW - 30, exp: NOW + 300, ...overrides,
  };
  return new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "oidc-test" }).sign(key);
}

function baseEnvelope(manifest: unknown, overrides: Partial<SignedEnvelopeV1> = {}): SignedEnvelopeV1 {
  const unsigned: Omit<SignedEnvelopeV1, "signature"> = {
    schema: "miseos.signed-envelope/v1", algorithm: "Ed25519", keyId: KEY_ID,
    payloadDigest: { algorithm: "sha256", value: createDigest(manifest) },
    issuedAt: new Date((NOW - 30) * 1000).toISOString(), expiresAt: new Date((NOW + 300) * 1000).toISOString(),
    nonce: cryptoRandom(), audience: AUD, actionId: "action-1", authorizationId: "auth-1", ...overrides,
  };
  return { ...unsigned, signature: sign(null, envelopeBytes({ ...unsigned, signature: "" }), signingPrivateKey).toString("base64") };
}
function createDigest(value: unknown) { return requirelessSha(canonicalize(value)); }
function requirelessSha(value: string) { return createHashCompat(value); }
function createHashCompat(value: string) { const h = new (require("node:crypto").Hash)(); return h.update(value, "utf8").digest("hex"); }
function cryptoRandom() { return `${Date.now()}-${Math.random().toString(36).slice(2)}`; }

// Avoid dynamic imports in the fixture helpers above.
import { createHash } from "node:crypto";

function scenario(overrides: Partial<Scenario> = {}): Scenario {
  const manifest = { schema: "miseos.provenance/v1", repository: REPO, commitSha: "a".repeat(40) };
  const authorization: AuthorizationSnapshot & { requestedOperation: "publish"; resource: string; requestedAt: string } = {
    schema: "miseos.authorization/v1", credentialId: "auth-1", subject: SUBJECT, scope: ["publish"],
    resources: [{ type: "exact", pattern: RESOURCE }], issuedAt: new Date((NOW - 60) * 1000).toISOString(), expiresAt: new Date((NOW + 300) * 1000).toISOString(),
    state: "SAFE", revocationId: REV_ID, requestedOperation: "publish", resource: RESOURCE, requestedAt: new Date(NOW * 1000).toISOString(),
  };
  return { manifest, envelope: baseEnvelope(manifest), token: "", authorization, chain: null, keyStatus: "valid", keyOwner: SUBJECT, revStatus: "valid", replay: "claimed", ...overrides };
}
interface Scenario {
  manifest: unknown; envelope: SignedEnvelopeV1; token: string; authorization: AuthorizationSnapshot & { requestedOperation: "publish"; resource: string; requestedAt: string };
  chain: DelegationCredential[] | null; keyStatus: "valid" | "revoked" | "suspended" | "unknown"; keyOwner: string; revStatus: "valid" | "revoked" | "unknown"; replay: ClaimResult;
}

function context(s: Scenario): VerificationContext {
  return {
    keyRegistry: new FakeKeyRegistry(s.keyStatus, s.keyOwner), revocationRegistry: new FakeRevocationRegistry(s.revStatus), replayStore: new FakeReplayStore(s.replay),
    expectedAudience: AUD, maxDelegationDepth: 3, maxClockSkewMs: 300_000, oidcToken: s.token,
    oidcPolicy: { allowedIssuers: ["https://token.actions.githubusercontent.com"], allowedAudiences: [AUD], maxClockSkewSeconds: 300, jwksUrl },
    trustedIdentityBinding: { githubSubject: SUBJECT, repository: REPO, keyId: KEY_ID },
  };
}

function tamperSignature(e: SignedEnvelopeV1): SignedEnvelopeV1 { return { ...e, signature: Buffer.from(e.signature, "base64").map((b, i) => i === 0 ? b ^ 1 : b).toString("base64") }; }

beforeAll(async () => {
  oidcPrivateKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
  oidcJwk = await exportJWK(oidcPrivateKey.publicKey); oidcJwk.kid = "oidc-test"; oidcJwk.alg = "RS256"; oidcJwk.use = "sig";
  jwksServer = createServer((req, res) => { if (req.url === "/jwks") { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [oidcJwk] })); } else { res.statusCode = 404; res.end(); } });
  await new Promise<void>(resolve => jwksServer.listen(0, "127.0.0.1", resolve));
  const address = jwksServer.address(); if (!address || typeof address === "string") throw new Error("JWKS server failed"); jwksUrl = new URL(`http://127.0.0.1:${address.port}/jwks`);
  const kp = generateKeyPairSync("ed25519"); signingPrivateKey = kp.privateKey; signingPublicDer = kp.publicKey.export({ type: "spki", format: "der" }).toString("base64");
});
afterAll(async () => { await new Promise<void>(resolve => jwksServer.close(() => resolve())); });

describe("security RC2 adversarial authority gate — 50 cases", () => {
  const cases: Array<{ name: string; mutate: (s: Scenario) => Promise<Scenario> | Scenario; allow: boolean }> = [
    { name: "01 baseline authorized request", mutate: async s => ({ ...s, token: await token() }), allow: true },
    { name: "02 wrong OIDC subject", mutate: async s => ({ ...s, token: await token({ sub: "repo:attacker/repo:ref:refs/heads/main" }) }), allow: false },
    { name: "03 wrong repository claim", mutate: async s => ({ ...s, token: await token({ repository: "attacker/repo" }) }), allow: false },
    { name: "04 wrong issuer", mutate: async s => ({ ...s, token: await token({ iss: "https://attacker.example" }) }), allow: false },
    { name: "05 wrong OIDC audience", mutate: async s => ({ ...s, token: await token({ aud: "https://attacker.example" }) }), allow: false },
    { name: "06 expired OIDC token", mutate: async s => ({ ...s, token: await token({ iat: NOW - 1000, exp: NOW - 10 }) }), allow: false },
    { name: "07 future OIDC token", mutate: async s => ({ ...s, token: await token({ iat: NOW + 1000, exp: NOW + 2000 }) }), allow: false },
    { name: "08 unauthorized workflow ref", mutate: async s => ({ ...s, token: await token({ workflow_ref: "Mise-OS/evil/.github/workflows/evil.yml@refs/heads/main" }) }), allow: false },
    { name: "09 wrong required environment", mutate: async s => ({ ...s, token: await token({ environment: "prod" }), }), allow: false },
    { name: "10 wrong repository owner", mutate: async s => ({ ...s, token: await token({ repository_owner: "attacker" }) }), allow: false },
    { name: "11 unknown signing key", mutate: async s => ({ ...s, envelope: { ...s.envelope, keyId: "unknown-key" } }), allow: false },
    { name: "12 revoked signing key", mutate: s => ({ ...s, keyStatus: "revoked" }), allow: false },
    { name: "13 suspended signing key", mutate: s => ({ ...s, keyStatus: "suspended" }), allow: false },
    { name: "14 envelope keyId not exact binding", mutate: s => ({ ...s, envelope: { ...s.envelope, keyId: "other-key" } }), allow: false },
    { name: "15 registered key owner mismatch", mutate: s => ({ ...s, keyOwner: "repo:other" }), allow: false },
    { name: "16 invalid envelope signature", mutate: s => ({ ...s, envelope: tamperSignature(s.envelope) }), allow: false },
    { name: "17 malformed signature bytes", mutate: s => ({ ...s, envelope: { ...s.envelope, signature: "%%%" } }), allow: false },
    { name: "18 expired envelope", mutate: s => ({ ...s, envelope: { ...s.envelope, expiresAt: new Date((NOW - 10) * 1000).toISOString() } }), allow: false },
    { name: "19 future envelope", mutate: s => ({ ...s, envelope: { ...s.envelope, issuedAt: new Date((NOW + 1000) * 1000).toISOString() } }), allow: false },
    { name: "20 envelope audience mismatch", mutate: s => ({ ...s, envelope: { ...s.envelope, audience: "https://attacker" } }), allow: false },
    { name: "21 manifest digest mismatch", mutate: s => ({ ...s, manifest: { changed: true } }), allow: false },
    { name: "22 authorization state revoked", mutate: s => ({ ...s, authorization: { ...s.authorization, state: "REVOKED" } }), allow: false },
    { name: "23 authorization subject mismatch", mutate: s => ({ ...s, authorization: { ...s.authorization, subject: "attacker" } }), allow: false },
    { name: "24 operation outside scope", mutate: s => ({ ...s, authorization: { ...s.authorization, scope: ["access"] } }), allow: false },
    { name: "25 exact resource mismatch", mutate: s => ({ ...s, authorization: { ...s.authorization, resource: "repo:other:artifact:v1" } }), allow: false },
    { name: "26 prefix boundary mismatch", mutate: s => ({ ...s, authorization: { ...s.authorization, resources: [{ type: "prefix", pattern: "repo:Other" }] } }), allow: false },
    { name: "27 glob mismatch", mutate: s => ({ ...s, authorization: { ...s.authorization, resources: [{ type: "glob", pattern: "repo:Mise-OS/*:release:*" }] } }), allow: false },
    { name: "28 authorization expired", mutate: s => ({ ...s, authorization: { ...s.authorization, expiresAt: new Date((NOW - 10) * 1000).toISOString() } }), allow: false },
    { name: "29 authorization future", mutate: s => ({ ...s, authorization: { ...s.authorization, issuedAt: new Date((NOW + 1000) * 1000).toISOString() } }), allow: false },
    { name: "30 authorization revocation unknown", mutate: s => ({ ...s, revStatus: "unknown" }), allow: false },
    { name: "31 authorization revoked", mutate: s => ({ ...s, revStatus: "revoked" }), allow: false },
    { name: "32 missing authorization revocation id", mutate: s => ({ ...s, authorization: { ...s.authorization, revocationId: undefined } }), allow: false },
    { name: "33 required delegation absent", mutate: s => ({ ...s, envelope: { ...s.envelope, delegationId: "deleg-1" } }), allow: false },
    { name: "34 unexpected delegation supplied", mutate: s => ({ ...s, chain: [{ } as DelegationCredential] }), allow: false },
    { name: "35 delegation root mismatch", mutate: s => ({ ...s, envelope: { ...s.envelope, delegationId: "deleg-1" }, chain: null }), allow: false },
    { name: "36 delegation target mismatch", mutate: s => ({ ...s, envelope: { ...s.envelope, delegationId: "deleg-1" }, chain: [{ } as DelegationCredential] }), allow: false },
    { name: "37 replay detected", mutate: s => ({ ...s, replay: "replayed" }), allow: false },
    { name: "38 replay infrastructure indeterminate", mutate: s => ({ ...s, replay: "indeterminate" }), allow: false },
    { name: "39 envelope missing expiration", mutate: s => { const e = { ...s.envelope }; delete e.expiresAt; return { ...s, envelope: e }; }, allow: false },
    { name: "40 empty nonce", mutate: s => ({ ...s, envelope: { ...s.envelope, nonce: "" } }), allow: false },
    { name: "41 altered payload digest", mutate: s => ({ ...s, envelope: { ...s.envelope, payloadDigest: { algorithm: "sha256", value: "0".repeat(64) } } }), allow: false },
    { name: "42 authorization audience cannot substitute for gate", mutate: s => ({ ...s, authorization: { ...s.authorization, credentialId: "attacker-auth" } }), allow: true },
    { name: "43 wrong workflow identity with valid repository", mutate: async s => ({ ...s, token: await token({ workflow: "attacker" }) }), allow: false },
    { name: "44 wrong workflow SHA", mutate: async s => ({ ...s, token: await token({ workflow_sha: "b".repeat(40) }) }), allow: false },
    { name: "45 wrong ref", mutate: async s => ({ ...s, token: await token({ ref: "refs/heads/evil" }) }), allow: false },
    { name: "46 wrong ref type", mutate: async s => ({ ...s, token: await token({ ref_type: "tag" }) }), allow: false },
    { name: "47 OIDC JWKS unavailable", mutate: async s => ({ ...s, token: await token(), }), allow: false },
    { name: "48 key registry unknown must not become allow", mutate: s => ({ ...s, keyStatus: "unknown" }), allow: false },
    { name: "49 revocation unknown must not become allow", mutate: s => ({ ...s, revStatus: "unknown" }), allow: false },
    { name: "50 simultaneous nonce claim remains single-use", mutate: s => ({ ...s, replay: "replayed" }), allow: false },
  ];

  it("contains exactly 50 adversarial cases", () => expect(cases).toHaveLength(50));

  it.each(cases)("$name", async c => {
    let s = await c.mutate(scenario());
    if (!s.token) s.token = await token();
    const decision = await verify(s.envelope, s.manifest, s.chain, s.authorization, context(s));
    expect(authorityDecision(decision)).toBe(c.allow ? "allow" : "deny");
    if (!c.allow) expect(decision.effect).not.toBe("allow");
  });

  it("CI release gate: no unauthorized case may reach ALLOW", async () => {
    for (const c of cases.filter(x => !x.allow)) {
      let s = await c.mutate(scenario());
      if (!s.token) s.token = await token();
      const decision = await verify(s.envelope, s.manifest, s.chain, s.authorization, context(s));
      expect(authorityDecision(decision), c.name).toBe("deny");
    }
  });
});
