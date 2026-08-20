import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:http";
import { exportJWK, SignJWT, type JWK } from "jose";
import { verifyOidcToken } from "../../src/github/oidc.js";

const NOW = Math.floor(Date.now() / 1000);
const ISSUER = "https://token.actions.githubusercontent.com";
const AUD = "https://miseos.dev";
const SUBJECT = "repo:Mise-OS/MiseOS-Dev-ID-:ref:refs/heads/main";
const REPO = "Mise-OS/MiseOS-Dev-ID-";
let server: Server;
let jwksUrl: URL;
let privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];

async function token(overrides: Record<string, unknown> = {}) {
  return new SignJWT({
    iss: ISSUER,
    aud: AUD,
    sub: SUBJECT,
    repository: REPO,
    repository_owner: "Mise-OS",
    repository_id: "1338747102",
    actor: "test",
    actor_id: "1",
    workflow: "security.yml",
    workflow_ref: "Mise-OS/MiseOS-Dev-ID-/.github/workflows/security.yml@refs/heads/main",
    workflow_sha: "a".repeat(40),
    run_id: "1",
    run_number: "1",
    ref: "refs/heads/main",
    ref_type: "branch",
    iat: NOW - 1,
    exp: NOW + 300,
    ...overrides,
  })
    .setProtectedHeader({ alg: "RS256", kid: "oidc-test" })
    .sign(privateKey);
}

function policy() {
  return {
    allowedIssuers: [ISSUER],
    allowedAudiences: [AUD],
    maxClockSkewSeconds: 300,
    jwksUrl,
  };
}

beforeAll(async () => {
  const kp = generateKeyPairSync("rsa", { modulusLength: 2048 });
  privateKey = kp.privateKey;
  const jwk = await exportJWK(kp.publicKey);
  (jwk as JWK).kid = "oidc-test";
  (jwk as JWK).alg = "RS256";
  (jwk as JWK).use = "sig";
  server = createServer((req, res) => {
    if (req.url === "/jwks") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("JWKS fixture failed");
  jwksUrl = new URL(`http://127.0.0.1:${address.port}/jwks`);
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("GitHub OIDC authority temporal hardening", () => {
  it("accepts iat within the configured verifier clock-skew window", async () => {
    const result = await verifyOidcToken(
      await token({ iat: NOW + 5, exp: NOW + 300 }),
      policy(),
      () => NOW,
    );
    expect(result.valid).toBe(true);
  });

  it("denies a token that expires during JWKS/signature verification", async () => {
    let reads = 0;
    const result = await verifyOidcToken(
      await token({ iat: NOW - 1, exp: NOW + 5 }),
      policy(),
      () => {
        reads += 1;
        return reads === 1 ? NOW : NOW + 10;
      },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("OIDC token is expired");
  });

  it("denies iat beyond the configured clock-skew window", async () => {
    const result = await verifyOidcToken(
      await token({ iat: NOW + 301, exp: NOW + 600 }),
      policy(),
      () => NOW,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("OIDC token issued too far in the future");
  });
});
