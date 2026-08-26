import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, it } from "vitest";
import { verifyGitHubOidc } from "../src/auth";

const trust = {
  audience: "self-hosted-ci-gate",
  repository: "example-owner/example-repository",
  repositoryId: "123456789",
  workflowRef: "example-owner/example-repository/.github/workflows/ci-gate.yml@refs/heads/main",
  jobWorkflowRef: "example-owner/self-hosted-ci/.github/workflows/ci-gate.yml@refs/heads/main",
};

async function oidcToken(overrides: Record<string, string> = {}) {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "test-key";
  const now = 1_800_000_000;
  const payload = {
    repository: trust.repository,
    repository_id: trust.repositoryId,
    workflow_ref: trust.workflowRef,
    job_workflow_ref: trust.jobWorkflowRef,
    run_id: "42",
    run_attempt: "1",
    event_name: "workflow_call",
    runner_environment: "github-hosted",
    ...overrides,
  };
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: "JWT" })
    .setIssuer("https://token.actions.githubusercontent.com")
    .setAudience(trust.audience)
    .setSubject("repo:example-owner/example-repository:ref:refs/heads/main")
    .setJti("unique-token-id")
    .setIssuedAt(now)
    .setNotBefore(now - 1)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  return { token, keys: createLocalJWKSet({ keys: [jwk] }), now };
}

describe("authentication", () => {
  it("accepts only the exact configured GitHub OIDC claims", async ({ expect }) => {
    const valid = await oidcToken();
    const actor = await verifyGitHubOidc(valid.token, trust, valid.keys, new Date(valid.now * 1000));
    expect(actor.repositoryId).toBe(trust.repositoryId);

    const wrongWorkflow = await oidcToken({ job_workflow_ref: "attacker/repo/.github/workflows/x.yml@refs/heads/main" });
    await expect(
      verifyGitHubOidc(wrongWorkflow.token, trust, wrongWorkflow.keys, new Date(wrongWorkflow.now * 1000)),
    ).rejects.toThrow("claim mismatch: job_workflow_ref");
  });
});
