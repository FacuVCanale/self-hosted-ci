import { exports } from "cloudflare:workers";
import { env } from "cloudflare:workers";
import { describe, it } from "vitest";
import { classifyRequestError, handleRequest } from "../src/index";
import { CanonicalPullRequestUnavailable } from "../src/github-checks";

describe("HTTP surface", () => {
  it("maps canonical exhaustion across RPC identity loss to retryable HTTP semantics", ({ expect }) => {
    const now = 1_800_000_000_000;
    expect(classifyRequestError(new CanonicalPullRequestUnavailable("not ready", now + 65_001), now)).toEqual({
      status: 503,
      code: "canonical_pull_request_unavailable",
      headers: { "retry-after": "66" },
    });
    const rpcError = new Error("not ready");
    rpcError.name = `CanonicalPullRequestUnavailable:${now + 5_000}`;
    expect(classifyRequestError(rpcError, now)).toEqual({
      status: 503,
      code: "canonical_pull_request_unavailable",
      headers: { "retry-after": "5" },
    });
  });
  it("exposes health and rejects every route outside the narrow API", async ({ expect }) => {
    const health = await exports.default.fetch(new Request("https://gate.example/health"));
    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toMatchObject({ status: "ok", activation_mode: "active" });

    const unknown = await exports.default.fetch(
      new Request("https://gate.example/v1/admin/dangerous", { method: "POST", body: "{}" }),
    );
    expect(unknown.status).toBe(404);
  });

  it("fails every mutation closed unless activation is exactly active", async ({ expect }) => {
    const response = await handleRequest(
      new Request("https://gate.example/v1/pools/pool-a/gates", { method: "POST", body: "{}" }),
      { ...env, ACTIVATION_MODE: "inert" },
    );
    expect(response.status).toBe(503);

    const invalidEnv = Object.create(env) as Cloudflare.Env;
    Object.defineProperty(invalidEnv, "ACTIVATION_MODE", { value: "typo", enumerable: true });
    const invalid = await handleRequest(
      new Request("https://gate.example/v1/pools/pool-a/gates", { method: "POST", body: "{}" }),
      invalidEnv,
    );
    expect(invalid.status).toBe(503);
  });

  it("has no manager surface and manager headers cannot acknowledge actions", async ({ expect }) => {
    const removed = await exports.default.fetch(new Request(
      "https://gate.example/v1/pools/pool-a/manager/heartbeat",
      { method: "POST", body: "{}", headers: { "x-gate-signature": "v1=fake" } },
    ));
    expect(removed.status).toBe(404);

    const crossAuth = await exports.default.fetch(new Request(
      "https://gate.example/v1/pools/pool-a/control-actions/ack",
      { method: "POST", body: "{}", headers: { "x-gate-signature": "v1=fake" } },
    ));
    expect(crossAuth.status).toBe(401);
  });

  it("does not expose the removed split Check preparation endpoint", async ({ expect }) => {
    const response = await exports.default.fetch(new Request(
      "https://gate.example/v1/pools/pool-a/checks/prepare",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          repository_id: "123456789",
          pr_number: 7,
          head_sha: "1".repeat(40),
        }),
      },
    ));
    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({ error: "not_found" });
  });
});
