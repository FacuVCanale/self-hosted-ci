import { exports } from "cloudflare:workers";
import { env } from "cloudflare:workers";
import { describe, it } from "vitest";
import { handleRequest } from "../src/index";

describe("HTTP surface", () => {
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
});
