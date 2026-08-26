import { exportJWK, exportPKCS8, generateKeyPair } from "jose";
import { beforeAll, describe, it } from "vitest";
import { deliverGitHubCheck, type CheckDeliveryEnv } from "../src/github-checks";

const now = new Date("2026-08-26T12:00:00Z");
const event = {
  checkRunId: 99,
  headSha: "1".repeat(40),
  evidenceDigest: "a".repeat(64),
  conclusion: "success" as const,
};
const marker = `github-automation-evidence:${event.evidenceDigest}`;
let authority!: CheckDeliveryEnv;

function check(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 99,
    name: "ci-gate",
    app: { id: 111 },
    head_sha: event.headSha,
    status: "in_progress",
    external_id: null,
    conclusion: null,
    ...overrides,
  };
}

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const pem = await exportPKCS8(privateKey);
  const jwk = await exportJWK(privateKey);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"],
  );
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  if (!(spki instanceof ArrayBuffer)) throw new Error("unexpected public key export");
  const digest = await crypto.subtle.digest("SHA-256", spki);
  const fingerprint = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  authority = {
    GITHUB_APP_ID: "111",
    GITHUB_APP_INSTALLATION_ID: "222",
    GITHUB_REPOSITORY: "example-owner/example-repository",
    GITHUB_REPOSITORY_ID: "123456789",
    GITHUB_APP_KEY_FINGERPRINT: fingerprint,
    GITHUB_APP_PRIVATE_KEY_PEM: pem,
  };
});

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status });
}

function authorityResponses(): Array<Response | Error> {
  return [
    json({ id: 111, permissions: { checks: "write", metadata: "read" } }),
    json({
      id: 222,
      app_id: 111,
      repository_selection: "selected",
      permissions: { checks: "write", metadata: "read" },
      suspended_at: null,
    }),
    json({
      token: "installation-token",
      expires_at: "2026-08-26T12:59:00Z",
      permissions: { checks: "write", metadata: "read" },
      repositories: [{ id: 123456789, full_name: "example-owner/example-repository" }],
    }, 201),
    json({ id: 123456789, full_name: "example-owner/example-repository" }),
  ];
}

function sequence(responses: Array<Response | Error>): { fetch: typeof fetch; calls: Request[] } {
  const calls: Request[] = [];
  const mock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push(new Request(input, init));
    const response = responses.shift();
    if (response === undefined) throw new Error("unexpected request");
    if (response instanceof Error) throw response;
    return response;
  };
  return { fetch: mock as typeof fetch, calls };
}

describe("effectively-once GitHub Check delivery", () => {
  it("pre-reads and emits only the exact terminal PATCH", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check()),
      json(check({ status: "completed", external_id: marker, conclusion: "success" })),
    ]);
    await expect(deliverGitHubCheck(authority, event, mock.fetch, now)).resolves.toEqual({
      state: "delivered",
      reconciled: false,
    });
    const patch = mock.calls.at(-1)!;
    expect(patch.method).toBe("PATCH");
    await expect(patch.json()).resolves.toEqual({ external_id: marker, conclusion: "success" });
  });

  it("recovers a crash after GitHub accepted the prior PATCH without writing again", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check({ status: "completed", external_id: marker, conclusion: "success" })),
    ]);
    await expect(deliverGitHubCheck(authority, event, mock.fetch, now)).resolves.toEqual({
      state: "delivered",
      reconciled: true,
    });
    expect(mock.calls.some((call) => call.method === "PATCH")).toBe(false);
  });

  it("read-backs an ambiguous PATCH and converges on the same evidence", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check()),
      new Error("connection reset after send"),
      json(check({ status: "completed", external_id: marker, conclusion: "success" })),
    ]);
    await expect(deliverGitHubCheck(authority, event, mock.fetch, now)).resolves.toEqual({
      state: "delivered",
      reconciled: true,
    });
  });

  it("blocks rather than overwriting different evidence", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check({
        status: "completed",
        external_id: `github-automation-evidence:${"b".repeat(64)}`,
        conclusion: "failure",
      })),
    ]);
    const result = await deliverGitHubCheck(authority, event, mock.fetch, now);
    expect(result.state).toBe("blocked");
    expect(mock.calls.some((call) => call.method === "PATCH")).toBe(false);
  });

  it("keeps an unreconciled ambiguous write transient for alarm retry", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check()),
      new Error("connection reset after send"),
      json(check()),
    ]);
    const result = await deliverGitHubCheck(authority, event, mock.fetch, now);
    expect(result.state).toBe("transient");
  });

  it("validates the configured SPKI fingerprint before any GitHub call", async ({ expect }) => {
    const mock = sequence([]);
    const result = await deliverGitHubCheck(
      { ...authority, GITHUB_APP_KEY_FINGERPRINT: "0".repeat(64) },
      event,
      mock.fetch,
      now,
    );
    expect(result.state).toBe("blocked");
    expect(mock.calls).toHaveLength(0);
  });

  it("blocks a same-ID Check from another App and never patches it", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check({ app: { id: 999 } })),
    ]);
    const result = await deliverGitHubCheck(authority, event, mock.fetch, now);
    expect(result.state).toBe("blocked");
    expect(mock.calls.some((call) => call.method === "PATCH")).toBe(false);
  });

  it("does not accept matching evidence unless GitHub reports completed", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check({ external_id: marker, conclusion: "success" })),
    ]);
    await expect(deliverGitHubCheck(authority, event, mock.fetch, now)).resolves.toMatchObject({
      state: "blocked",
    });
  });

  it("keeps a rate-limited 403 retryable", async ({ expect }) => {
    const mock = sequence([
      new Response("{}", {
        status: 403,
        headers: { "content-type": "application/json", "retry-after": "60" },
      }),
    ]);
    const result = await deliverGitHubCheck(authority, event, mock.fetch, now);
    expect(result.state).toBe("transient");
    expect(result).toHaveProperty("retryAt");
  });

  it("blocks a non-rate-limit authorization 403", async ({ expect }) => {
    const mock = sequence([json({ message: "forbidden" }, 403)]);
    await expect(deliverGitHubCheck(authority, event, mock.fetch, now)).resolves.toMatchObject({
      state: "blocked",
    });
  });

  it("preserves Retry-After when a rate-limited PATCH remains ambiguous", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check()),
      new Response("{}", {
        status: 403,
        headers: { "content-type": "application/json", "retry-after": "60" },
      }),
      json(check()),
    ]);
    const before = Date.now() + 60_000;
    const result = await deliverGitHubCheck(authority, event, mock.fetch, now);
    expect(result.state).toBe("transient");
    if (result.state !== "transient") throw new Error("unexpected delivery result");
    expect(result.retryAt).toBeGreaterThanOrEqual(before);
  });

  it("preserves Retry-After when ambiguous PATCH reconciliation is rate-limited", async ({ expect }) => {
    const mock = sequence([
      ...authorityResponses(),
      json(check()),
      new Error("connection reset after send"),
      new Response("{}", {
        status: 403,
        headers: { "content-type": "application/json", "retry-after": "90" },
      }),
    ]);
    const before = Date.now() + 90_000;
    const result = await deliverGitHubCheck(authority, event, mock.fetch, now);
    expect(result.state).toBe("transient");
    if (result.state !== "transient") throw new Error("unexpected delivery result");
    expect(result.retryAt).toBeGreaterThanOrEqual(before);
  });
});
