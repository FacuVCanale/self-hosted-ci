import { exportJWK, exportPKCS8, generateKeyPair } from "jose";
import { createPrivateKey } from "node:crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  deliverGitHubCheck,
  derivePreparationMarker,
  prepareGitHubCheck,
  resolveCanonicalPullRequest,
  type CheckDeliveryEnv,
  type CheckPreparationEvent,
} from "../src/github-checks";

const now = new Date("2026-08-26T12:00:00Z");
const event = {
  checkRunId: 99,
  headSha: "1".repeat(40),
  evidenceDigest: "a".repeat(64),
  conclusion: "success" as const,
  preparationMarker: `github-automation-preparation:${"f".repeat(64)}`,
};
const marker = `github-automation-evidence:${event.evidenceDigest}`;
let authority!: CheckDeliveryEnv;
const preparation: CheckPreparationEvent = {
  repositoryId: "123456789",
  prNumber: 7,
  headSha: "1".repeat(40),
  baseSha: "2".repeat(40),
  mergePolicyVersion: "local-ort-v1",
  actor: {
    repository: "example-owner/example-repository",
    repositoryId: "123456789",
    workflowRef: "example-owner/example-repository/.github/workflows/ci-gate.yml@refs/heads/main",
    jobWorkflowRef: "example-owner/self-hosted-ci/.github/workflows/ci-gate.yml@refs/heads/main",
    runId: "42",
    runAttempt: "1",
    subject: "repo:example-owner/example-repository:ref:refs/heads/main",
    tokenId: "unique-token-id",
  },
};

function check(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 99,
    name: "ci-gate",
    app: { id: 111 },
    head_sha: event.headSha,
    status: "in_progress",
    external_id: event.preparationMarker,
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

function pullResponse(overrides: Record<string, unknown> = {}): Response {
  return json({
    number: preparation.prNumber,
    state: "open",
    head: { sha: preparation.headSha },
    base: {
      sha: preparation.baseSha,
      ref: "main",
      repo: { id: 123456789, full_name: "example-owner/example-repository" },
    },
    ...overrides,
  });
}

function refResponse(overrides: Record<string, unknown> = {}): Response {
  return json({
    ref: "refs/heads/main",
    object: { type: "commit", sha: preparation.baseSha },
    ...overrides,
  });
}

const noPause = async (): Promise<void> => undefined;

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

function expectExactUserAgent(calls: Request[]): void {
  for (const call of calls) {
    expect(call.headers.get("user-agent")).toBe("self-hosted-ci-gate-service");
  }
}

function preparedCheck(marker: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 501,
    name: "ci-gate",
    app: { id: 111 },
    head_sha: preparation.headSha,
    status: "in_progress",
    external_id: marker,
    conclusion: null,
    ...overrides,
  };
}

describe("local-ort canonical Check preparation", () => {
  const stableCanonicalReads = (): Array<Response | Error> => [
    pullResponse({ merge_commit_sha: null, mergeable: null }),
    refResponse(),
    pullResponse({ merge_commit_sha: "9".repeat(40), mergeable: false }),
    refResponse(),
  ];

  it("double-reads an exact head/base snapshot without merge-ref authority", async ({ expect }) => {
    const mock = sequence(stableCanonicalReads());
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch, noPause)).resolves.toEqual({
      baseSha: preparation.baseSha,
      headSha: preparation.headSha,
      mergePolicyVersion: "local-ort-v1",
    });
    expect(mock.calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/repos/example-owner/example-repository/pulls/7",
      "/repos/example-owner/example-repository/git/ref/heads/main",
      "/repos/example-owner/example-repository/pulls/7",
      "/repos/example-owner/example-repository/git/ref/heads/main",
    ]);
    expectExactUserAgent(mock.calls);
  });

  it("retries the whole snapshot when the base ref moves between reads", async ({ expect }) => {
    const oldBase = "4".repeat(40);
    const mock = sequence([
      pullResponse(),
      refResponse({ object: { type: "commit", sha: oldBase } }),
      pullResponse(),
      refResponse(),
      ...stableCanonicalReads(),
    ]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch, noPause)).resolves.toEqual({
      baseSha: preparation.baseSha,
      headSha: preparation.headSha,
      mergePolicyVersion: "local-ort-v1",
    });
    expect(mock.calls).toHaveLength(8);
  });

  it("rejects a stale event head without authenticating or creating a Check", async ({ expect }) => {
    const mock = sequence([
      pullResponse({ head: { sha: "8".repeat(40) } }),
    ]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch, noPause)).rejects.toMatchObject({ name: "CanonicalPullRequestBlocked" });
    expect(mock.calls).toHaveLength(1);
  });

  it("creates and lists the dedicated Check on the exact PR head SHA", async ({ expect }) => {
    const marker = await derivePreparationMarker(preparation);
    const created = {
      id: 501, name: "ci-gate", app: { id: 111 }, head_sha: preparation.headSha,
      status: "in_progress", external_id: marker, conclusion: null,
    };
    const mock = sequence([
      ...authorityResponses(),
      ...stableCanonicalReads(),
      json({ total_count: 0, check_runs: [] }),
      json(created, 201),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toEqual({
      state: "prepared", reconciled: false, tuple_current: true,
      check_run_id: 501, check_target_sha: preparation.headSha,
    });
    const post = mock.calls.at(-1)!;
    await expect(post.json()).resolves.toMatchObject({ head_sha: preparation.headSha });
    expect(post.url.endsWith("/check-runs")).toBe(true);
    expectExactUserAgent(mock.calls);
  });

  it("requires PKCS#8 private-key PEM and rejects PKCS#1 before any request", async ({ expect }) => {
    const pkcs1 = createPrivateKey(authority.GITHUB_APP_PRIVATE_KEY_PEM)
      .export({ format: "pem", type: "pkcs1" })
      .toString();
    expect(pkcs1).toContain("BEGIN RSA PRIVATE KEY");
    expect(authority.GITHUB_APP_PRIVATE_KEY_PEM).toContain("BEGIN PRIVATE KEY");
    const mock = sequence([]);
    await expect(prepareGitHubCheck(
      { ...authority, GITHUB_APP_PRIVATE_KEY_PEM: pkcs1 },
      preparation,
      mock.fetch,
      now,
    )).resolves.toEqual({ state: "blocked", error: "GitHub App private key is malformed" });
    expect(mock.calls).toHaveLength(0);
  });

  it("derives one stable marker per exact tuple owner and changes it on run attempt", async ({ expect }) => {
    const first = await derivePreparationMarker(preparation);
    await expect(derivePreparationMarker({ ...preparation })).resolves.toBe(first);
    await expect(derivePreparationMarker({
      ...preparation,
      actor: { ...preparation.actor, runAttempt: "2" },
    })).resolves.not.toBe(first);
  });

  it("adopts the unique exact existing Check without POSTing", async ({ expect }) => {
    const marker = await derivePreparationMarker(preparation);
    const mock = sequence([
      ...authorityResponses(),
      ...stableCanonicalReads(),
      json({ total_count: 1, check_runs: [preparedCheck(marker)] }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toEqual({
      state: "prepared", reconciled: true, tuple_current: true,
      check_run_id: 501, check_target_sha: preparation.headSha,
    });
    expect(mock.calls.some((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toBe(false);
  });

  it("reconciles an ambiguous create by exact marker and never emits a second POST", async ({ expect }) => {
    const marker = await derivePreparationMarker(preparation);
    const mock = sequence([
      ...authorityResponses(),
      ...stableCanonicalReads(),
      json({ total_count: 0, check_runs: [] }),
      new Error("connection reset after Check creation"),
      json({ total_count: 1, check_runs: [preparedCheck(marker)] }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "prepared", reconciled: true, check_run_id: 501,
    });
    expect(mock.calls.filter((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toHaveLength(1);
  });

  it("fails closed on base repository/ref drift before authentication or Check creation", async ({ expect }) => {
    for (const changed of [
      { base: { ref: "main", repo: { id: 999, full_name: "attacker/fork" } } },
      { base: { ref: "../main", repo: { id: 123456789, full_name: "example-owner/example-repository" } } },
    ]) {
      const mock = sequence([pullResponse(changed)]);
      await expect(resolveCanonicalPullRequest(authority, {
        repositoryId: preparation.repositoryId,
        prNumber: preparation.prNumber,
        headSha: preparation.headSha,
        actor: preparation.actor,
      }, mock.fetch, noPause)).rejects.toMatchObject({ name: "CanonicalPullRequestBlocked" });
      expect(mock.calls).toHaveLength(1);
    }
  });

  it("propagates canonical-read rate limits without polling amplification", async ({ expect }) => {
    const mock = sequence([
      new Response(JSON.stringify({ message: "rate limited" }), {
        status: 429,
        headers: { "content-type": "application/json", "retry-after": "60" },
      }),
    ]);
    const before = Date.now();
    const error = await resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch, noPause).then(() => null, (failure: unknown) => failure);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).name).toMatch(/^CanonicalPullRequestUnavailable:\d{13}$/);
    expect(Number((error as Error).name.split(":")[1])).toBeGreaterThanOrEqual(before + 60_000);
    expect(mock.calls).toHaveLength(1);
  });

  it("blocks same-marker Checks from another App and duplicate matches across pages", async ({ expect }) => {
    const marker = await derivePreparationMarker(preparation);
    for (const listings of [
      [json({ total_count: 1, check_runs: [preparedCheck(marker, { app: { id: 999 } })] })],
      [
        json({
          total_count: 101,
          check_runs: [preparedCheck(marker), ...Array.from({ length: 99 }, () => ({ external_id: null }))],
        }),
        json({ total_count: 101, check_runs: [preparedCheck(marker, { id: 502 })] }),
      ],
    ]) {
      const mock = sequence([...authorityResponses(), ...stableCanonicalReads(), ...listings]);
      await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({ state: "blocked" });
      expect(mock.calls.some((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toBe(false);
    }
  });
});

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
