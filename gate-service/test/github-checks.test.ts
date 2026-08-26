import { exportJWK, exportPKCS8, generateKeyPair } from "jose";
import { beforeAll, describe, it } from "vitest";
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
  testedMergeSha: "3".repeat(40),
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
    merge_commit_sha: preparation.testedMergeSha,
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

function commitResponse(overrides: Record<string, unknown> = {}): Response {
  return json({
    sha: preparation.testedMergeSha,
    parents: [{ sha: preparation.baseSha }, { sha: preparation.headSha }],
    ...overrides,
  });
}

function preparationAuthorityResponses(): Array<Response | Error> {
  return [...authorityResponses(), pullResponse(), refResponse(), commitResponse()];
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

async function preparationMarker(event = preparation): Promise<string> {
  const canonical = [
    "ci-gate-preparation-v1",
    event.repositoryId,
    String(event.prNumber),
    event.headSha,
    event.baseSha,
    event.testedMergeSha,
    event.actor.runId,
    event.actor.runAttempt,
  ].join("\n");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `github-automation-preparation:${hex}`;
}

function preparedCheck(marker: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 501,
    name: "ci-gate",
    app: { id: 111 },
    head_sha: preparation.testedMergeSha,
    status: "in_progress",
    external_id: marker,
    conclusion: null,
    ...overrides,
  };
}

describe("idempotent GitHub Check preparation", () => {
  it("resolves the server-canonical merge only when its ordered parents are exact", async ({ expect }) => {
    const recomputedMerge = "4".repeat(40);
    const mock = sequence([
      pullResponse({
        base: {
          sha: "9".repeat(40),
          ref: "main",
          repo: { id: 123456789, full_name: "example-owner/example-repository" },
        },
        merge_commit_sha: recomputedMerge,
      }),
      refResponse(),
      commitResponse({ sha: recomputedMerge }),
    ]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch)).resolves.toEqual({
      baseSha: preparation.baseSha,
      testedMergeSha: recomputedMerge,
    });
    expect(mock.calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/repos/example-owner/example-repository/pulls/7",
      "/repos/example-owner/example-repository/git/ref/heads/main",
      `/repos/example-owner/example-repository/commits/${recomputedMerge}`,
    ]);
  });
  it("derives one idempotent marker per exact run owner", async ({ expect }) => {
    const first = await derivePreparationMarker(preparation);
    const rerun = await derivePreparationMarker({
      ...preparation,
      actor: { ...preparation.actor, runId: "900", runAttempt: "8", tokenId: "rerun" },
    });
    expect(rerun).not.toBe(first);
    await expect(derivePreparationMarker(preparation)).resolves.toBe(first);
  });
  it("creates the exact in-progress Check and returns no App credential", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...preparationAuthorityResponses(),
      json({ total_count: 0, check_runs: [] }),
      json(preparedCheck(marker), 201),
    ]);
    const result = await prepareGitHubCheck(authority, preparation, mock.fetch, now);
    expect(result).toEqual({
      state: "prepared",
      reconciled: false,
      tuple_current: true,
      check_run_id: 501,
      check_target_sha: preparation.testedMergeSha,
    });
    expect(JSON.stringify(result)).not.toContain("installation-token");
    const create = mock.calls.at(-1)!;
    expect(create.method).toBe("POST");
    expect(create.url).toBe("https://api.github.com/repos/example-owner/example-repository/check-runs");
    await expect(create.json()).resolves.toEqual({
      name: "ci-gate",
      head_sha: preparation.testedMergeSha,
      status: "in_progress",
      external_id: marker,
    });
    const pullRead = mock.calls.find((call) => call.url.endsWith("/pulls/7"))!;
    expect(pullRead.headers.get("authorization")).toBeNull();
  });

  it("returns the existing Check for an identical run attempt without creating", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...preparationAuthorityResponses(),
      json({ total_count: 1, check_runs: [preparedCheck(marker)] }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "prepared",
      reconciled: true,
      tuple_current: true,
      check_run_id: 501,
    });
    expect(mock.calls.filter((call) => call.url.endsWith("/check-runs") && call.method === "POST")).toHaveLength(0);
  });

  it("never adopts terminal evidence heuristically without a durable intent binding", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...authorityResponses(),
      json({
        total_count: 1,
        check_runs: [preparedCheck(marker, {
          status: "completed",
          conclusion: "success",
          external_id: `github-automation-evidence:${"9".repeat(64)}`,
        })],
      }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now, false)).resolves.toMatchObject({
      state: "transient",
    });
    expect(mock.calls.some((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toBe(false);
  });

  it("rejects stale PR tuples before listing or creating a Check", async ({ expect }) => {
    const responses = authorityResponses();
    responses.push(pullResponse({ merge_commit_sha: "4".repeat(40) }));
    responses.push(refResponse());
    responses.push(commitResponse({
      sha: "4".repeat(40),
      parents: [{ sha: preparation.baseSha }, { sha: preparation.headSha }],
    }));
    const mock = sequence(responses);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "blocked",
      error: "current pull request tuple mismatch",
    });
    expect(mock.calls.some((call) => call.url.includes("/check-runs"))).toBe(false);
  });

  it("rejects canonical merge commits with wrong, reordered, or extra parents", async ({ expect }) => {
    for (const parents of [
      [{ sha: "9".repeat(40) }, { sha: preparation.headSha }],
      [{ sha: preparation.headSha }, { sha: preparation.baseSha }],
      [{ sha: preparation.baseSha }, { sha: preparation.headSha }, { sha: "9".repeat(40) }],
    ]) {
      const mock = sequence([pullResponse(), refResponse(), commitResponse({ parents })]);
      await expect(resolveCanonicalPullRequest(authority, {
        repositoryId: preparation.repositoryId,
        prNumber: preparation.prNumber,
        headSha: preparation.headSha,
        actor: preparation.actor,
      }, mock.fetch)).rejects.toThrow(/canonical tested merge/);
    }
  });

  it("rejects a commit response that does not identify the requested canonical SHA", async ({ expect }) => {
    const mock = sequence([pullResponse(), refResponse(), commitResponse({ sha: "9".repeat(40) })]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch)).rejects.toThrow("canonical tested merge commit is invalid");
  });

  it("rejects a PR whose base repository is not the configured immutable repository", async ({ expect }) => {
    const mock = sequence([pullResponse({
      base: {
        sha: preparation.baseSha,
        ref: "main",
        repo: { id: 999, full_name: "attacker/repository" },
      },
    })]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch)).rejects.toThrow("current pull request tuple mismatch");
  });

  it("rejects a stale expected head before resolving base or merge commits", async ({ expect }) => {
    const mock = sequence([pullResponse({ head: { sha: "9".repeat(40) } })]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mock.fetch)).rejects.toThrow("current pull request tuple mismatch");
    expect(mock.calls).toHaveLength(1);
  });

  it("rejects unsafe or mismatched base branch refs", async ({ expect }) => {
    const unsafe = sequence([pullResponse({
      base: {
        sha: preparation.baseSha,
        ref: "../main",
        repo: { id: 123456789, full_name: "example-owner/example-repository" },
      },
    })]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, unsafe.fetch)).rejects.toThrow("current pull request tuple mismatch");

    const mismatched = sequence([pullResponse(), refResponse({ ref: "refs/heads/attacker" })]);
    await expect(resolveCanonicalPullRequest(authority, {
      repositoryId: preparation.repositoryId,
      prNumber: preparation.prNumber,
      headSha: preparation.headSha,
      actor: preparation.actor,
    }, mismatched.fetch)).rejects.toThrow("canonical base ref is invalid");
  });

  it("binds an exact ambiguous marker before classifying a moved PR obsolete", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...authorityResponses(),
      json({ total_count: 1, check_runs: [preparedCheck(marker)] }),
      pullResponse({ head: { sha: "8".repeat(40) } }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now, false)).resolves.toEqual({
      state: "prepared",
      reconciled: true,
      tuple_current: false,
      check_run_id: 501,
      check_target_sha: preparation.testedMergeSha,
    });
    expect(mock.calls.findIndex((call) => call.url.includes("/check-runs")))
      .toBeLessThan(mock.calls.findIndex((call) => call.url.endsWith("/pulls/7")));
  });

  it("reconciles an ambiguous create by the stable marker on the tested SHA", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...preparationAuthorityResponses(),
      json({ total_count: 0, check_runs: [] }),
      new Error("connection reset after send"),
      json({ total_count: 1, check_runs: [preparedCheck(marker)] }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "prepared",
      reconciled: true,
      tuple_current: true,
      check_run_id: 501,
    });
    expect(mock.calls.filter((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toHaveLength(1);
  });

  it("blocks a marker collision from another App", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...preparationAuthorityResponses(),
      json({ total_count: 1, check_runs: [preparedCheck(marker, { app: { id: 999 } })] }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "blocked",
    });
    expect(mock.calls.some((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toBe(false);
  });

  it("blocks duplicate marker matches instead of guessing ownership", async ({ expect }) => {
    const marker = await preparationMarker();
    const mock = sequence([
      ...preparationAuthorityResponses(),
      json({
        total_count: 2,
        check_runs: [preparedCheck(marker), preparedCheck(marker, { id: 502 })],
      }),
    ]);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "blocked",
      error: "duplicate Check preparation marker",
    });
  });

  it("rejects repository authority drift before authenticating to GitHub", async ({ expect }) => {
    const mock = sequence([]);
    await expect(prepareGitHubCheck(
      authority,
      { ...preparation, repositoryId: "987654321" },
      mock.fetch,
      now,
    )).resolves.toMatchObject({ state: "blocked" });
    expect(mock.calls).toHaveLength(0);
  });

  it("scans every page and detects a duplicate marker on the last page", async ({ expect }) => {
    const marker = await preparationMarker();
    const responses: Array<Response | Error> = [...preparationAuthorityResponses()];
    responses.push(json({
      total_count: 101,
      check_runs: [preparedCheck(marker), ...Array.from({ length: 99 }, () => ({ external_id: null }))],
    }));
    responses.push(json({ total_count: 101, check_runs: [preparedCheck(marker, { id: 502 })] }));
    const mock = sequence(responses);
    await expect(prepareGitHubCheck(authority, preparation, mock.fetch, now)).resolves.toMatchObject({
      state: "blocked",
      error: "duplicate Check preparation marker",
    });
    expect(mock.calls.some((call) => call.method === "POST" && call.url.endsWith("/check-runs"))).toBe(false);
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
