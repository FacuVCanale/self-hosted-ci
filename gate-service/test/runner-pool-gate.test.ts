import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, it } from "vitest";
import { vi } from "vitest";
import { exportJWK, exportPKCS8, generateKeyPair } from "jose";
import type { GateSnapshot, OidcActor } from "../src/contracts";
import { LocalMergeRunnerPoolGate } from "../src/runner-pool-gate";
import { derivePreparationMarker } from "../src/github-checks";
import { classifyRequestError } from "../src/index";

const actor: OidcActor = {
  repository: "example-owner/example-repository",
  repositoryId: "123456789",
  workflowRef: "example-owner/example-repository/.github/workflows/ci-gate.yml@refs/heads/main",
  jobWorkflowRef: "example-owner/self-hosted-ci/.github/workflows/ci-gate.yml@refs/heads/main",
  runId: "42",
  runAttempt: "1",
  subject: "repo:example-owner/example-repository:ref:refs/heads/main",
  tokenId: "oidc-jti-1",
};

function acquisition(overrides: Record<string, unknown> = {}) {
  return {
    repository_id: "123456789",
    pr_number: 7,
    head_sha: "1".repeat(40),
    ...overrides,
  };
}

async function localTransition(
  gate: GateSnapshot,
  toState: "hosted_success" | "hosted_failure",
  ownerActor = actor,
) {
  const conclusion = toState === "hosted_success" ? "success" : "failure";
  const mergeBaseSha = "5".repeat(40);
  const testedTreeSha = "6".repeat(40);
  const localCommitSha = "7".repeat(40);
  const commandDigest = "8".repeat(64);
  const material = [
    "ci-gate-local-ort-evidence-v1",
    gate.logical_key,
    String(gate.generation),
    gate.base_sha,
    gate.head_sha,
    gate.merge_policy_version,
    "git version 2.55.0",
    gate.runner_image,
    mergeBaseSha,
    testedTreeSha,
    localCommitSha,
    commandDigest,
    ownerActor.runId,
    ownerActor.runAttempt,
    conclusion,
  ].join("\n") + "\n";
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  const evidenceDigest = [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return {
    logical_key: gate.logical_key,
    generation: gate.generation,
    expected_version: gate.version,
    from_state: "hosted_selected" as const,
    to_state: toState,
    evidence_digest: evidenceDigest,
    base_sha: gate.base_sha,
    head_sha: gate.head_sha,
    merge_policy_version: gate.merge_policy_version,
    git_version: "git version 2.55.0",
    runner_image: gate.runner_image,
    merge_base_sha: mergeBaseSha,
    tested_tree_sha: testedTreeSha,
    local_commit_sha: localCommitSha,
    command_digest: commandDigest,
  };
}

async function seedGate(
  stub: DurableObjectStub<LocalMergeRunnerPoolGate>,
  pool: string,
  raw = acquisition(),
  ownerActor = actor,
) {
  const input = raw as ReturnType<typeof acquisition>;
  const suppliedBaseSha = (raw as Record<string, unknown>).base_sha;
  const baseSha = typeof suppliedBaseSha === "string" ? suppliedBaseSha : "2".repeat(40);
  const mergePolicyVersion = "local-ort-v1";
  const marker = await derivePreparationMarker({
    repositoryId: input.repository_id as string,
    prNumber: input.pr_number as number,
    headSha: input.head_sha as string,
    baseSha,
    mergePolicyVersion: "local-ort-v1",
    actor: ownerActor,
  });
  return runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
    const now = Date.now();
    state.storage.sql.exec("INSERT OR IGNORE INTO pool_metadata VALUES (1,?)", pool);
    state.storage.sql.exec(
      `INSERT OR IGNORE INTO check_creation_intents(
        intent_key,marker,repository_id,pr_number,head_sha,base_sha,merge_policy_version,
        owner,actor_subject,state,post_attempted,check_run_id,deadline_at,next_attempt_at,
        attempts,last_error,created_at,updated_at,consumed_generation,incident_at
      ) VALUES (?,?,?,?,?,?,?,?,?,'pending',1,NULL,?,?,0,NULL,?,?,NULL,NULL)`,
      marker, marker, input.repository_id, input.pr_number, input.head_sha, baseSha,
      mergePolicyVersion, `${ownerActor.runId}:${ownerActor.runAttempt}`, ownerActor.subject,
      now + 300_000, now, now, now,
    );
    const testInstance = instance as unknown as {
      commitPreparedIntent(poolId: string, intentMarker: string, checkId: number, subject: string, at: number): Promise<GateSnapshot>;
    };
    return testInstance.commitPreparedIntent(pool, marker, 99, ownerActor.subject, now);
  });
}

async function testAppAuthority(): Promise<{ pem: string; fingerprint: string }> {
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
  return {
    pem,
    fingerprint: [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  };
}

function githubHarness(options: {
  ambiguousCreate?: boolean;
  failFirstRequest?: boolean;
  hiddenCreatedListings?: number;
  pauseFirstCreate?: boolean;
  mergeRefFailures?: number;
  staleMergeParents?: number;
  mergeConflict?: boolean;
} = {}) {
  const checks: Record<string, unknown>[] = [];
  let pullHeadSha = "1".repeat(40);
  let pullBaseSha = "2".repeat(40);
  let pullMergeSha = "3".repeat(40);
  let hiddenCreatedListings = options.ambiguousCreate === true
    ? options.hiddenCreatedListings ?? 1
    : 0;
  let posts = 0;
  let releaseFirstCreate!: () => void;
  let signalFirstCreate!: () => void;
  const firstCreateStarted = new Promise<void>((resolve) => { signalFirstCreate = resolve; });
  const firstCreateRelease = new Promise<void>((resolve) => { releaseFirstCreate = resolve; });
  let failFirstRequest = options.failFirstRequest === true;
  let mergeRefFailures = options.mergeRefFailures ?? 0;
  let staleMergeParents = options.staleMergeParents ?? 0;
  const request = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const call = new Request(input, init);
    const url = new URL(call.url);
    if (failFirstRequest && url.pathname === "/app") {
      failFirstRequest = false;
      throw new Error("simulated crash boundary before network completion");
    }
    if (url.pathname === "/app") return Response.json({ id: 111, permissions: { checks: "write", metadata: "read" } });
    if (url.pathname.endsWith("/installation")) return Response.json({
      id: 222, app_id: 111, repository_selection: "selected",
      permissions: { checks: "write", metadata: "read" }, suspended_at: null,
    });
    if (url.pathname.endsWith("/access_tokens")) return Response.json({
      token: "installation-token",
      expires_at: new Date(Date.now() + 59 * 60_000).toISOString(),
      permissions: { checks: "write", metadata: "read" },
      repositories: [{ id: 123456789, full_name: "example-owner/example-repository" }],
    }, { status: 201 });
    if (url.pathname.endsWith("/pulls/7")) return Response.json({
      number: 7, state: "open", head: { sha: pullHeadSha },
      base: {
        sha: "2".repeat(40),
        ref: "main",
        repo: { id: 123456789, full_name: "example-owner/example-repository" },
      },
      merge_commit_sha: null,
      mergeable: options.mergeConflict === true ? false : true,
    });
    if (url.pathname === "/repos/example-owner/example-repository/git/ref/heads/main") {
      return Response.json({ ref: "refs/heads/main", object: { type: "commit", sha: pullBaseSha } });
    }
    if (url.pathname === "/repos/example-owner/example-repository/git/ref/pull/7/merge") {
      if (mergeRefFailures > 0) {
        mergeRefFailures -= 1;
        return Response.json({ message: "Not Found" }, { status: 404 });
      }
      return Response.json({ ref: "refs/pull/7/merge", object: { type: "commit", sha: pullMergeSha } });
    }
    if (url.pathname === `/repos/example-owner/example-repository/commits/${pullMergeSha}`) {
      if (staleMergeParents > 0) {
        staleMergeParents -= 1;
        return Response.json({
          sha: pullMergeSha,
          parents: [{ sha: "9".repeat(40) }, { sha: pullHeadSha }],
        });
      }
      return Response.json({
        sha: pullMergeSha,
        parents: [{ sha: pullBaseSha }, { sha: pullHeadSha }],
      });
    }
    if (url.pathname.includes("/commits/") && url.pathname.endsWith("/check-runs")) {
      if (hiddenCreatedListings > 0 && checks.length > 0) {
        hiddenCreatedListings -= 1;
        return Response.json({ total_count: 0, check_runs: [] });
      }
      return Response.json({ total_count: checks.length, check_runs: checks });
    }
    if (url.pathname.endsWith("/check-runs") && call.method === "POST") {
      posts += 1;
      if (options.pauseFirstCreate && posts === 1) {
        signalFirstCreate();
        await firstCreateRelease;
      }
      const body = await call.json() as Record<string, unknown>;
      const check = { id: 99 + posts - 1, app: { id: 111 }, conclusion: null, ...body };
      checks.push(check);
      if (options.ambiguousCreate) throw new Error("connection reset after commit");
      return Response.json(check, { status: 201 });
    }
    if (/\/check-runs\/\d+$/.test(url.pathname) && call.method === "GET") {
      return Response.json(checks.find((value) => String(value.id) === url.pathname.split("/").at(-1)) ?? null);
    }
    if (/\/check-runs\/\d+$/.test(url.pathname) && call.method === "PATCH") {
      const body = await call.json() as Record<string, unknown>;
      const index = checks.findIndex((value) => String(value.id) === url.pathname.split("/").at(-1));
      checks[index] = { ...checks[index], ...body, status: "completed" };
      return Response.json(checks[index]);
    }
    if (url.pathname === "/repos/example-owner/example-repository") {
      return Response.json({ id: 123456789, full_name: "example-owner/example-repository" });
    }
    throw new Error(`unexpected GitHub call: ${call.method} ${call.url}`);
  });
  return {
    request,
    posts: () => posts,
    check: () => checks.at(-1) ?? null,
    checks: () => checks,
    movePull: () => { pullHeadSha = "8".repeat(40); },
    moveBase: () => {
      pullBaseSha = "4".repeat(40);
      pullMergeSha = "5".repeat(40);
    },
    recomputeMerge: () => { pullMergeSha = "6".repeat(40); },
    moveHeadTuple: () => {
      pullHeadSha = "8".repeat(40);
      pullBaseSha = "4".repeat(40);
      pullMergeSha = "5".repeat(40);
    },
    waitForFirstCreate: () => firstCreateStarted,
    releaseFirstCreate: () => releaseFirstCreate(),
  };
}

function installTestAuthority(instance: LocalMergeRunnerPoolGate, authority: { pem: string; fingerprint: string }): void {
  const runtime = instance as unknown as { env: Record<string, string> };
  runtime.env.GITHUB_APP_PRIVATE_KEY_PEM = authority.pem;
  runtime.env.GITHUB_APP_KEY_FINGERPRINT = authority.fingerprint;
}

describe("hosted-only LocalMergeRunnerPoolGate", () => {
  it("derives logical_key and creates exactly one hosted dispatch idempotently", async ({ expect }) => {
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("hosted-pool");
    try {
      const first = await seedGate(stub, "hosted-pool");
      const retry = await stub.acquire("hosted-pool", acquisition(), actor);
      expect(first).toEqual(retry);
      expect(first.logical_key).toBe(`123456789:7:${"1".repeat(40)}:ci-gate`);
      expect(first.state).toBe("hosted_selected");
      expect(first.owner).toBe("42:1");
      const actions = await stub.listControlActions();
      expect(actions).toHaveLength(1);
      expect(actions[0]?.kind).toBe("dispatch_hosted");
    } finally {
      github.request.mockRestore();
    }
  });

  it("rejects caller logical keys and conflicting check invariants", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("invariants-pool");
    await seedGate(stub, "invariants-pool");
    const callerKey = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.acquire("invariants-pool", acquisition({ logical_key: "caller-controlled" }), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.name : "unknown";
      }
    });
    expect(callerKey).toBe("ZodError");
    const conflictingCheck = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.acquire("invariants-pool", acquisition({ check_run_id: 100 }), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(conflictingCheck).toContain("Unrecognized key");
    const callerMerge = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.acquire("invariants-pool", acquisition({ tested_merge_sha: "3".repeat(40) }), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(callerMerge).toContain("Unrecognized key");
    const callerBase = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.acquire("invariants-pool", acquisition({ base_sha: "2".repeat(40) }), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(callerBase).toContain("Unrecognized key");
  });

  it("allows one hosted terminal winner and fences the competing CAS", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("winner-pool");
    const gate = await seedGate(stub, "winner-pool");
    const committed = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      const winner = await instance.transition(await localTransition(gate, "hosted_failure"), actor);
      return { winner, outbox: await instance.listCheckOutbox() };
    });
    expect(committed.winner.state).toBe("hosted_failure");
    expect(committed.outbox).toHaveLength(1);
    expect(committed.outbox[0]?.state).toBe("pending");
    expect(committed.outbox[0]?.attempts).toBe(0);
    const loser = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.transition(await localTransition(gate, "hosted_success"), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(loser).toContain("conflicts with committed evidence");
    const outbox = await stub.listCheckOutbox();
    expect(outbox).toHaveLength(1);
    // The local test runtime is active, so the scheduled alarm immediately
    // consumes the pending entry and fail-closes on its deliberately invalid key.
    expect(outbox[0]?.state).toBe("blocked");
    expect(outbox[0]?.attempts).toBe(1);
    expect(outbox[0]?.last_error).toContain("private key is malformed");
  });

  it("requires complete local merge evidence even in the local-test environment", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("strict-evidence-pool");
    const gate = await seedGate(stub, "strict-evidence-pool");
    const error = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.transition({
          logical_key: gate.logical_key,
          generation: gate.generation,
          expected_version: gate.version,
          from_state: "hosted_selected",
          to_state: "hosted_failure",
          evidence_digest: "a".repeat(64),
        }, actor);
        return "unexpected_success";
      } catch (failure) {
        return failure instanceof Error ? failure.message : "unknown";
      }
    });
    expect(error).toContain("base_sha");
    expect(error).toContain("git_version");
    expect((await stub.getGate(gate.logical_key, gate.generation)).state).toBe("hosted_selected");
  });

  it("returns an identical terminal retry and conflicts different evidence", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("terminal-retry-pool");
    const gate = await seedGate(stub, "terminal-retry-pool");
    const transition = await localTransition(gate, "hosted_failure");
    const committed = await stub.transition(transition, actor);
    await expect(stub.transition(transition, actor)).resolves.toEqual(committed);
    const conflict = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.transition(await localTransition(gate, "hosted_success"), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(conflict).toContain("conflicts with committed evidence");
  });

  it("lets the OIDC coordinator acknowledge hosted actions", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("ack-pool");
    await seedGate(stub, "ack-pool");
    const action = (await stub.listControlActions())[0];
    await expect(stub.acknowledgeControlAction({
      action_id: action?.action_id,
      outcome: "accepted",
    }, actor)).resolves.toEqual({ accepted: true });
  });

  it("supersedes the prior generation on base movement and fences late completion and ACK", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("base-movement-pool");
    const oldGate = await seedGate(stub, "base-movement-pool");
    const oldAction = (await stub.listControlActions())[0];
    const current = await seedGate(
      stub,
      "base-movement-pool",
      acquisition({ base_sha: "4".repeat(40), tested_merge_sha: "5".repeat(40) }),
    );
    expect(current.generation).toBe(oldGate.generation + 1);
    expect((await stub.getGate(oldGate.logical_key, oldGate.generation)).state).toBe("hosted_failure");
    expect(await stub.listCheckOutbox()).toHaveLength(1);

    const lateCompletion = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.transition(await localTransition(oldGate, "hosted_success"), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(lateCompletion).toContain("not latest");

    const lateAck = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.acknowledgeControlAction({
          action_id: oldAction?.action_id,
          outcome: "completed",
        }, actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(lateAck).toContain("not latest");
  });

  it("fences cross-owner terminal transitions and action ACKs", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("cross-owner-pool");
    const gate = await seedGate(stub, "cross-owner-pool");
    const action = (await stub.listControlActions())[0];
    const otherActor = { ...actor, runId: "43", tokenId: "oidc-jti-2", subject: `${actor.subject}:other-run` };

    const transition = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.transition(await localTransition(gate, "hosted_failure", otherActor), otherActor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(transition).toContain("another OIDC coordinator");

    const ack = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
      try {
        await instance.acknowledgeControlAction({
          action_id: action?.action_id,
          outcome: "accepted",
        }, otherActor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(ack).toContain("another OIDC coordinator");
  });

  it("does not displace an active owner when a rerun arrives", async ({ expect }) => {
    const github = githubHarness();
    const selectedStub = env.RUNNER_POOLS_V2.getByName("selected-rerun-pool");
    try {
      await seedGate(selectedStub, "selected-rerun-pool");
      const rerunActor = { ...actor, runAttempt: "2", tokenId: "oidc-jti-rerun" };
      const crossOwner = await runInDurableObject(selectedStub, async (instance: LocalMergeRunnerPoolGate) => {
        try {
          await instance.acquire("selected-rerun-pool", acquisition(), rerunActor);
          return "unexpected_success";
        } catch (error) {
          return error instanceof Error ? error.message : "unknown";
        }
      });
      expect(crossOwner).toContain("active coordinator");
      expect((await selectedStub.getGate(`123456789:7:${"1".repeat(40)}:ci-gate`, 1)).state).toBe("hosted_selected");
      expect(await selectedStub.listCheckOutbox()).toHaveLength(0);
    } finally {
      github.request.mockRestore();
    }
  });

  it("watchdog fails an abandoned hosted gate and creates one terminal outbox", async ({ expect }) => {
    const stub = env.RUNNER_POOLS_V2.getByName("hosted-timeout-pool");
    const gate = await seedGate(stub, "hosted-timeout-pool");
    const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
      state.storage.sql.exec(
        "UPDATE gates SET hosted_deadline_at=0 WHERE logical_key=? AND generation=?",
        gate.logical_key,
        gate.generation,
      );
      await instance.alarm();
      return {
        gate: await instance.getGate(gate.logical_key, gate.generation),
        outbox: await instance.listCheckOutbox(),
        audit: await instance.listAudit(),
      };
    });
    expect(result.gate.state).toBe("hosted_failure");
    expect(result.gate.evidence_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(result.outbox).toHaveLength(1);
    expect(result.outbox[0]?.conclusion).toBe("failure");
    expect(result.audit.some((entry) => entry.event_type === "hosted_gate_timeout")).toBe(true);
  });

  it("integrates acquire intent through transition and alarm-delivered PATCH", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-success-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        const gate = await instance.acquire("integrated-success-pool", acquisition(), actor);
        await instance.transition(await localTransition(gate, "hosted_success"), actor);
        await instance.alarm();
        const evidence = state.storage.sql.exec<Record<string, SqlStorageValue>>(
          "SELECT * FROM terminal_evidence WHERE logical_key=? AND generation=?",
          gate.logical_key,
          gate.generation,
        ).one();
        const audit = (await instance.listAudit()).find((entry) => entry.event_type === "hosted_gate_terminal");
        return { gate, outbox: await instance.listCheckOutbox(), evidence, audit };
      });
      expect(result.outbox).toHaveLength(1);
      expect(result.gate.merge_policy_version).toBe("local-ort-v1");
      expect(result.outbox[0]?.state, String(result.outbox[0]?.last_error)).toBe("delivered");
      expect(github.posts()).toBe(1);
      expect(github.check()).toMatchObject({ status: "completed", conclusion: "success" });
      expect(result.evidence).toMatchObject({
        base_sha: result.gate.base_sha,
        head_sha: result.gate.head_sha,
        merge_policy_version: "local-ort-v1",
        git_version: "git version 2.55.0",
        runner_image: "ubuntu-24.04",
        merge_base_sha: "5".repeat(40),
        tested_tree_sha: "6".repeat(40),
        local_commit_sha: "7".repeat(40),
        command_digest: "8".repeat(64),
        owner_run_id: actor.runId,
        owner_run_attempt: actor.runAttempt,
      });
      expect(JSON.parse(String(result.audit?.detail_json))).toMatchObject({
        evidence_digest: result.evidence.evidence_digest,
        base_sha: result.gate.base_sha,
        head_sha: result.gate.head_sha,
        git_version: "git version 2.55.0",
        runner_image: "ubuntu-24.04",
        local_commit_sha: "7".repeat(40),
      });
    } finally {
      github.request.mockRestore();
    }
  });

  it("fences success on canonical base drift but still delivers historical failure", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const pool = "integrated-success-drift-pool";
    const stub = env.RUNNER_POOLS_V2.getByName(pool);
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        const gate = await instance.acquire(pool, acquisition(), actor);
        github.moveBase();
        const success = await instance.transition(await localTransition(gate, "hosted_success"), actor)
          .then(() => "unexpected_success", (error: unknown) => error instanceof Error ? error.message : "unknown");
        const selected = await instance.getGate(gate.logical_key, gate.generation);
        const failure = await instance.transition(await localTransition(gate, "hosted_failure"), actor);
        await instance.alarm();
        return { success, selected, failure, outbox: await instance.listCheckOutbox() };
      });
      expect(result.success).toContain("moved before successful transition");
      expect(result.selected.state).toBe("hosted_selected");
      expect(result.failure.state).toBe("hosted_failure");
      expect(result.outbox).toHaveLength(1);
      expect(result.outbox[0]).toMatchObject({ state: "delivered", conclusion: "failure", check_run_id: 99 });
      expect(github.check()).toMatchObject({ head_sha: "1".repeat(40), status: "completed", conclusion: "failure" });
    } finally {
      github.request.mockRestore();
    }
  });

  it("creates exactly one head Check from a stable double-read canonical tuple", async ({ expect }) => {
    for (const [suffix, options] of [
      ["missing-ref", { mergeRefFailures: 1 }],
      ["stale-parents", { staleMergeParents: 1 }],
    ] as const) {
      const authority = await testAppAuthority();
      const github = githubHarness(options);
      const pool = `integrated-canonical-poll-${suffix}`;
      const stub = env.RUNNER_POOLS_V2.getByName(pool);
      try {
        const gate = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
          installTestAuthority(instance, authority);
          return instance.acquire(pool, acquisition(), actor);
        });
        expect(gate).toMatchObject({
          state: "hosted_selected",
          base_sha: "2".repeat(40),
          head_sha: "1".repeat(40),
          merge_policy_version: "local-ort-v1",
          check_run_id: 99,
        });
        expect(github.posts()).toBe(1);
        expect(github.checks()).toHaveLength(1);
      } finally {
        github.request.mockRestore();
      }
    }
  });

  it("does not consult synthetic merge refs or mergeability during acquire", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ mergeRefFailures: 3, staleMergeParents: 3, mergeConflict: true });
    const pool = "integrated-local-merge-authority";
    const stub = env.RUNNER_POOLS_V2.getByName(pool);
    try {
      const gate = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        return instance.acquire(pool, acquisition(), actor);
      });
      expect(gate).toMatchObject({
        state: "hosted_selected",
        head_sha: "1".repeat(40),
        base_sha: "2".repeat(40),
        merge_policy_version: "local-ort-v1",
      });
      expect(github.posts()).toBe(1);
    } finally {
      github.request.mockRestore();
    }
  });

  it("reconciles ambiguous committed POST from alarm without ever re-POSTing", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ ambiguousCreate: true });
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-ambiguous-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        let outcome = "unexpected_success";
        try {
          await instance.acquire("integrated-ambiguous-pool", acquisition(), actor);
        } catch (error) {
          outcome = error instanceof Error ? error.message : "unknown";
        }
        state.storage.sql.exec("UPDATE check_creation_intents SET next_attempt_at=0");
        await instance.alarm();
        return {
          outcome,
          gate: await instance.getGate(`123456789:7:${"1".repeat(40)}:ci-gate`, 1),
        };
      });
      expect(result.outcome).toContain("pending durable reconciliation");
      expect(result.gate.state).toBe("hosted_selected");
      expect(github.posts()).toBe(1);
    } finally {
      github.request.mockRestore();
    }
  });

  it("binds an ambiguous Check after the PR moves, then fails it closed without an orphan", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ ambiguousCreate: true });
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-stale-reconcile-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        await expect(instance.acquire("integrated-stale-reconcile-pool", acquisition(), actor))
          .rejects.toThrow("pending durable reconciliation");
        github.movePull();
        state.storage.sql.exec("UPDATE check_creation_intents SET next_attempt_at=0");
        await instance.alarm();
        return {
          gate: await instance.getGate(`123456789:7:${"1".repeat(40)}:ci-gate`, 1),
          outbox: await instance.listCheckOutbox(),
        };
      });
      expect(result.gate.state).toBe("hosted_failure");
      expect(result.outbox).toHaveLength(1);
      expect(result.outbox[0]).toMatchObject({ state: "delivered", conclusion: "failure", check_run_id: 99 });
      expect(github.posts()).toBe(1);
      expect(github.check()).toMatchObject({ status: "completed", conclusion: "failure" });
    } finally {
      github.request.mockRestore();
    }
  });

  it("commits no intent without a pre-existing durable alarm wake-up", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ failFirstRequest: true });
    const stub = env.RUNNER_POOLS_V2.getByName("intent-pre-network-crash-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        let outcome = "unexpected_success";
        try {
          await instance.acquire("intent-pre-network-crash-pool", acquisition(), actor);
        } catch (error) {
          outcome = error instanceof Error ? error.message : "unknown";
        }
        const before = state.storage.sql.exec<Record<string, SqlStorageValue>>(
          "SELECT post_attempted,attempts,state FROM check_creation_intents",
        ).one();
        const alarmBefore = await state.storage.getAlarm();
        state.storage.sql.exec("UPDATE check_creation_intents SET next_attempt_at=0");
        await instance.alarm();
        const after = state.storage.sql.exec<Record<string, SqlStorageValue>>(
          "SELECT post_attempted,attempts,state FROM check_creation_intents",
        ).one();
        const alarmAfter = await state.storage.getAlarm();
        return { outcome, before, after, alarmBefore, alarmAfter };
      });
      expect(result.outcome).toContain("pending durable reconciliation");
      expect(result.before).toMatchObject({ post_attempted: 1, attempts: 1, state: "pending" });
      expect(result.alarmBefore).not.toBeNull();
      expect(result.after).toMatchObject({ post_attempted: 1, attempts: 2, state: "pending" });
      expect(result.alarmAfter).not.toBeNull();
      expect(github.posts()).toBe(0);
    } finally {
      github.request.mockRestore();
    }
  });

  it("keeps an overdue ambiguous intent observable and scheduled for list-only reconciliation", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ ambiguousCreate: true, hiddenCreatedListings: 3 });
    const stub = env.RUNNER_POOLS_V2.getByName("intent-overdue-pool");
    try {
      const first = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        await expect(instance.acquire("intent-overdue-pool", acquisition(), actor))
          .rejects.toThrow("pending durable reconciliation");
        state.storage.sql.exec("UPDATE check_creation_intents SET deadline_at=0,next_attempt_at=0");
        await instance.alarm();
        const first = state.storage.sql.exec<Record<string, SqlStorageValue>>(
          "SELECT state,post_attempted,attempts,last_error,next_attempt_at,incident_at FROM check_creation_intents",
        ).one();
        return first;
      });
      await evictDurableObject(stub);
      const intent = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        state.storage.sql.exec("UPDATE check_creation_intents SET next_attempt_at=0");
        await instance.alarm();
        const second = state.storage.sql.exec<Record<string, SqlStorageValue>>(
          "SELECT state,post_attempted,attempts,last_error,next_attempt_at,incident_at FROM check_creation_intents",
        ).one();
        state.storage.sql.exec("UPDATE check_creation_intents SET next_attempt_at=0");
        await instance.alarm();
        return {
          second,
          final: state.storage.sql.exec<Record<string, SqlStorageValue>>(
            `SELECT state,post_attempted,attempts,last_error,next_attempt_at,incident_at,consumed_generation
             FROM check_creation_intents`,
          ).one(),
          audit: await instance.listAudit(),
          alarm: await state.storage.getAlarm(),
        };
      });
      expect(first).toMatchObject({ state: "pending", post_attempted: 1, attempts: 2 });
      expect(first.last_error).toMatch(/^creation reconciliation deadline exceeded:/);
      expect(first.incident_at).not.toBeNull();
      expect(Number(intent.second.next_attempt_at)).toBeGreaterThan(Number(first.next_attempt_at));
      expect(intent.final).toMatchObject({ state: "check_bound", post_attempted: 1, consumed_generation: 1 });
      expect(intent.audit.filter((entry) => entry.event_type === "check_creation_reconciliation_overdue")).toHaveLength(1);
      expect(intent.alarm).not.toBeNull();
      expect(github.posts()).toBe(1);
    } finally {
      github.request.mockRestore();
    }
  });

  it("recovers a committed ambiguous intent after real Durable Object eviction", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ ambiguousCreate: true });
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-eviction-reconcile-pool");
    let original: LocalMergeRunnerPoolGate | undefined;
    try {
      await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        original = instance;
        installTestAuthority(instance, authority);
        await expect(instance.acquire("integrated-eviction-reconcile-pool", acquisition(), actor))
          .rejects.toThrow("pending durable reconciliation");
        state.storage.sql.exec("UPDATE check_creation_intents SET next_attempt_at=0");
      });
      await evictDurableObject(stub);
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        expect(instance).not.toBe(original);
        installTestAuthority(instance, authority);
        await instance.alarm();
        return instance.getGate(`123456789:7:${"1".repeat(40)}:ci-gate`, 1);
      });
      expect(result).toMatchObject({ state: "hosted_selected", check_run_id: 99 });
      expect(github.posts()).toBe(1);
    } finally {
      github.request.mockRestore();
    }
  });

  it("integrates watchdog timeout through failure PATCH delivery", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-timeout-pool");
    try {
      const outbox = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        await instance.acquire("integrated-timeout-pool", acquisition(), actor);
        state.storage.sql.exec("UPDATE gates SET hosted_deadline_at=0");
        await instance.alarm();
        return instance.listCheckOutbox();
      });
      expect(outbox).toHaveLength(1);
      expect(outbox[0], String(outbox[0]?.last_error)).toMatchObject({ state: "delivered", conclusion: "failure" });
      expect(github.check()).toMatchObject({ status: "completed", conclusion: "failure" });
    } finally {
      github.request.mockRestore();
    }
  });

  it("gives a new owner a new generation and Check after terminal success or failure", async ({ expect }) => {
    for (const [suffix, terminalState, digest] of [
      ["success", "hosted_success", "b"],
      ["failure", "hosted_failure", "c"],
    ] as const) {
      const authority = await testAppAuthority();
      const github = githubHarness();
      const stub = env.RUNNER_POOLS_V2.getByName(`integrated-rerun-${suffix}`);
      try {
        const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
          installTestAuthority(instance, authority);
          const first = await instance.acquire(`integrated-rerun-${suffix}`, acquisition(), actor);
          await instance.transition(await localTransition(first, terminalState), actor);
          await instance.alarm();
          const rerunActor = { ...actor, runId: "84", runAttempt: "2", tokenId: `rerun-${suffix}` };
          const second = await instance.acquire(`integrated-rerun-${suffix}`, acquisition(), rerunActor);
          return { first: await instance.getGate(first.logical_key, first.generation), second };
        });
        expect(result.first.state).toBe(terminalState);
        expect(result.second).toMatchObject({ generation: 2, state: "hosted_selected", owner: "84:2" });
        expect(github.posts()).toBe(2);
        expect(github.checks().map((check) => check.id)).toEqual([99, 100]);
      } finally {
        github.request.mockRestore();
      }
    }
  });

  it("delivers immutable terminal outboxes for both generations when rerun starts before alarm", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-rerun-before-alarm-pool");
    try {
      await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        const first = await instance.acquire("integrated-rerun-before-alarm-pool", acquisition(), actor);
        await instance.transition(await localTransition(first, "hosted_success"), actor);
        const rerunActor = { ...actor, runId: "84", runAttempt: "2", tokenId: "rerun-before-alarm" };
        const second = await instance.acquire("integrated-rerun-before-alarm-pool", acquisition(), rerunActor);
        await instance.transition(await localTransition(second, "hosted_failure", rerunActor), rerunActor);
      });
      await evictDurableObject(stub);
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        await instance.alarm();
        const staleRetry = await instance.acquire("integrated-rerun-before-alarm-pool", acquisition(), actor);
        return { outbox: await instance.listCheckOutbox(), staleRetry };
      });
      expect(result.outbox).toHaveLength(2);
      expect(result.outbox.every((row) => row.state === "delivered")).toBe(true);
      expect(result.staleRetry).toMatchObject({ generation: 1, owner: "42:1", state: "hosted_success" });
      expect(github.posts()).toBe(2);
      expect(github.checks()).toMatchObject([
        { id: 99, status: "completed", conclusion: "success" },
        { id: 100, status: "completed", conclusion: "failure" },
      ]);
    } finally {
      github.request.mockRestore();
    }
  });

  it("allows exactly one takeover after durable expiry and prevents stale-owner ABA", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-expiry-takeover-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        const first = await instance.acquire("integrated-expiry-takeover-pool", acquisition(), actor);
        const owner2 = { ...actor, runId: "84", runAttempt: "1", tokenId: "owner-2" };
        const owner3 = { ...actor, runId: "126", runAttempt: "1", tokenId: "owner-3" };
        const activeAttempts = await Promise.allSettled([
          instance.acquire("integrated-expiry-takeover-pool", acquisition(), owner2),
          instance.acquire("integrated-expiry-takeover-pool", acquisition(), owner3),
        ]);
        const postsWhileActive = github.posts();
        state.storage.sql.exec(
          "UPDATE gates SET hosted_deadline_at=0 WHERE logical_key=? AND generation=?",
          first.logical_key,
          first.generation,
        );
        const takeoverAttempts = await Promise.allSettled([
          instance.acquire("integrated-expiry-takeover-pool", acquisition(), owner2),
          instance.acquire("integrated-expiry-takeover-pool", acquisition(), owner3),
        ]);
        const winner = takeoverAttempts.find((attempt) => attempt.status === "fulfilled");
        const stale = await instance.acquire("integrated-expiry-takeover-pool", acquisition(), actor)
          .then(() => "unexpected_success", (error: unknown) => error instanceof Error ? error.message : "unknown");
        return {
          first, activeAttempts, postsWhileActive, takeoverAttempts, winner, stale,
          outbox: await instance.listCheckOutbox(),
        };
      });
      expect(result.activeAttempts.every((attempt) => attempt.status === "rejected")).toBe(true);
      expect(result.postsWhileActive).toBe(1);
      expect(result.takeoverAttempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
      expect(result.takeoverAttempts.filter((attempt) => attempt.status === "rejected")).toHaveLength(1);
      expect(result.winner).toMatchObject({ status: "fulfilled", value: { generation: 2, state: "hosted_selected" } });
      expect(result.stale).toContain("active coordinator");
      expect(result.outbox).toHaveLength(1);
      expect(github.posts()).toBe(2);
    } finally {
      github.request.mockRestore();
    }
  });

  it("completes the old exact Check on base movement and preserves its outbox across eviction", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-base-movement-pool");
    try {
      await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        await instance.acquire("integrated-base-movement-pool", acquisition(), actor);
        github.moveBase();
        await instance.acquire("integrated-base-movement-pool", acquisition(), actor);
      });
      await evictDurableObject(stub);
      const outbox = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        await instance.alarm();
        return instance.listCheckOutbox();
      });
      expect(outbox).toHaveLength(1);
      expect(outbox[0]).toMatchObject({ generation: 1, state: "delivered", conclusion: "failure" });
      expect(github.checks()).toMatchObject([
        { id: 99, status: "completed", conclusion: "failure" },
        { id: 100, status: "in_progress", conclusion: null },
      ]);
    } finally {
      github.request.mockRestore();
    }
  });

  it("same-owner retry is idempotent under local merge policy", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const pool = "integrated-local-policy-retry";
    const stub = env.RUNNER_POOLS_V2.getByName(pool);
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        const first = await instance.acquire(pool, acquisition(), actor);
        github.recomputeMerge();
        const retry = await instance.acquire(pool, acquisition(), actor);
        return { first, retry };
      });
      expect(result.retry).toEqual(result.first);
      expect(github.posts()).toBe(1);
      expect(github.checks()).toHaveLength(1);
    } finally {
      github.request.mockRestore();
    }
  });

  it("terminalizes an active old tuple when a different owner acquires a real head movement", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-cross-owner-head-movement-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        const old = await instance.acquire("integrated-cross-owner-head-movement-pool", acquisition(), actor);
        github.moveHeadTuple();
        const movedActor = { ...actor, runId: "84", runAttempt: "1", tokenId: "moved-owner" };
        const moved = await instance.acquire("integrated-cross-owner-head-movement-pool", acquisition({
          head_sha: "8".repeat(40),
        }), movedActor);
        await instance.alarm();
        return {
          old: await instance.getGate(old.logical_key, old.generation),
          moved,
          outbox: await instance.listCheckOutbox(),
        };
      });
      expect(result.old.state).toBe("hosted_failure");
      expect(result.moved).toMatchObject({ generation: 1, state: "hosted_selected", owner: "84:1" });
      expect(result.moved.logical_key).toContain("8".repeat(40));
      expect(result.outbox).toHaveLength(1);
      expect(result.outbox[0]).toMatchObject({ state: "delivered", conclusion: "failure", check_run_id: 99 });
      expect(github.posts()).toBe(2);
      expect(github.checks()[0]).toMatchObject({ id: 99, status: "completed", conclusion: "failure" });
    } finally {
      github.request.mockRestore();
    }
  });

  it("reconciles stale intent A without superseding current tuple B and delivers both exact Checks", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ ambiguousCreate: true });
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-stale-a-current-b-pool");
    const movedActor = { ...actor, runId: "84", runAttempt: "1", tokenId: "current-b-owner" };
    let currentB!: GateSnapshot;
    try {
      await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        await expect(instance.acquire("integrated-stale-a-current-b-pool", acquisition(), actor))
          .rejects.toThrow("pending durable reconciliation");
        github.moveHeadTuple();
        currentB = await instance.acquire("integrated-stale-a-current-b-pool", acquisition({
          head_sha: "8".repeat(40),
        }), movedActor);
        state.storage.sql.exec(
          "UPDATE check_creation_intents SET next_attempt_at=0 WHERE owner='42:1'",
        );
      });
      await evictDurableObject(stub);
      const afterCommit = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate, state) => {
        installTestAuthority(instance, authority);
        const internal = instance as unknown as { reconcileCheckCreationIntents(now: number): Promise<void> };
        await internal.reconcileCheckCreationIntents(Date.now());
        const ownerC = { ...actor, runId: "126", runAttempt: "1", tokenId: "current-c-owner" };
        const cAttempt = await instance.acquire("integrated-stale-a-current-b-pool", acquisition({
          head_sha: "8".repeat(40),
        }), ownerC).then(() => "unexpected_success", (error: unknown) => error instanceof Error ? error.message : "unknown");
        return {
          current: await instance.getGate(currentB.logical_key, currentB.generation),
          stale: await instance.getGate(`123456789:7:${"1".repeat(40)}:ci-gate`, 1),
          outbox: await instance.listCheckOutbox(),
          actions: await instance.listControlActions(),
          staleAllocation: state.storage.sql.exec<Record<string, SqlStorageValue>>(
            `SELECT state FROM allocations WHERE logical_key=? AND generation=1`,
            `123456789:7:${"1".repeat(40)}:ci-gate`,
          ).one(),
          selectedCount: state.storage.sql.exec<{ count: number }>(
            "SELECT COUNT(*) AS count FROM gates WHERE repository_id='123456789' AND pr_number=7 AND state='hosted_selected'",
          ).one().count,
          cAttempt,
        };
      });
      expect(afterCommit.current).toMatchObject({ state: "hosted_selected", owner: "84:1" });
      expect(afterCommit.stale).toMatchObject({ state: "hosted_failure", owner: "42:1", check_run_id: 99 });
      expect(afterCommit.outbox).toHaveLength(1);
      expect(afterCommit.outbox[0]).toMatchObject({ state: "pending", conclusion: "failure", check_run_id: 99 });
      expect(afterCommit.actions).toHaveLength(1);
      expect(afterCommit.staleAllocation).toEqual({ state: "released" });
      expect(afterCommit.selectedCount).toBe(1);
      expect(afterCommit.cAttempt).toContain("active coordinator");

      await evictDurableObject(stub);
      const final = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        await instance.alarm();
        await instance.transition(await localTransition(currentB, "hosted_success", movedActor), movedActor);
        await instance.alarm();
        return instance.listCheckOutbox();
      });
      expect(final).toHaveLength(2);
      expect(final.every((row) => row.state === "delivered")).toBe(true);
      expect(github.posts()).toBe(2);
      expect(github.checks()).toMatchObject([
        { id: 99, status: "completed", conclusion: "failure" },
        { id: 100, status: "completed", conclusion: "success" },
      ]);
    } finally {
      github.request.mockRestore();
    }
  });

  it("coalesces only an exact owner marker and re-evaluates a different in-flight tuple", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness({ pauseFirstCreate: true });
    const stub = env.RUNNER_POOLS_V2.getByName("integrated-owner-distinct-marker-pool");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        const firstPromise = instance.acquire("integrated-owner-distinct-marker-pool", acquisition(), actor);
        await github.waitForFirstCreate();
        github.moveBase();
        const movedPromise = instance.acquire("integrated-owner-distinct-marker-pool", acquisition(), actor);
        github.releaseFirstCreate();
        const [first, moved] = await Promise.all([firstPromise, movedPromise]);
        return { first, moved, old: await instance.getGate(first.logical_key, first.generation) };
      });
      expect(result.first.generation).toBe(1);
      expect(result.moved.generation).toBe(2);
      expect(result.moved.check_run_id).toBe(100);
      expect(result.old.state).toBe("hosted_failure");
      expect(github.posts()).toBe(2);
    } finally {
      github.releaseFirstCreate();
      github.request.mockRestore();
    }
  });

  it("serializes same-owner concurrency and rejects a cross-pool alias without a second Check", async ({ expect }) => {
    const authority = await testAppAuthority();
    const github = githubHarness();
    const stub = env.RUNNER_POOLS_V2.getByName("repository:123456789-concurrency");
    try {
      const result = await runInDurableObject(stub, async (instance: LocalMergeRunnerPoolGate) => {
        installTestAuthority(instance, authority);
        const [first, retry] = await Promise.all([
          instance.acquire("authorized-pool", acquisition(), actor),
          instance.acquire("authorized-pool", acquisition(), actor),
        ]);
        let alias = "unexpected_success";
        try {
          await instance.acquire("attacker-pool", acquisition(), actor);
        } catch (error) {
          alias = error instanceof Error ? error.message : "unknown";
        }
        return { first, retry, alias };
      });
      expect(result.retry).toEqual(result.first);
      expect(result.alias).toContain("already bound to another runner pool");
      expect(github.posts()).toBe(1);
    } finally {
      github.request.mockRestore();
    }
  });
});
