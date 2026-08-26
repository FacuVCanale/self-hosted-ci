import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, it } from "vitest";
import type { OidcActor } from "../src/contracts";
import { RunnerPoolGate } from "../src/runner-pool-gate";

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
    base_sha: "2".repeat(40),
    tested_merge_sha: "3".repeat(40),
    check_run_id: 99,
    ...overrides,
  };
}

describe("hosted-only RunnerPoolGate", () => {
  it("derives logical_key and creates exactly one hosted dispatch idempotently", async ({ expect }) => {
    const stub = env.RUNNER_POOLS.getByName("hosted-pool");
    const first = await stub.acquire("hosted-pool", acquisition(), actor);
    const retry = await stub.acquire("hosted-pool", acquisition(), actor);
    expect(first).toEqual(retry);
    expect(first.logical_key).toBe(`123456789:7:${"1".repeat(40)}:ci-gate`);
    expect(first.state).toBe("hosted_selected");
    expect(first.owner).toBe("42:1");
    const actions = await stub.listControlActions();
    expect(actions).toHaveLength(1);
    expect(actions[0]?.kind).toBe("dispatch_hosted");
  });

  it("rejects caller logical keys and conflicting check invariants", async ({ expect }) => {
    const stub = env.RUNNER_POOLS.getByName("invariants-pool");
    await stub.acquire("invariants-pool", acquisition(), actor);
    const callerKey = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      try {
        await instance.acquire("invariants-pool", acquisition({ logical_key: "caller-controlled" }), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.name : "unknown";
      }
    });
    expect(callerKey).toBe("ZodError");
    const conflictingCheck = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      try {
        await instance.acquire("invariants-pool", acquisition({ check_run_id: 100 }), actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(conflictingCheck).toContain("check or owner invariants");
  });

  it("allows one hosted terminal winner and fences the competing CAS", async ({ expect }) => {
    const stub = env.RUNNER_POOLS.getByName("winner-pool");
    const gate = await stub.acquire("winner-pool", acquisition(), actor);
    const committed = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      const winner = await instance.transition({
        logical_key: gate.logical_key,
        generation: gate.generation,
        expected_version: gate.version,
        from_state: "hosted_selected",
        to_state: "hosted_success",
        evidence_digest: "a".repeat(64),
      }, actor);
      return { winner, outbox: await instance.listCheckOutbox() };
    });
    expect(committed.winner.state).toBe("hosted_success");
    expect(committed.outbox).toHaveLength(1);
    expect(committed.outbox[0]?.state).toBe("pending");
    expect(committed.outbox[0]?.attempts).toBe(0);
    const loser = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      try {
        await instance.transition({
          logical_key: gate.logical_key,
          generation: gate.generation,
          expected_version: gate.version,
          from_state: "hosted_selected",
          to_state: "hosted_failure",
          evidence_digest: "b".repeat(64),
        }, actor);
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

  it("returns an identical terminal retry and conflicts different evidence", async ({ expect }) => {
    const stub = env.RUNNER_POOLS.getByName("terminal-retry-pool");
    const gate = await stub.acquire("terminal-retry-pool", acquisition(), actor);
    const transition = {
      logical_key: gate.logical_key,
      generation: gate.generation,
      expected_version: gate.version,
      from_state: "hosted_selected" as const,
      to_state: "hosted_success" as const,
      evidence_digest: "e".repeat(64),
    };
    const committed = await stub.transition(transition, actor);
    await expect(stub.transition(transition, actor)).resolves.toEqual(committed);
    const conflict = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      try {
        await instance.transition({
          ...transition,
          to_state: "hosted_failure",
          evidence_digest: "f".repeat(64),
        }, actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(conflict).toContain("conflicts with committed evidence");
  });

  it("lets the OIDC coordinator acknowledge hosted actions", async ({ expect }) => {
    const stub = env.RUNNER_POOLS.getByName("ack-pool");
    await stub.acquire("ack-pool", acquisition(), actor);
    const action = (await stub.listControlActions())[0];
    await expect(stub.acknowledgeControlAction({
      action_id: action?.action_id,
      outcome: "accepted",
    }, actor)).resolves.toEqual({ accepted: true });
  });

  it("supersedes the prior generation on base movement and fences late completion and ACK", async ({ expect }) => {
    const stub = env.RUNNER_POOLS.getByName("base-movement-pool");
    const oldGate = await stub.acquire("base-movement-pool", acquisition(), actor);
    const oldAction = (await stub.listControlActions())[0];
    const current = await stub.acquire(
      "base-movement-pool",
      acquisition({ base_sha: "4".repeat(40), tested_merge_sha: "5".repeat(40) }),
      actor,
    );
    expect(current.generation).toBe(oldGate.generation + 1);
    expect((await stub.getGate(oldGate.logical_key, oldGate.generation)).state).toBe("superseded");

    const lateCompletion = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      try {
        await instance.transition({
          logical_key: oldGate.logical_key,
          generation: oldGate.generation,
          expected_version: oldGate.version,
          from_state: "hosted_selected",
          to_state: "hosted_success",
          evidence_digest: "c".repeat(64),
        }, actor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(lateCompletion).toContain("not latest");

    const lateAck = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
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
    const stub = env.RUNNER_POOLS.getByName("cross-owner-pool");
    const gate = await stub.acquire("cross-owner-pool", acquisition(), actor);
    const action = (await stub.listControlActions())[0];
    const otherActor = { ...actor, runId: "43", tokenId: "oidc-jti-2", subject: `${actor.subject}:other-run` };

    const transition = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      try {
        await instance.transition({
          logical_key: gate.logical_key,
          generation: gate.generation,
          expected_version: gate.version,
          from_state: "hosted_selected",
          to_state: "hosted_failure",
          evidence_digest: "d".repeat(64),
        }, otherActor);
        return "unexpected_success";
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(transition).toContain("another OIDC coordinator");

    const ack = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
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
});
