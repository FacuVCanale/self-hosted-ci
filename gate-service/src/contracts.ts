import { z } from "zod";

const sha = z.string().regex(/^[0-9a-f]{40}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const positiveInteger = z.number().int().positive();

export const activationModeSchema = z.enum(["active", "inert"]);
export const runnerPoolIdSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/);

export const acquireGateSchema = z.strictObject({
  repository_id: z.string().regex(/^\d+$/),
  pr_number: positiveInteger,
  head_sha: sha,
  base_sha: sha,
  tested_merge_sha: sha,
  check_run_id: positiveInteger,
});

export const transitionGateSchema = z.strictObject({
  logical_key: z.string().min(1).max(256),
  generation: positiveInteger,
  expected_version: positiveInteger,
  from_state: z.literal("hosted_selected"),
  to_state: z.enum(["hosted_success", "hosted_failure"]),
  evidence_digest: digest,
});

export const acknowledgeActionSchema = z.strictObject({
  action_id: z.string().uuid(),
  outcome: z.enum(["accepted", "completed", "failed"]),
});

export type GateState = "hosted_selected" | "hosted_success" | "hosted_failure" | "superseded";

export interface OidcActor {
  repository: string;
  repositoryId: string;
  workflowRef: string;
  jobWorkflowRef: string;
  runId: string;
  runAttempt: string;
  subject: string;
  tokenId: string;
}

export interface GateSnapshot {
  logical_key: string;
  generation: number;
  version: number;
  state: GateState;
  runner_pool_id: string;
  owner: string;
  check_run_id: number;
  evidence_digest: string | null;
}

export function deriveLogicalKey(repositoryId: string, prNumber: number, headSha: string): string {
  return `${repositoryId}:${prNumber}:${headSha}:ci-gate`;
}
