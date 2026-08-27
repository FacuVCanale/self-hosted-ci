import { AuthenticationError, verifyGitHubOidc } from "./auth";
import { activationModeSchema, runnerPoolIdSchema } from "./contracts";
import { GateConflict, GateFenced, LocalMergeRunnerPoolGate } from "./runner-pool-gate";
import { CanonicalPullRequestBlocked, CanonicalPullRequestUnavailable } from "./github-checks";
import { ZodError } from "zod";

export {
  LocalMergeRunnerPoolGate,
} from "./runner-pool-gate";
export { RunnerPoolGate } from "./legacy-runner-pool-gate";

const MAX_BODY_BYTES = 32 * 1024;

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

async function boundedBody(request: Request): Promise<string> {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number.parseInt(declared, 10) > MAX_BODY_BYTES) {
    throw new GateConflict("request body exceeds limit");
  }
  if (request.body === null) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    size += part.value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new GateConflict("request body exceeds limit");
    }
    chunks.push(part.value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
}

function parseJson(body: string): unknown {
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new GateConflict("request body must be valid JSON");
  }
}

function bearer(request: Request): string {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.startsWith("Bearer ")) {
    throw new AuthenticationError("missing bearer token");
  }
  return authorization.slice(7);
}

function route(url: URL): { poolId: string; operation: string } | null {
  const match = /^\/v1\/pools\/([^/]+)\/(gates|gates\/transition|control-actions\/ack)$/.exec(
    url.pathname,
  );
  if (match === null) return null;
  return {
    poolId: runnerPoolIdSchema.parse(decodeURIComponent(match[1]!)),
    operation: match[2]!,
  };
}

function log(level: "info" | "warn" | "error", event: string, detail: Record<string, unknown>): void {
  console.log(JSON.stringify({ level, event, timestamp: new Date().toISOString(), ...detail }));
}

export function classifyRequestError(error: unknown, now = Date.now()): {
  status: number;
  code: string;
  headers: HeadersInit;
} {
  const errorName = error !== null && typeof error === "object" && "name" in error
    && typeof error.name === "string"
    ? error.name
    : null;
  const retryableMatch = errorName === null
    ? null
    : /^CanonicalPullRequestUnavailable:(\d{13})$/.exec(errorName);
  const retryableCanonical = retryableMatch !== null;
  const blockedCanonical = error instanceof CanonicalPullRequestBlocked
    || errorName === "CanonicalPullRequestBlocked";
  if (retryableCanonical) {
    const retryAt = Number(retryableMatch[1]);
    const retryAfterSeconds = Math.max(1, Math.ceil((retryAt - now) / 1_000));
    return {
      status: 503,
      code: "canonical_pull_request_unavailable",
      headers: { "retry-after": String(retryAfterSeconds) },
    };
  }
  if (error instanceof AuthenticationError) return { status: 401, code: "unauthorized", headers: {} };
  if (blockedCanonical) return { status: 409, code: "canonical_pull_request_blocked", headers: {} };
  if (error instanceof GateFenced || errorName === "GateFenced") {
    return { status: 409, code: "fenced", headers: {} };
  }
  if (error instanceof GateConflict || error instanceof ZodError
    || errorName === "GateConflict" || errorName === "ZodError") {
    return { status: 400, code: "invalid_request", headers: {} };
  }
  return { status: 500, code: "internal_error", headers: {} };
}

export async function handleRequest(request: Request, env: Cloudflare.Env): Promise<Response> {
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);
    const activation = activationModeSchema.safeParse(env.ACTIVATION_MODE);
    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        status: activation.success ? "ok" : "misconfigured",
        environment: env.ENVIRONMENT,
        activation_mode: activation.success ? activation.data : "invalid",
      }, activation.success ? 200 : 500);
    }
    if (!activation.success || activation.data !== "active") {
      return json({ error: "environment_inert", request_id: requestId }, 503);
    }
    if (request.method !== "POST") return json({ error: "not_found", request_id: requestId }, 404);

    try {
      const matched = route(url);
      if (matched === null) return json({ error: "not_found", request_id: requestId }, 404);
      const body = await boundedBody(request);
      const payload = parseJson(body);
      const stub = env.RUNNER_POOLS_V2.getByName(`repository:${env.GITHUB_REPOSITORY_ID}`);
      const actor = await verifyGitHubOidc(bearer(request), {
        audience: env.OIDC_AUDIENCE,
        repository: env.OIDC_REPOSITORY,
        repositoryId: env.OIDC_REPOSITORY_ID,
        workflowRef: env.OIDC_WORKFLOW_REF,
        jobWorkflowRef: env.OIDC_JOB_WORKFLOW_REF,
        eventName: env.OIDC_EVENT_NAME,
      });
      if (matched.poolId !== env.RUNNER_POOL_ID) throw new GateConflict("runner pool is not authorized");
      const result = matched.operation === "gates"
        ? await stub.acquire(matched.poolId, payload, actor)
        : matched.operation === "gates/transition"
          ? await stub.transition(payload, actor)
          : await stub.acknowledgeControlAction(payload, actor);
      log("info", "request_complete", {
        request_id: requestId,
        operation: matched.operation,
        runner_pool_id: matched.poolId,
        status: 200,
      });
      return json(result);
    } catch (error) {
      const { status, code, headers } = classifyRequestError(error);
      log(status >= 500 ? "error" : "warn", "request_failed", {
        request_id: requestId,
        status,
        code,
        error_type: error instanceof Error ? error.name : "unknown",
      });
      return json(
        { error: code, request_id: requestId },
        status,
        headers,
      );
    }
}

export default { fetch: handleRequest } satisfies ExportedHandler<Cloudflare.Env>;
