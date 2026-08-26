import { AuthenticationError, verifyGitHubOidc } from "./auth";
import { activationModeSchema, runnerPoolIdSchema } from "./contracts";
import { GateConflict, GateFenced, RunnerPoolGate } from "./runner-pool-gate";
import { ZodError } from "zod";

export { RunnerPoolGate } from "./runner-pool-gate";

const MAX_BODY_BYTES = 32 * 1024;

function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
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
      const stub = env.RUNNER_POOLS.getByName(matched.poolId);
      const actor = await verifyGitHubOidc(bearer(request), {
        audience: env.OIDC_AUDIENCE,
        repository: env.OIDC_REPOSITORY,
        repositoryId: env.OIDC_REPOSITORY_ID,
        workflowRef: env.OIDC_WORKFLOW_REF,
        jobWorkflowRef: env.OIDC_JOB_WORKFLOW_REF,
      });
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
      const status = error instanceof AuthenticationError
        ? 401
        : error instanceof GateFenced
          ? 409
          : error instanceof GateConflict || error instanceof ZodError
            ? 400
            : 500;
      const code = error instanceof AuthenticationError
        ? "unauthorized"
        : error instanceof GateFenced
          ? "fenced"
          : error instanceof GateConflict || error instanceof ZodError
            ? "invalid_request"
            : "internal_error";
      log(status >= 500 ? "error" : "warn", "request_failed", {
        request_id: requestId,
        status,
        code,
        error_type: error instanceof Error ? error.name : "unknown",
      });
      return json({ error: code, request_id: requestId }, status);
    }
}

export default { fetch: handleRequest } satisfies ExportedHandler<Cloudflare.Env>;
