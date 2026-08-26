import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTPayload,
} from "jose";
import type { OidcActor } from "./contracts";

const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_JWKS = createRemoteJWKSet(
  new URL("https://token.actions.githubusercontent.com/.well-known/jwks"),
);

export interface OidcTrust {
  audience: string;
  repository: string;
  repositoryId: string;
  workflowRef: string;
  jobWorkflowRef: string;
  eventName: string;
}

export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

function exactStringClaim(payload: JWTPayload, name: string, expected?: string): string {
  const value = payload[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthenticationError(`missing string claim: ${name}`);
  }
  if (expected !== undefined && value !== expected) {
    throw new AuthenticationError(`claim mismatch: ${name}`);
  }
  return value;
}

export async function verifyGitHubOidc(
  token: string,
  trust: OidcTrust,
  keySet: JWTVerifyGetKey = GITHUB_JWKS,
  currentDate?: Date,
): Promise<OidcActor> {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, keySet, {
      algorithms: ["RS256"],
      audience: trust.audience,
      issuer: GITHUB_ISSUER,
      currentDate,
      requiredClaims: [
        "sub",
        "jti",
        "repository",
        "repository_id",
        "workflow_ref",
        "job_workflow_ref",
        "run_id",
        "run_attempt",
        "event_name",
        "runner_environment",
      ],
      typ: "JWT",
    });
    if (protectedHeader.alg !== "RS256") {
      throw new AuthenticationError("unexpected OIDC algorithm");
    }
    exactStringClaim(payload, "event_name", trust.eventName);
    exactStringClaim(payload, "runner_environment", "github-hosted");
    return {
      repository: exactStringClaim(payload, "repository", trust.repository),
      repositoryId: exactStringClaim(payload, "repository_id", trust.repositoryId),
      workflowRef: exactStringClaim(payload, "workflow_ref", trust.workflowRef),
      jobWorkflowRef: exactStringClaim(payload, "job_workflow_ref", trust.jobWorkflowRef),
      runId: exactStringClaim(payload, "run_id"),
      runAttempt: exactStringClaim(payload, "run_attempt"),
      subject: exactStringClaim(payload, "sub"),
      tokenId: exactStringClaim(payload, "jti"),
    };
  } catch (error) {
    if (error instanceof AuthenticationError) throw error;
    if (error instanceof joseErrors.JOSEError) {
      throw new AuthenticationError("invalid GitHub OIDC token");
    }
    throw error;
  }
}
