import { exportJWK, importPKCS8, SignJWT } from "jose";
import { z } from "zod";
import type { OidcActor, PreparedCheck } from "./contracts";

const GITHUB_API = "https://api.github.com";
const GITHUB_API_VERSION = "2026-03-10";
const GITHUB_USER_AGENT = "self-hosted-ci-gate-service";
const RESPONSE_LIMIT = 128 * 1024;
const TOKEN_MAX_TTL_MS = 62 * 60 * 1_000;
const TOKEN_MIN_TTL_MS = 30 * 1_000;
const EXACT_PERMISSIONS = { checks: "write", metadata: "read" } as const;
export const MERGE_POLICY_VERSION = "local-ort-v1" as const;
export const RUNNER_IMAGE_POLICY = "ubuntu-24.04" as const;

const authoritySchema = z.strictObject({
  appId: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().positive()),
  installationId: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().positive()),
  repository: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
  repositoryId: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().int().positive()),
  keyFingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  privateKeyPem: z.string().min(1),
});

export interface CheckDeliveryEnv {
  GITHUB_APP_ID: string;
  GITHUB_APP_INSTALLATION_ID: string;
  GITHUB_REPOSITORY: string;
  GITHUB_REPOSITORY_ID: string;
  GITHUB_APP_KEY_FINGERPRINT: string;
  GITHUB_APP_PRIVATE_KEY_PEM: string;
}

export interface CheckDeliveryEvent {
  checkRunId: number;
  headSha: string;
  evidenceDigest: string;
  conclusion: "success" | "failure";
  preparationMarker: string;
}

export type CheckDeliveryResult =
  | { state: "delivered"; reconciled: boolean }
  | { state: "blocked"; error: string }
  | { state: "transient"; error: string; retryAt?: number };

export type CheckPreparationResult =
  | ({ state: "prepared"; reconciled: boolean; tuple_current: boolean } & PreparedCheck)
  | { state: "blocked"; error: string }
  | { state: "transient"; error: string; retryAt?: number };

export interface CheckPreparationEvent {
  repositoryId: string;
  prNumber: number;
  headSha: string;
  baseSha: string;
  mergePolicyVersion: typeof MERGE_POLICY_VERSION;
  actor: OidcActor;
}

export type PullRequestExpectation = Omit<CheckPreparationEvent, "baseSha" | "mergePolicyVersion">;

export interface CanonicalPullRequest {
  baseSha: string;
  headSha: string;
  mergePolicyVersion: typeof MERGE_POLICY_VERSION;
}

interface Authority {
  appId: number;
  installationId: number;
  repository: string;
  repositoryId: number;
  keyFingerprint: string;
  privateKeyPem: string;
}

interface GitHubResponse {
  status: number;
  value: Record<string, unknown> | null;
}

class TransientGitHubError extends Error {
  constructor(
    message: string,
    readonly retryAt?: number,
    readonly pollable = false,
  ) {
    super(message);
  }
}
class BlockingGitHubError extends Error {}

export class CanonicalPullRequestUnavailable extends Error {
  constructor(message: string, retryAt = Date.now() + 2_000) {
    super(message);
    this.name = `CanonicalPullRequestUnavailable:${Math.ceil(retryAt)}`;
  }
}

export class CanonicalPullRequestBlocked extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalPullRequestBlocked";
  }
}

const CANONICAL_READ_DELAYS_MS = [250, 500] as const;
const RATE_LIMIT_FALLBACK_MS = 60_000;

export async function resolveCanonicalPullRequest(
  rawEnv: CheckDeliveryEnv,
  event: PullRequestExpectation,
  request: typeof fetch = fetch,
  pause: (milliseconds: number) => Promise<void> = sleep,
): Promise<CanonicalPullRequest> {
  const authority = parseAuthority(rawEnv);
  validatePullRequestExpectation(event, authority);
  for (let attempt = 0; attempt <= CANONICAL_READ_DELAYS_MS.length; attempt += 1) {
    try {
      return await readCanonicalPullRequest(authority, event, request);
    } catch (error) {
      if (error instanceof BlockingGitHubError) {
        throw new CanonicalPullRequestBlocked(error.message);
      }
      if (!(error instanceof TransientGitHubError)) throw error;
      if (!error.pollable) {
        throw new CanonicalPullRequestUnavailable(error.message, error.retryAt);
      }
      if (attempt === CANONICAL_READ_DELAYS_MS.length) {
        throw new CanonicalPullRequestUnavailable(error.message);
      }
      await pause(CANONICAL_READ_DELAYS_MS[attempt]!);
    }
  }
  throw new CanonicalPullRequestUnavailable("canonical pull request resolution exhausted");
}

export async function prepareGitHubCheck(
  rawEnv: CheckDeliveryEnv,
  event: CheckPreparationEvent,
  request: typeof fetch = fetch,
  now = new Date(),
  allowCreate = true,
): Promise<CheckPreparationResult> {
  try {
    const authority = parseAuthority(rawEnv);
    validatePreparationEvent(event, authority);
    const token = await authenticate(authority, request, now);
    const marker = await derivePreparationMarker(event);
    if (allowCreate) await verifyCurrentPullRequest(authority, event, request);
    const existing = await findPreparedCheck(authority, token, event.headSha, marker, request);
    if (existing !== null) {
      return prepared(
        existing.id,
        event.headSha,
        true,
        allowCreate || await tupleIsCurrent(authority, event, request),
      );
    }
    if (!allowCreate) {
      return { state: "transient", error: "Check creation intent is not yet visible" };
    }

    try {
      const created = await githubJson(
        request,
        `${GITHUB_API}/repos/${authority.repository}/check-runs`,
        {
          method: "POST",
          headers: tokenHeaders(token),
          body: JSON.stringify({
            name: "ci-gate",
            head_sha: event.headSha,
            status: "in_progress",
            external_id: marker,
          }),
        },
        201,
      );
      assertPreparedCheck(created, event.headSha, marker, authority);
      return prepared(created.id as number, event.headSha, false, true);
    } catch (createError) {
      // A transport failure or retryable GitHub response may happen after the
      // Check was committed. Re-list by the server-derived marker before ever
      // attempting another create.
      const reconciled = await findPreparedCheck(
        authority,
        token,
        event.headSha,
        marker,
        request,
      );
      if (reconciled !== null) return prepared(reconciled.id, event.headSha, true, true);
      throw createError;
    }
  } catch (error) {
    if (error instanceof BlockingGitHubError || error instanceof z.ZodError) {
      return { state: "blocked", error: safeMessage(error) };
    }
    return {
      state: "transient",
      error: safeMessage(error),
      ...(error instanceof TransientGitHubError && error.retryAt !== undefined
        ? { retryAt: error.retryAt }
        : {}),
    };
  }
}

export async function deliverGitHubCheck(
  rawEnv: CheckDeliveryEnv,
  event: CheckDeliveryEvent,
  request: typeof fetch = fetch,
  now = new Date(),
): Promise<CheckDeliveryResult> {
  try {
    const authority = parseAuthority(rawEnv);
    validateEvent(event);
    const token = await authenticate(authority, request, now);
    const marker = `github-automation-evidence:${event.evidenceDigest}`;
    const before = await getCheck(authority, token, event.checkRunId, request);
    const beforeResult = classifyObserved(before, event, marker, authority);
    if (beforeResult !== null) return beforeResult;

    let patchAmbiguous = false;
    let retryAt: number | undefined;
    try {
      const patched = await githubJson(
        request,
        `${GITHUB_API}/repos/${authority.repository}/check-runs/${event.checkRunId}`,
        {
          method: "PATCH",
          headers: tokenHeaders(token),
          body: JSON.stringify({ external_id: marker, conclusion: event.conclusion }),
        },
        200,
      );
      assertExactCheck(patched, event, marker, authority);
      return { state: "delivered", reconciled: false };
    } catch (error) {
      if (error instanceof BlockingGitHubError) return { state: "blocked", error: error.message };
      if (error instanceof TransientGitHubError) retryAt = error.retryAt;
      patchAmbiguous = true;
    }

    if (patchAmbiguous) {
      try {
        const observed = await getCheck(authority, token, event.checkRunId, request);
        const reconciled = classifyObserved(observed, event, marker, authority);
        if (reconciled?.state === "delivered") return { state: "delivered", reconciled: true };
        if (reconciled?.state === "blocked") return reconciled;
      } catch (error) {
        if (error instanceof BlockingGitHubError) return { state: "blocked", error: error.message };
        if (error instanceof TransientGitHubError && error.retryAt !== undefined) {
          retryAt = Math.max(retryAt ?? 0, error.retryAt);
        }
      }
      return {
        state: "transient",
        error: "ambiguous Check Run PATCH was not reconciled",
        ...(retryAt !== undefined ? { retryAt } : {}),
      };
    }
    return { state: "transient", error: "Check Run delivery did not complete" };
  } catch (error) {
    if (error instanceof BlockingGitHubError || error instanceof z.ZodError) {
      return { state: "blocked", error: safeMessage(error) };
    }
    return {
      state: "transient",
      error: safeMessage(error),
      ...(error instanceof TransientGitHubError && error.retryAt !== undefined
        ? { retryAt: error.retryAt }
        : {}),
    };
  }
}

function parseAuthority(rawEnv: CheckDeliveryEnv): Authority {
  return authoritySchema.parse({
    appId: rawEnv.GITHUB_APP_ID,
    installationId: rawEnv.GITHUB_APP_INSTALLATION_ID,
    repository: rawEnv.GITHUB_REPOSITORY,
    repositoryId: rawEnv.GITHUB_REPOSITORY_ID,
    keyFingerprint: rawEnv.GITHUB_APP_KEY_FINGERPRINT,
    privateKeyPem: rawEnv.GITHUB_APP_PRIVATE_KEY_PEM,
  });
}

function validatePreparationEvent(event: CheckPreparationEvent, authority: Authority): void {
  validatePullRequestExpectation(event, authority);
  if (event.mergePolicyVersion !== MERGE_POLICY_VERSION) throw new BlockingGitHubError("merge policy mismatch");
}

function validatePullRequestExpectation(event: PullRequestExpectation, authority: Authority): void {
  if (
    event.repositoryId !== String(authority.repositoryId)
    || event.actor.repositoryId !== event.repositoryId
    || event.actor.repository !== authority.repository
  ) {
    throw new BlockingGitHubError("Check preparation repository authority mismatch");
  }
  if (!Number.isSafeInteger(event.prNumber) || event.prNumber < 1) {
    throw new BlockingGitHubError("Check preparation PR number is invalid");
  }
  if (!/^[0-9a-f]{40}$/.test(event.headSha)) throw new BlockingGitHubError("Check preparation SHA is invalid");
}

export async function derivePreparationMarker(event: CheckPreparationEvent): Promise<string> {
  const canonical = [
    "ci-gate-preparation-local-ort-v1",
    event.repositoryId,
    String(event.prNumber),
    event.headSha,
    event.baseSha,
    event.mergePolicyVersion,
    event.actor.runId,
    event.actor.runAttempt,
  ].join("\n");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `github-automation-preparation:${hex}`;
}

async function verifyCurrentPullRequest(
  authority: Authority,
  event: CheckPreparationEvent,
  request: typeof fetch,
): Promise<void> {
  const canonical = await readCanonicalPullRequest(authority, event, request);
  if (canonical.baseSha !== event.baseSha || canonical.headSha !== event.headSha
    || canonical.mergePolicyVersion !== event.mergePolicyVersion) {
    throw new BlockingGitHubError("current pull request tuple mismatch");
  }
}

async function readCanonicalPullRequest(
  authority: Authority,
  event: PullRequestExpectation,
  request: typeof fetch,
): Promise<CanonicalPullRequest> {
  const firstPull = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}/pulls/${event.prNumber}`,
    { headers: publicHeaders() },
    200,
  );
  const head = objectValue(firstPull.head);
  const base = objectValue(firstPull.base);
  const baseRepo = objectValue(base?.repo);
  const baseRef = base?.ref;
  if (
    firstPull.number !== event.prNumber
    || firstPull.state !== "open"
    || head?.sha !== event.headSha
    || baseRepo?.id !== authority.repositoryId
    || baseRepo?.full_name !== authority.repository
    || typeof baseRef !== "string"
    || !validBranchRef(baseRef)
  ) {
    throw new BlockingGitHubError("current pull request tuple mismatch");
  }
  const firstRef = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}/git/ref/heads/${encodeURIComponent(baseRef)}`,
    { headers: publicHeaders() },
    200,
  );
  const refObject = objectValue(firstRef.object);
  const baseSha = refObject?.sha;
  if (
    firstRef.ref !== `refs/heads/${baseRef}`
    || refObject?.type !== "commit"
    || typeof baseSha !== "string"
    || !/^[0-9a-f]{40}$/.test(baseSha)
  ) {
    throw new BlockingGitHubError("canonical base ref is invalid");
  }
  const secondPull = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}/pulls/${event.prNumber}`,
    { headers: publicHeaders() },
    200,
  );
  const secondHead = objectValue(secondPull.head);
  const secondBase = objectValue(secondPull.base);
  const secondRepo = objectValue(secondBase?.repo);
  const secondRefName = secondBase?.ref;
  if (
    secondPull.number !== event.prNumber
    || secondPull.state !== "open"
    || secondHead?.sha !== event.headSha
    || secondRepo?.id !== authority.repositoryId
    || secondRepo?.full_name !== authority.repository
    || secondRefName !== baseRef
  ) {
    throw new TransientGitHubError("pull request changed during canonical read", undefined, true);
  }
  const secondGitRef = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}/git/ref/heads/${encodeURIComponent(baseRef)}`,
    { headers: publicHeaders() },
    200,
  );
  const secondRefObject = objectValue(secondGitRef.object);
  if (secondGitRef.ref !== `refs/heads/${baseRef}` || secondRefObject?.type !== "commit"
    || secondRefObject.sha !== baseSha) {
    throw new TransientGitHubError("base ref changed during canonical read", undefined, true);
  }
  return { baseSha, headSha: event.headSha, mergePolicyVersion: MERGE_POLICY_VERSION };
}

function validBranchRef(value: string): boolean {
  return value.length > 0
    && value.length <= 255
    && !value.startsWith("/")
    && !value.endsWith("/")
    && !value.endsWith(".")
    && !value.includes("..")
    && !value.includes("@{")
    && !/[\u0000-\u0020~^:?*[\\]/.test(value)
    && value.split("/").every((part) => part !== "." && part !== ".." && !part.endsWith(".lock"));
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function prepared(
  checkRunId: number,
  checkTargetSha: string,
  reconciled: boolean,
  tupleCurrent: boolean,
): CheckPreparationResult {
  return {
    state: "prepared",
    reconciled,
    tuple_current: tupleCurrent,
    check_run_id: checkRunId,
    check_target_sha: checkTargetSha,
  };
}

async function tupleIsCurrent(
  authority: Authority,
  event: CheckPreparationEvent,
  request: typeof fetch,
): Promise<boolean> {
  try {
    await verifyCurrentPullRequest(authority, event, request);
    return true;
  } catch (error) {
    if (error instanceof BlockingGitHubError) return false;
    throw error;
  }
}

async function findPreparedCheck(
  authority: Authority,
  token: string,
  headSha: string,
  marker: string,
  request: typeof fetch,
): Promise<{ id: number } | null> {
  const matches: Record<string, unknown>[] = [];
  let page = 1;
  let total = Number.POSITIVE_INFINITY;
  while ((page - 1) * 100 < total) {
    const listed = await githubJson(
      request,
      `${GITHUB_API}/repos/${authority.repository}/commits/${headSha}/check-runs?check_name=ci-gate&filter=all&per_page=100&page=${page}`,
      { headers: tokenHeaders(token) },
      200,
    );
    if (!Number.isSafeInteger(listed.total_count) || !Array.isArray(listed.check_runs)) {
      throw new TransientGitHubError("GitHub Check Run list response is invalid");
    }
    total = listed.total_count as number;
    matches.push(...listed.check_runs.filter((value) => {
      if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
      const check = value as Record<string, unknown>;
      return check.external_id === marker;
    }) as Record<string, unknown>[]);
    if (listed.check_runs.length === 0) break;
    page += 1;
  }
  if (matches.length > 1) throw new BlockingGitHubError("duplicate Check preparation marker");
  if (matches.length === 0) return null;
  const match = matches[0]!;
  assertPreparedCheck(match, headSha, marker, authority);
  return { id: match.id as number };
}

function assertPreparedCheck(
  observed: Record<string, unknown>,
  headSha: string,
  marker: string,
  authority: Authority,
): void {
  if (
    !Number.isSafeInteger(observed.id)
    || (observed.id as number) < 1
    || observed.name !== "ci-gate"
    || observed.head_sha !== headSha
    || observed.external_id !== marker
    || observed.status !== "in_progress"
    || observed.conclusion !== null
    || !hasExpectedApp(observed, authority.appId)
  ) {
    throw new BlockingGitHubError("prepared Check Run identity mismatch");
  }
}

function validateEvent(event: CheckDeliveryEvent): void {
  if (!Number.isSafeInteger(event.checkRunId) || event.checkRunId < 1) {
    throw new BlockingGitHubError("check_run_id is invalid");
  }
  if (!/^[0-9a-f]{40}$/.test(event.headSha) || !/^[0-9a-f]{64}$/.test(event.evidenceDigest)) {
    throw new BlockingGitHubError("Check Run evidence is invalid");
  }
  if (!/^github-automation-preparation:[0-9a-f]{64}$/.test(event.preparationMarker)) {
    throw new BlockingGitHubError("Check Run preparation marker is invalid");
  }
  if (event.conclusion !== "success" && event.conclusion !== "failure") {
    throw new BlockingGitHubError("Check Run conclusion is invalid");
  }
}

async function authenticate(
  authority: Authority,
  request: typeof fetch,
  now: Date,
): Promise<string> {
  let privateKey: CryptoKey;
  try {
    privateKey = await importPKCS8(authority.privateKeyPem, "RS256", { extractable: true });
  } catch {
    throw new BlockingGitHubError("GitHub App private key is malformed");
  }
  if (await spkiFingerprint(privateKey) !== authority.keyFingerprint) {
    throw new BlockingGitHubError("GitHub App key fingerprint mismatch");
  }
  const issuedAt = Math.floor(now.getTime() / 1_000) - 60;
  const jwt = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuer(String(authority.appId))
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + 600)
    .sign(privateKey);
  const appHeaders = tokenHeaders(jwt);
  const app = await githubJson(request, `${GITHUB_API}/app`, { headers: appHeaders }, 200);
  if (app.id !== authority.appId || !exactPermissions(app.permissions)) {
    throw new BlockingGitHubError("authenticated GitHub App authority mismatch");
  }
  const installation = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}/installation`,
    { headers: appHeaders },
    200,
  );
  if (
    installation.id !== authority.installationId
    || installation.app_id !== authority.appId
    || installation.repository_selection !== "selected"
    || installation.suspended_at !== null
    || !exactPermissions(installation.permissions)
  ) {
    throw new BlockingGitHubError("GitHub App installation authority mismatch");
  }
  const minted = await githubJson(
    request,
    `${GITHUB_API}/app/installations/${authority.installationId}/access_tokens`,
    {
      method: "POST",
      headers: appHeaders,
      body: JSON.stringify({
        repository_ids: [authority.repositoryId],
        permissions: EXACT_PERMISSIONS,
      }),
    },
    201,
  );
  const token = minted.token;
  const expiresAt = typeof minted.expires_at === "string" ? Date.parse(minted.expires_at) : Number.NaN;
  const repositories = minted.repositories;
  if (
    typeof token !== "string"
    || token.length === 0
    || /\s/.test(token)
    || !Number.isFinite(expiresAt)
    || expiresAt <= now.getTime() + TOKEN_MIN_TTL_MS
    || expiresAt > now.getTime() + TOKEN_MAX_TTL_MS
    || !exactPermissions(minted.permissions)
    || !Array.isArray(repositories)
    || repositories.length !== 1
    || !exactRepository(repositories[0], authority)
  ) {
    throw new BlockingGitHubError("minted installation token scope mismatch");
  }
  const repository = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}`,
    { headers: tokenHeaders(token) },
    200,
  );
  if (!exactRepository(repository, authority)) {
    throw new BlockingGitHubError("installation token repository identity mismatch");
  }
  return token;
}

async function spkiFingerprint(privateKey: CryptoKey): Promise<string> {
  const privateJwk = await exportJWK(privateKey);
  if (privateJwk.kty !== "RSA" || typeof privateJwk.n !== "string" || typeof privateJwk.e !== "string") {
    throw new BlockingGitHubError("GitHub App private key is not RSA");
  }
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: privateJwk.n, e: privateJwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"],
  );
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  if (!(spki instanceof ArrayBuffer)) throw new BlockingGitHubError("public key export failed");
  const digest = await crypto.subtle.digest("SHA-256", spki);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function getCheck(
  authority: Authority,
  token: string,
  checkRunId: number,
  request: typeof fetch,
): Promise<Record<string, unknown>> {
  const observed = await githubJson(
    request,
    `${GITHUB_API}/repos/${authority.repository}/check-runs/${checkRunId}`,
    { headers: tokenHeaders(token) },
    200,
  );
  if (observed.id !== checkRunId) throw new BlockingGitHubError("Check Run read returned another ID");
  return observed;
}

function classifyObserved(
  observed: Record<string, unknown>,
  event: CheckDeliveryEvent,
  marker: string,
  authority: Authority,
): CheckDeliveryResult | null {
  if (
    observed.id !== event.checkRunId
    || observed.head_sha !== event.headSha
    || observed.name !== "ci-gate"
    || !hasExpectedApp(observed, authority.appId)
  ) {
    return { state: "blocked", error: "Check Run target identity mismatch" };
  }
  if (observed.external_id === marker) {
    if (observed.status === "completed" && observed.conclusion === event.conclusion) {
      return { state: "delivered", reconciled: true };
    }
    return { state: "blocked", error: "evidence marker exists with conflicting conclusion" };
  }
  if (
    observed.external_id !== event.preparationMarker
    || observed.status !== "in_progress"
    || observed.conclusion !== null
  ) {
    return { state: "blocked", error: "Check Run contains different terminal evidence" };
  }
  return null;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function assertExactCheck(
  observed: Record<string, unknown>,
  event: CheckDeliveryEvent,
  marker: string,
  authority: Authority,
): void {
  if (
    observed.id !== event.checkRunId
    || observed.head_sha !== event.headSha
    || observed.name !== "ci-gate"
    || !hasExpectedApp(observed, authority.appId)
    || observed.external_id !== marker
    || observed.status !== "completed"
    || observed.conclusion !== event.conclusion
  ) {
    throw new TransientGitHubError("Check Run PATCH response did not confirm exact evidence");
  }
}

function hasExpectedApp(observed: Record<string, unknown>, appId: number): boolean {
  const app = observed.app;
  return app !== null && typeof app === "object" && !Array.isArray(app)
    && (app as Record<string, unknown>).id === appId;
}

async function githubJson(
  request: typeof fetch,
  url: string,
  init: RequestInit,
  expectedStatus: number,
  retry: { transientStatuses?: readonly number[]; pollableStatuses?: readonly number[] } = {},
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await request(url, init);
  } catch {
    throw new TransientGitHubError("GitHub API transport failed");
  }
  const rateLimited = response.status === 403 && (
    response.headers.has("retry-after") || response.headers.get("x-ratelimit-remaining") === "0"
  );
  const pollable = retry.pollableStatuses?.includes(response.status) === true;
  const retryable = pollable || retry.transientStatuses?.includes(response.status) === true
    || rateLimited || response.status === 408 || response.status === 409 || response.status === 425
    || response.status === 429 || response.status >= 500;
  if (response.status !== expectedStatus) {
    throw retryable
      ? new TransientGitHubError(
        `GitHub API transient HTTP ${response.status}`,
        rateLimited || response.status === 429
          ? retryAfter(response.headers) ?? Date.now() + RATE_LIMIT_FALLBACK_MS
          : retryAfter(response.headers),
        pollable,
      )
      : new BlockingGitHubError(`GitHub API rejected authority with HTTP ${response.status}`);
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && Number.parseInt(declared, 10) > RESPONSE_LIMIT) {
    throw new TransientGitHubError("GitHub API response exceeds limit");
  }
  const body = await boundedResponseBody(response);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body)) as unknown;
  } catch {
    throw new TransientGitHubError("GitHub API response is invalid JSON");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TransientGitHubError("GitHub API response is not an object");
  }
  return value as Record<string, unknown>;
}

async function boundedResponseBody(response: Response): Promise<ArrayBuffer> {
  if (response.body === null) return new ArrayBuffer(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    size += part.value.byteLength;
    if (size > RESPONSE_LIMIT) {
      await reader.cancel();
      throw new TransientGitHubError("GitHub API response exceeds limit");
    }
    chunks.push(part.value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body.buffer;
}

function retryAfter(headers: Headers): number | undefined {
  const retry = headers.get("retry-after");
  if (retry !== null) {
    const seconds = Number(retry);
    if (Number.isFinite(seconds) && seconds >= 0) return Date.now() + seconds * 1_000;
    const date = Date.parse(retry);
    if (Number.isFinite(date)) return date;
  }
  const reset = Number(headers.get("x-ratelimit-reset"));
  return Number.isFinite(reset) && reset > 0 ? reset * 1_000 : undefined;
}

function tokenHeaders(token: string): HeadersInit {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "content-type": "application/json",
    "user-agent": GITHUB_USER_AGENT,
    "x-github-api-version": GITHUB_API_VERSION,
  };
}

function publicHeaders(): HeadersInit {
  return {
    accept: "application/vnd.github+json",
    "content-type": "application/json",
    "user-agent": GITHUB_USER_AGENT,
    "x-github-api-version": GITHUB_API_VERSION,
  };
}

function exactPermissions(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const entries = Object.entries(value);
  return entries.length === 2
    && entries.every(([key, permission]) => EXACT_PERMISSIONS[key as keyof typeof EXACT_PERMISSIONS] === permission);
}

function exactRepository(value: unknown, authority: Authority): boolean {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (value as Record<string, unknown>).id === authority.repositoryId
    && (value as Record<string, unknown>).full_name === authority.repository;
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 512) : "unknown GitHub delivery error";
}
