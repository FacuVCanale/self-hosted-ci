import { DurableObject } from "cloudflare:workers";
import {
  acknowledgeActionSchema,
  acquireGateSchema,
  deriveLogicalKey,
  transitionGateSchema,
  type GateSnapshot,
  type GateState,
  type OidcActor,
} from "./contracts";
import {
  deliverGitHubCheck,
  derivePreparationMarker,
  prepareGitHubCheck,
  resolveCanonicalTestedMerge,
  type CheckDeliveryEvent,
} from "./github-checks";

interface GateRow extends Record<string, SqlStorageValue> {
  logical_key: string;
  generation: number;
  version: number;
  state: GateState;
  runner_pool_id: string;
  repository_id: string;
  pr_number: number;
  head_sha: string;
  base_sha: string;
  tested_merge_sha: string;
  check_run_id: number;
  owner: string;
  evidence_digest: string | null;
  preparation_marker: string;
  hosted_deadline_at: number | null;
  created_at: number;
  updated_at: number;
}

interface OutboxRow extends Record<string, SqlStorageValue> {
  outbox_key: string;
  logical_key: string;
  generation: number;
  check_run_id: number;
  conclusion: "success" | "failure";
  evidence_digest: string;
  head_sha: string;
  preparation_marker: string;
  attempts: number;
  next_attempt_at: number;
}

interface CheckCreationIntentRow extends Record<string, SqlStorageValue> {
  intent_key: string;
  marker: string;
  repository_id: string;
  pr_number: number;
  head_sha: string;
  base_sha: string;
  tested_merge_sha: string;
  owner: string;
  actor_subject: string;
  state: "pending" | "check_bound" | "blocked";
  post_attempted: number;
  check_run_id: number | null;
  deadline_at: number;
  next_attempt_at: number;
  attempts: number;
  last_error: string | null;
  consumed_generation: number | null;
  incident_at: number | null;
  created_at: number;
  updated_at: number;
}

const INERT_RECHECK_MS = 5 * 60 * 1_000;
const MAX_ALARM_BATCH = 10;
const MAX_BACKOFF_MS = 60 * 60 * 1_000;
const MAX_SERVER_RETRY_DELAY_MS = 24 * 60 * 60 * 1_000;
const HOSTED_DEADLINE_MS = 35 * 60 * 1_000;
const CHECK_CREATION_DEADLINE_MS = 5 * 60 * 1_000;

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export class GateConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GateConflict";
  }
}

export class GateFenced extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GateFenced";
  }
}

export class RunnerPoolGate extends DurableObject<Cloudflare.Env> {
  private deliveryInProgress = false;
  private readonly acquisitions = new Map<string, {
    owner: string;
    marker: string;
    promise: Promise<GateSnapshot>;
  }>();

  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => this.migrate());
  }

  private migrate(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
        id INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pool_metadata (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        runner_pool_id TEXT NOT NULL UNIQUE
      );
      CREATE TABLE IF NOT EXISTS gates (
        logical_key TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK (generation > 0),
        version INTEGER NOT NULL CHECK (version > 0),
        state TEXT NOT NULL CHECK (state IN ('hosted_selected','hosted_success','hosted_failure','superseded')),
        runner_pool_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        pr_number INTEGER NOT NULL CHECK (pr_number > 0),
        head_sha TEXT NOT NULL,
        base_sha TEXT NOT NULL,
        tested_merge_sha TEXT NOT NULL,
        check_run_id INTEGER NOT NULL CHECK (check_run_id > 0),
        owner TEXT NOT NULL,
        evidence_digest TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (logical_key, generation)
      );
      CREATE TABLE IF NOT EXISTS control_actions (
        action_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        logical_key TEXT NOT NULL,
        generation INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind = 'dispatch_hosted'),
        state TEXT NOT NULL CHECK (state IN ('pending','accepted','completed','failed')),
        acknowledged_by TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (logical_key, generation) REFERENCES gates(logical_key, generation)
      );
      CREATE TABLE IF NOT EXISTS check_outbox (
        outbox_key TEXT PRIMARY KEY,
        logical_key TEXT NOT NULL,
        generation INTEGER NOT NULL,
        check_run_id INTEGER NOT NULL,
        conclusion TEXT NOT NULL CHECK (conclusion IN ('success','failure')),
        evidence_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state = 'not_deliverable'),
        created_at INTEGER NOT NULL,
        FOREIGN KEY (logical_key, generation) REFERENCES gates(logical_key, generation)
      );
      CREATE TABLE IF NOT EXISTS allocations (
        logical_key TEXT NOT NULL,
        generation INTEGER NOT NULL,
        backend TEXT NOT NULL CHECK (backend = 'github-hosted'),
        state TEXT NOT NULL CHECK (state IN ('selected','released')),
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (logical_key, generation),
        FOREIGN KEY (logical_key, generation) REFERENCES gates(logical_key, generation)
      );
      CREATE TABLE IF NOT EXISTS audit (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        logical_key TEXT,
        generation INTEGER,
        actor TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
    const version = this.ctx.storage.sql
      .exec<{ id: number }>("SELECT COALESCE(MAX(id), 0) AS id FROM _sql_schema_migrations")
      .one().id;
    if (version < 1) {
      this.ctx.storage.sql.exec(
        "INSERT INTO _sql_schema_migrations(id,applied_at) VALUES (1,?)",
        Date.now(),
      );
    }
    if (version < 2) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          ALTER TABLE check_outbox RENAME TO check_outbox_v1;
          CREATE TABLE check_outbox (
            outbox_key TEXT PRIMARY KEY,
            logical_key TEXT NOT NULL,
            generation INTEGER NOT NULL,
            check_run_id INTEGER NOT NULL,
            conclusion TEXT NOT NULL CHECK (conclusion IN ('success','failure')),
            evidence_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','delivered','blocked')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            next_attempt_at INTEGER NOT NULL,
            last_attempt_at INTEGER,
            last_error TEXT,
            delivered_at INTEGER,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (logical_key, generation) REFERENCES gates(logical_key, generation)
          );
          INSERT INTO check_outbox(
            outbox_key,logical_key,generation,check_run_id,conclusion,evidence_digest,
            state,attempts,next_attempt_at,last_attempt_at,last_error,delivered_at,created_at
          )
          SELECT outbox_key,logical_key,generation,check_run_id,conclusion,evidence_digest,
            'pending',0,created_at,NULL,NULL,NULL,created_at
          FROM check_outbox_v1;
          DROP TABLE check_outbox_v1;
        `);
        this.ctx.storage.sql.exec(
          "INSERT INTO _sql_schema_migrations(id,applied_at) VALUES (2,?)",
          Date.now(),
        );
      });
    }
    if (version < 3) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          ALTER TABLE gates ADD COLUMN preparation_marker TEXT NOT NULL DEFAULT '';
          ALTER TABLE gates ADD COLUMN hosted_deadline_at INTEGER;
          ALTER TABLE check_outbox ADD COLUMN preparation_marker TEXT NOT NULL DEFAULT '';
        `);
        this.ctx.storage.sql.exec(
          "INSERT INTO _sql_schema_migrations(id,applied_at) VALUES (3,?)",
          Date.now(),
        );
      });
    }
    if (version < 4) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          CREATE TABLE check_creation_intents (
            intent_key TEXT PRIMARY KEY,
            marker TEXT NOT NULL UNIQUE,
            repository_id TEXT NOT NULL,
            pr_number INTEGER NOT NULL CHECK (pr_number > 0),
            head_sha TEXT NOT NULL,
            base_sha TEXT NOT NULL,
            tested_merge_sha TEXT NOT NULL,
            owner TEXT NOT NULL,
            actor_subject TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','check_bound','blocked')),
            post_attempted INTEGER NOT NULL CHECK (post_attempted IN (0,1)),
            check_run_id INTEGER,
            deadline_at INTEGER NOT NULL,
            next_attempt_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
          );
        `);
        this.ctx.storage.sql.exec(
          "INSERT INTO _sql_schema_migrations(id,applied_at) VALUES (4,?)",
          Date.now(),
        );
      });
    }
    if (version < 5) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          ALTER TABLE check_creation_intents ADD COLUMN consumed_generation INTEGER;
          ALTER TABLE check_creation_intents ADD COLUMN incident_at INTEGER;
        `);
        this.ctx.storage.sql.exec(
          "INSERT INTO _sql_schema_migrations(id,applied_at) VALUES (5,?)",
          Date.now(),
        );
      });
    }
  }

  async acquire(runnerPoolId: string, raw: unknown, actor: OidcActor): Promise<GateSnapshot> {
    if (this.deliveryInProgress) throw new GateFenced("Check delivery is in progress");
    const input = acquireGateSchema.parse(raw);
    if (input.repository_id !== actor.repositoryId) throw new GateFenced("OIDC repository does not own request");
    this.ctx.storage.transactionSync(() => this.bindPool(runnerPoolId));
    const owner = `${actor.runId}:${actor.runAttempt}`;
    const testedMergeSha = await resolveCanonicalTestedMerge(this.env, {
      repositoryId: input.repository_id,
      prNumber: input.pr_number,
      headSha: input.head_sha,
      baseSha: input.base_sha,
      actor,
    });
    const local = this.ctx.storage.sql.exec<GateRow>(
      `SELECT * FROM gates WHERE repository_id=? AND pr_number=?
       ORDER BY created_at DESC,generation DESC LIMIT 1`,
      input.repository_id,
      input.pr_number,
    ).toArray()[0];
    const sameCanonicalTuple = local !== undefined
      && local.head_sha === input.head_sha
      && local.base_sha === input.base_sha
      && local.tested_merge_sha === testedMergeSha;
    if (sameCanonicalTuple && local.owner === owner) return this.snapshot(local);
    if (sameCanonicalTuple && local.state === "hosted_selected" && local.owner !== owner
      && (local.hosted_deadline_at === null || Date.now() < local.hosted_deadline_at)) {
      throw new GateFenced("logical gate is owned by an active coordinator");
    }
    const resolvedInput = { ...input, tested_merge_sha: testedMergeSha };
    const logicalKey = deriveLogicalKey(input.repository_id, input.pr_number, input.head_sha);
    const preparationMarker = await derivePreparationMarker({
      repositoryId: input.repository_id,
      prNumber: input.pr_number,
      headSha: input.head_sha,
      baseSha: input.base_sha,
      testedMergeSha,
      actor,
    });
    const acquisitionKey = `${input.repository_id}:${input.pr_number}`;
    const inProgress = this.acquisitions.get(acquisitionKey);
    if (inProgress !== undefined) {
      if (inProgress.owner === owner && inProgress.marker === preparationMarker) return inProgress.promise;
      await inProgress.promise.catch(() => undefined);
      return this.acquire(runnerPoolId, input, actor);
    }
    const acquisition = this.acquireOnce(runnerPoolId, resolvedInput, actor, logicalKey, preparationMarker);
    this.acquisitions.set(acquisitionKey, { owner, marker: preparationMarker, promise: acquisition });
    try {
      return await acquisition;
    } finally {
      if (this.acquisitions.get(acquisitionKey)?.promise === acquisition) this.acquisitions.delete(acquisitionKey);
    }
  }

  private async acquireOnce(
    runnerPoolId: string,
    input: ReturnType<typeof acquireGateSchema.parse> & { tested_merge_sha: string },
    actor: OidcActor,
    logicalKey: string,
    preparationMarker: string,
  ): Promise<GateSnapshot> {
    const owner = `${actor.runId}:${actor.runAttempt}`;
    const now = Date.now();
    const intentDeadline = now + CHECK_CREATION_DEADLINE_MS;
    // Schedule before the SQL commit. A crash may leave only a harmless empty
    // alarm, but no committed creation intent can ever exist without a durable
    // wake-up path. The alarm remains list-only once post_attempted is durable.
    await this.scheduleEarlierAlarm(now + 2_000);
    const observed = this.ctx.storage.sql.exec<GateRow>(
      `SELECT * FROM gates WHERE repository_id=? AND pr_number=?
       ORDER BY created_at DESC,generation DESC LIMIT 1`,
      input.repository_id,
      input.pr_number,
    ).toArray()[0];
    const observedSameTuple = observed !== undefined
      && observed.head_sha === input.head_sha
      && observed.base_sha === input.base_sha
      && observed.tested_merge_sha === input.tested_merge_sha;
    if (observedSameTuple && observed.owner !== owner && observed.state === "hosted_selected") {
      if (observed.hosted_deadline_at === null || now < observed.hosted_deadline_at) {
        throw new GateFenced("logical gate is owned by an active coordinator");
      }
      await this.expireAbandonedGates(now);
    }
    let existingGate: GateSnapshot | undefined;
    let allowCreate = false;
    this.ctx.storage.transactionSync(() => {
      this.bindPool(runnerPoolId);
      const latest = this.ctx.storage.sql
        .exec<GateRow>("SELECT * FROM gates WHERE logical_key=? ORDER BY generation DESC LIMIT 1", logicalKey)
        .toArray()[0];
      const sameTuple = latest !== undefined
        && latest.repository_id === input.repository_id
        && latest.pr_number === input.pr_number
        && latest.head_sha === input.head_sha
        && latest.base_sha === input.base_sha
        && latest.tested_merge_sha === input.tested_merge_sha;
      if (sameTuple && latest !== undefined && latest.owner !== owner && latest.state === "hosted_selected") {
        throw new GateFenced("logical gate is owned by an active coordinator");
      }
      if (sameTuple && latest.owner === owner) {
        if (latest.preparation_marker !== preparationMarker) throw new GateConflict("gate marker invariant mismatch");
        existingGate = this.snapshot(latest);
        return;
      }
      const competingIntent = this.ctx.storage.sql.exec<CheckCreationIntentRow>(
        `SELECT * FROM check_creation_intents
         WHERE repository_id=? AND pr_number=? AND head_sha=? AND state='pending' AND owner<>?
         ORDER BY created_at LIMIT 1`,
        input.repository_id,
        input.pr_number,
        input.head_sha,
        owner,
      ).toArray()[0];
      if (competingIntent !== undefined) {
        throw new GateFenced("logical gate acquisition is owned by another durable intent");
      }
      const intent = this.intent(preparationMarker);
      if (intent === undefined) {
        this.ctx.storage.sql.exec(
          `INSERT INTO check_creation_intents(
            intent_key,marker,repository_id,pr_number,head_sha,base_sha,tested_merge_sha,
            owner,actor_subject,state,post_attempted,check_run_id,deadline_at,next_attempt_at,
            attempts,last_error,created_at,updated_at,consumed_generation,incident_at
          ) VALUES (?,?,?,?,?,?,?,?,?,'pending',0,NULL,?,?,0,NULL,?,?,NULL,NULL)`,
          preparationMarker,
          preparationMarker,
          input.repository_id,
          input.pr_number,
          input.head_sha,
          input.base_sha,
          input.tested_merge_sha,
          owner,
          actor.subject,
          intentDeadline,
          now,
          now,
          now,
        );
        allowCreate = true;
      } else {
        this.assertExactIntent(intent, input, preparationMarker);
        if (intent.state === "blocked") throw new GateConflict("Check creation intent is blocked");
        if (intent.owner !== owner) throw new GateFenced("Check creation intent belongs to another coordinator");
        if (intent.consumed_generation !== null) {
          const consumed = this.gate(logicalKey, intent.consumed_generation);
          if (consumed.owner !== owner || consumed.preparation_marker !== preparationMarker) {
            throw new GateConflict("consumed Check creation intent binding mismatch");
          }
          existingGate = this.snapshot(consumed);
          return;
        }
        allowCreate = intent.post_attempted === 0;
      }
      if (allowCreate) {
        this.ctx.storage.sql.exec(
          "UPDATE check_creation_intents SET post_attempted=1,updated_at=? WHERE intent_key=? AND post_attempted=0",
          now,
          preparationMarker,
        );
      }
    });
    if (existingGate !== undefined) return existingGate;
    const event = {
      repositoryId: input.repository_id,
      prNumber: input.pr_number,
      headSha: input.head_sha,
      baseSha: input.base_sha,
      testedMergeSha: input.tested_merge_sha,
      actor,
    };
    const prepared = await prepareGitHubCheck(this.env, event, fetch, new Date(), allowCreate);
    if (prepared.state === "prepared") {
      return this.commitPreparedIntent(
        runnerPoolId,
        preparationMarker,
        prepared.check_run_id,
        actor.subject,
        now,
        !prepared.tuple_current,
      );
    }
    const retryAt = Date.now() + 2_000;
    this.ctx.storage.sql.exec(
      `UPDATE check_creation_intents SET attempts=attempts+1,last_error=?,next_attempt_at=?,updated_at=?,
       state=CASE WHEN ?='blocked' THEN 'blocked' ELSE state END WHERE intent_key=?`,
      prepared.error,
      retryAt,
      Date.now(),
      prepared.state,
      preparationMarker,
    );
    await this.scheduleEarlierAlarm(retryAt);
    if (prepared.state === "blocked") throw new GateConflict(prepared.error);
    throw new GateFenced("Check creation is pending durable reconciliation");
  }

  async transition(raw: unknown, actor: OidcActor): Promise<GateSnapshot> {
    const input = transitionGateSchema.parse(raw);
    const now = Date.now();
    let result!: GateSnapshot;
    const initial = this.gate(input.logical_key, input.generation);
    if (input.generation !== this.latestGeneration(input.logical_key)) {
      throw new GateFenced("gate generation is not latest");
    }
    if (initial.repository_id !== actor.repositoryId || initial.owner !== `${actor.runId}:${actor.runAttempt}`) {
      throw new GateFenced("gate belongs to another OIDC coordinator");
    }
    if (initial.state === "hosted_success" || initial.state === "hosted_failure") {
      if (initial.state === input.to_state && initial.evidence_digest === input.evidence_digest) {
        return this.snapshot(initial);
      }
      throw new GateConflict("terminal gate retry conflicts with committed evidence");
    }
    if (initial.version !== input.expected_version || initial.state !== input.from_state) {
      throw new GateFenced("gate compare-and-swap expectation failed");
    }
    // Scheduling before the SQL commit means a crash can create only a harmless
    // empty alarm, never a committed outbox row with no wake-up path.
    await this.ctx.storage.setAlarm(now);
    this.ctx.storage.transactionSync(() => {
      const current = this.gate(input.logical_key, input.generation);
      if (input.generation !== this.latestGeneration(input.logical_key)) {
        throw new GateFenced("gate generation is not latest");
      }
      if (current.repository_id !== actor.repositoryId || current.owner !== `${actor.runId}:${actor.runAttempt}`) {
        throw new GateFenced("gate belongs to another OIDC coordinator");
      }
      if (current.version !== input.expected_version || current.state !== input.from_state) {
        throw new GateFenced("gate compare-and-swap expectation failed");
      }
      const conclusion = input.to_state === "hosted_success" ? "success" : "failure";
      this.ctx.storage.sql.exec(
        `UPDATE gates SET state=?,version=version+1,evidence_digest=?,updated_at=?
         WHERE logical_key=? AND generation=? AND version=? AND state='hosted_selected'`,
        input.to_state,
        input.evidence_digest,
        now,
        input.logical_key,
        input.generation,
        input.expected_version,
      );
      this.ctx.storage.sql.exec(
        "UPDATE allocations SET state='released',updated_at=? WHERE logical_key=? AND generation=?",
        now,
        input.logical_key,
        input.generation,
      );
      this.ctx.storage.sql.exec(
        `INSERT INTO check_outbox(
          outbox_key,logical_key,generation,check_run_id,conclusion,evidence_digest,
          state,attempts,next_attempt_at,last_attempt_at,last_error,delivered_at,created_at,
          preparation_marker
         ) VALUES (?,?,?,?,?,?,'pending',0,?,NULL,NULL,NULL,?,?)`,
        `${input.logical_key}:${input.generation}:${input.to_state}:${input.evidence_digest}`,
        input.logical_key,
        input.generation,
        current.check_run_id,
        conclusion,
        input.evidence_digest,
        now,
        now,
        current.preparation_marker,
      );
      this.audit("hosted_gate_terminal", input.logical_key, input.generation, actor.subject, {
        from: input.from_state,
        to: input.to_state,
        outbox_delivery: "pending",
      }, now);
      result = this.snapshot(this.gate(input.logical_key, input.generation));
    });
    return result;
  }

  override async alarm(): Promise<void> {
    if ((this.env.ACTIVATION_MODE as string) !== "active") {
      const pending = this.ctx.storage.sql.exec<{ count: number }>(
        `SELECT
          (SELECT COUNT(*) FROM check_outbox WHERE state='pending') +
          (SELECT COUNT(*) FROM gates WHERE state='hosted_selected') +
          (SELECT COUNT(*) FROM check_creation_intents WHERE state='pending') AS count`,
      ).one().count;
      if (pending === 0) await this.ctx.storage.deleteAlarm();
      else await this.ctx.storage.setAlarm(Date.now() + INERT_RECHECK_MS);
      return;
    }
    await this.reconcileCheckCreationIntents(Date.now());
    await this.expireAbandonedGates(Date.now());
    let processed = 0;
    while (processed < MAX_ALARM_BATCH) {
      const row = this.nextDueOutbox(Date.now());
      if (row === undefined) break;
      await this.deliverOutbox(row);
      processed += 1;
    }
    await this.scheduleNextAlarm();
  }

  async acknowledgeControlAction(raw: unknown, actor: OidcActor): Promise<{ accepted: true }> {
    const input = acknowledgeActionSchema.parse(raw);
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const action = this.ctx.storage.sql
        .exec<{ state: string; acknowledged_by: string | null; owner: string; repository_id: string }>(
          `SELECT a.state,a.acknowledged_by,g.owner,g.repository_id
           FROM control_actions a JOIN gates g
             ON g.logical_key=a.logical_key AND g.generation=a.generation
           WHERE a.action_id=?`,
          input.action_id,
        )
        .toArray()[0];
      if (action === undefined) throw new GateConflict("unknown control action");
      if (this.latestGenerationForAction(input.action_id) !== this.latestGenerationForLogicalAction(input.action_id)) {
        throw new GateFenced("control action generation is not latest");
      }
      if (action.repository_id !== actor.repositoryId || action.owner !== `${actor.runId}:${actor.runAttempt}`) {
        throw new GateFenced("control action belongs to another OIDC coordinator");
      }
      if (action.acknowledged_by !== null && action.acknowledged_by !== actor.subject) {
        throw new GateFenced("control action acknowledged by another coordinator");
      }
      if (action.state !== input.outcome) {
        if (action.state === "completed" || action.state === "failed") {
          throw new GateConflict("control action is already terminal");
        }
        this.ctx.storage.sql.exec(
          "UPDATE control_actions SET state=?,acknowledged_by=?,updated_at=? WHERE action_id=?",
          input.outcome,
          actor.subject,
          now,
          input.action_id,
        );
      }
      this.audit("control_action_ack", null, null, actor.subject, {
        action_id: input.action_id,
        outcome: input.outcome,
      }, now);
    });
    return { accepted: true };
  }

  async getGate(logicalKey: string, generation: number): Promise<GateSnapshot> {
    return this.snapshot(this.gate(logicalKey, generation));
  }

  async listControlActions(): Promise<Record<string, SqlStorageValue>[]> {
    return this.ctx.storage.sql.exec<Record<string, SqlStorageValue>>(
      "SELECT * FROM control_actions ORDER BY created_at,action_id",
    ).toArray();
  }

  async listCheckOutbox(): Promise<Record<string, SqlStorageValue>[]> {
    return this.ctx.storage.sql.exec<Record<string, SqlStorageValue>>(
      "SELECT * FROM check_outbox ORDER BY created_at,outbox_key",
    ).toArray();
  }

  async listAudit(): Promise<Record<string, SqlStorageValue>[]> {
    return this.ctx.storage.sql.exec<Record<string, SqlStorageValue>>(
      "SELECT * FROM audit ORDER BY sequence",
    ).toArray();
  }

  private bindPool(runnerPoolId: string): void {
    const existing = this.ctx.storage.sql
      .exec<{ runner_pool_id: string }>("SELECT runner_pool_id FROM pool_metadata WHERE singleton=1")
      .toArray()[0];
    if (existing === undefined) {
      this.ctx.storage.sql.exec("INSERT INTO pool_metadata VALUES (1,?)", runnerPoolId);
    } else if (existing.runner_pool_id !== runnerPoolId) {
      throw new GateConflict("Durable Object is already bound to another runner pool");
    }
  }

  private nextDueOutbox(now: number): OutboxRow | undefined {
    return this.ctx.storage.sql.exec<OutboxRow>(
      `SELECT o.*,g.tested_merge_sha AS head_sha
       FROM check_outbox o JOIN gates g
         ON g.logical_key=o.logical_key AND g.generation=o.generation
       WHERE o.state='pending' AND o.next_attempt_at<=?
       ORDER BY o.next_attempt_at,o.created_at,o.outbox_key LIMIT 1`,
      now,
    ).toArray()[0];
  }

  private async deliverOutbox(row: OutboxRow): Promise<void> {
    const attemptAt = Date.now();
    this.ctx.storage.sql.exec(
      `UPDATE check_outbox SET attempts=attempts+1,last_attempt_at=?,last_error=NULL
       WHERE outbox_key=? AND state='pending'`,
      attemptAt,
      row.outbox_key,
    );
    const event: CheckDeliveryEvent = {
      checkRunId: row.check_run_id,
      headSha: row.head_sha,
      evidenceDigest: row.evidence_digest,
      conclusion: row.conclusion,
      preparationMarker: row.preparation_marker,
    };
    this.deliveryInProgress = true;
    let result;
    try {
      result = await deliverGitHubCheck(this.env, event);
    } finally {
      this.deliveryInProgress = false;
    }
    const now = Date.now();
    if (result.state === "delivered") {
      this.ctx.storage.sql.exec(
        `UPDATE check_outbox SET state='delivered',delivered_at=?,next_attempt_at=?,last_error=NULL
         WHERE outbox_key=? AND state='pending'`,
        now,
        now,
        row.outbox_key,
      );
      this.audit("check_outbox_delivered", row.logical_key, row.generation, "gate-service", {
        outbox_key: row.outbox_key,
        reconciled: result.reconciled,
      }, now);
      return;
    }
    if (result.state === "blocked") {
      this.ctx.storage.sql.exec(
        `UPDATE check_outbox SET state='blocked',last_error=?
         WHERE outbox_key=? AND state='pending'`,
        result.error,
        row.outbox_key,
      );
      this.audit("check_outbox_blocked", row.logical_key, row.generation, "gate-service", {
        outbox_key: row.outbox_key,
        error: result.error,
      }, now);
      return;
    }
    const attempts = row.attempts + 1;
    const delay = Math.min(MAX_BACKOFF_MS, 2 ** Math.min(attempts, 16) * 1_000);
    const serverRetryAt = result.retryAt === undefined
      ? 0
      : Math.min(result.retryAt, now + MAX_SERVER_RETRY_DELAY_MS);
    const nextAttemptAt = Math.max(now + delay, serverRetryAt);
    this.ctx.storage.sql.exec(
      `UPDATE check_outbox SET next_attempt_at=?,last_error=?
       WHERE outbox_key=? AND state='pending'`,
      nextAttemptAt,
      result.error,
      row.outbox_key,
    );
  }

  private async scheduleNextAlarm(): Promise<void> {
    const next = this.ctx.storage.sql.exec<{ next_attempt_at: number | null }>(`
      SELECT MIN(next_attempt_at) AS next_attempt_at FROM (
        SELECT next_attempt_at FROM check_outbox WHERE state='pending'
        UNION ALL
        SELECT hosted_deadline_at AS next_attempt_at FROM gates
          WHERE state='hosted_selected' AND hosted_deadline_at IS NOT NULL
        UNION ALL
        SELECT next_attempt_at FROM check_creation_intents
          WHERE state='pending'
      )
    `).one().next_attempt_at;
    if (next === null) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    await this.ctx.storage.setAlarm(Math.max(Date.now(), next));
  }

  private intent(marker: string): CheckCreationIntentRow | undefined {
    return this.ctx.storage.sql.exec<CheckCreationIntentRow>(
      "SELECT * FROM check_creation_intents WHERE intent_key=?",
      marker,
    ).toArray()[0];
  }

  private assertExactIntent(
    intent: CheckCreationIntentRow,
    input: { repository_id: string; pr_number: number; head_sha: string; base_sha: string; tested_merge_sha: string },
    marker: string,
  ): void {
    if (
      intent.marker !== marker
      || intent.repository_id !== input.repository_id
      || intent.pr_number !== input.pr_number
      || intent.head_sha !== input.head_sha
      || intent.base_sha !== input.base_sha
      || intent.tested_merge_sha !== input.tested_merge_sha
    ) throw new GateConflict("Check creation intent tuple mismatch");
  }

  private async commitPreparedIntent(
    runnerPoolId: string,
    marker: string,
    checkRunId: number,
    actorSubject: string,
    now: number,
    obsolete = false,
  ): Promise<GateSnapshot> {
    const intent = this.intent(marker);
    if (intent === undefined || intent.state === "blocked") throw new GateConflict("Check creation intent unavailable");
    if (intent.check_run_id !== null && intent.check_run_id !== checkRunId) {
      throw new GateConflict("Check creation intent is bound to another Check");
    }
    const logicalKey = deriveLogicalKey(intent.repository_id, intent.pr_number, intent.head_sha);
    const hostedDeadlineAt = obsolete ? null : now + HOSTED_DEADLINE_MS;
    if (obsolete) await this.scheduleEarlierAlarm(now);
    else await this.scheduleEarlierAlarm(hostedDeadlineAt!);
    const obsoleteEvidence = obsolete
      ? await sha256Hex([
          "ci-gate-obsolete-check-v1",
          logicalKey,
          marker,
          String(checkRunId),
          intent.tested_merge_sha,
        ].join("\n"))
      : undefined;
    const prior = this.ctx.storage.sql.exec<GateRow>(
      `SELECT * FROM gates WHERE repository_id=? AND pr_number=? AND state='hosted_selected'
       ORDER BY created_at DESC,generation DESC LIMIT 1`,
      intent.repository_id,
      intent.pr_number,
    ).toArray()[0];
    const supersedeEvidence = !obsolete && prior?.state === "hosted_selected"
      ? await sha256Hex([
          "ci-gate-generation-superseded-v1",
          prior.logical_key,
          String(prior.generation),
          prior.tested_merge_sha,
          marker,
        ].join("\n"))
      : undefined;
    if (supersedeEvidence !== undefined) await this.scheduleEarlierAlarm(now);
    let result!: GateSnapshot;
    this.ctx.storage.transactionSync(() => {
      const currentIntent = this.intent(marker);
      if (currentIntent === undefined || currentIntent.state === "blocked") {
        throw new GateConflict("Check creation intent unavailable");
      }
      if (currentIntent.check_run_id !== null && currentIntent.check_run_id !== checkRunId) {
        throw new GateConflict("Check creation intent is bound to another Check");
      }
      const existing = this.ctx.storage.sql.exec<GateRow>(
        "SELECT * FROM gates WHERE logical_key=? ORDER BY generation DESC LIMIT 1",
        logicalKey,
      ).toArray()[0];
      const sameTuple = existing !== undefined
        && existing.base_sha === currentIntent.base_sha
        && existing.tested_merge_sha === currentIntent.tested_merge_sha;
      if (sameTuple && existing.owner === currentIntent.owner) {
        if (existing.check_run_id !== checkRunId || existing.preparation_marker !== marker) {
          throw new GateConflict("durable Check binding conflicts with existing gate");
        }
        this.ctx.storage.sql.exec(
          `UPDATE check_creation_intents SET state='check_bound',check_run_id=?,consumed_generation=?,updated_at=?
           WHERE intent_key=?`,
          checkRunId,
          existing.generation,
          now,
          marker,
        );
        result = this.snapshot(existing);
        return;
      }
      const activePrior = this.ctx.storage.sql.exec<GateRow>(
        `SELECT * FROM gates WHERE repository_id=? AND pr_number=? AND state='hosted_selected'
         ORDER BY created_at DESC,generation DESC LIMIT 1`,
        currentIntent.repository_id,
        currentIntent.pr_number,
      ).toArray()[0];
      if (activePrior !== undefined && !obsolete) {
        const activeSameTuple = activePrior.head_sha === currentIntent.head_sha
          && activePrior.base_sha === currentIntent.base_sha
          && activePrior.tested_merge_sha === currentIntent.tested_merge_sha;
        if (activeSameTuple && activePrior.owner !== currentIntent.owner) {
          throw new GateFenced("logical gate is owned by an active coordinator");
        }
        if (prior === undefined
          || activePrior.logical_key !== prior.logical_key
          || activePrior.generation !== prior.generation) {
          throw new GateFenced("pull request gate changed during acquisition");
        }
      }
      const generation = (existing?.generation ?? 0) + 1;
      if (activePrior !== undefined && !obsolete) {
        this.supersedeOlder(activePrior, logicalKey, generation, now, supersedeEvidence);
      }
      if (obsolete) {
        if (obsoleteEvidence === undefined) throw new GateConflict("missing obsolete terminal evidence");
        this.ctx.storage.sql.exec(
          `INSERT INTO gates(
            logical_key,generation,version,state,runner_pool_id,repository_id,pr_number,
            head_sha,base_sha,tested_merge_sha,check_run_id,owner,evidence_digest,
            created_at,updated_at,preparation_marker,hosted_deadline_at
          ) VALUES (?,?,1,'hosted_failure',?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
          logicalKey,
          generation,
          runnerPoolId,
          currentIntent.repository_id,
          currentIntent.pr_number,
          currentIntent.head_sha,
          currentIntent.base_sha,
          currentIntent.tested_merge_sha,
          checkRunId,
          currentIntent.owner,
          obsoleteEvidence,
          now,
          now,
          marker,
        );
        this.ctx.storage.sql.exec(
          "INSERT INTO allocations VALUES (?,?,'github-hosted','released',?)",
          logicalKey,
          generation,
          now,
        );
        this.ctx.storage.sql.exec(
          `INSERT INTO check_outbox(
            outbox_key,logical_key,generation,check_run_id,conclusion,evidence_digest,
            state,attempts,next_attempt_at,last_attempt_at,last_error,delivered_at,created_at,
            preparation_marker
          ) VALUES (?,?,?,?,? ,?,'pending',0,?,NULL,NULL,NULL,?,?)`,
          `${logicalKey}:${generation}:hosted_failure:${obsoleteEvidence}`,
          logicalKey,
          generation,
          checkRunId,
          "failure",
          obsoleteEvidence,
          now,
          now,
          marker,
        );
        this.ctx.storage.sql.exec(
          `UPDATE check_creation_intents SET state='check_bound',check_run_id=?,consumed_generation=?,updated_at=?
           WHERE intent_key=?`,
          checkRunId,
          generation,
          now,
          marker,
        );
        this.audit("obsolete_check_bound_terminal", logicalKey, generation, actorSubject, {
          check_run_id: checkRunId,
          outbox_delivery: "pending",
          local_execution: "structurally_disabled",
        }, now);
        result = this.snapshot(this.gate(logicalKey, generation));
        return;
      }
      this.ctx.storage.sql.exec(
        `INSERT INTO gates(
          logical_key,generation,version,state,runner_pool_id,repository_id,pr_number,
          head_sha,base_sha,tested_merge_sha,check_run_id,owner,evidence_digest,
          created_at,updated_at,preparation_marker,hosted_deadline_at
        ) VALUES (?,?,1,'hosted_selected',?,?,?,?,?,?,?,?,NULL,?,?,?,?)`,
        logicalKey,
        generation,
        runnerPoolId,
        currentIntent.repository_id,
        currentIntent.pr_number,
        currentIntent.head_sha,
        currentIntent.base_sha,
        currentIntent.tested_merge_sha,
        checkRunId,
        currentIntent.owner,
        now,
        now,
        marker,
        hostedDeadlineAt,
      );
      this.ctx.storage.sql.exec(
        `INSERT INTO control_actions VALUES (?,?,?,?,?,'pending',NULL,?,?)`,
        crypto.randomUUID(),
        `${logicalKey}:${generation}:dispatch_hosted`,
        logicalKey,
        generation,
        "dispatch_hosted",
        now,
        now,
      );
      this.ctx.storage.sql.exec(
        "INSERT INTO allocations VALUES (?,?,?,'selected',?)",
        logicalKey,
        generation,
        "github-hosted",
        now,
      );
      this.ctx.storage.sql.exec(
        `UPDATE check_creation_intents SET state='check_bound',check_run_id=?,consumed_generation=?,updated_at=?
         WHERE intent_key=?`,
        checkRunId,
        generation,
        now,
        marker,
      );
      this.audit("hosted_gate_acquired", logicalKey, generation, actorSubject, {
        check_creation_intent: marker,
        local_execution: "structurally_disabled",
      }, now);
      result = this.snapshot(this.gate(logicalKey, generation));
    });
    return result;
  }

  private supersedeOlder(
    selected: GateRow,
    replacementLogicalKey: string,
    replacementGeneration: number,
    now: number,
    evidenceDigest?: string,
  ): void {
    if (evidenceDigest === undefined) throw new GateConflict("missing supersede terminal evidence");
    this.ctx.storage.sql.exec(
      `UPDATE gates SET state='hosted_failure',version=version+1,evidence_digest=?,updated_at=?
       WHERE logical_key=? AND generation=? AND state='hosted_selected'`,
      evidenceDigest,
      now,
      selected.logical_key,
      selected.generation,
    );
    this.ctx.storage.sql.exec(
      `INSERT INTO check_outbox(
        outbox_key,logical_key,generation,check_run_id,conclusion,evidence_digest,
        state,attempts,next_attempt_at,last_attempt_at,last_error,delivered_at,created_at,
        preparation_marker
      ) VALUES (?,?,?,?,? ,?,'pending',0,?,NULL,NULL,NULL,?,?)`,
      `${selected.logical_key}:${selected.generation}:hosted_failure:${evidenceDigest}`,
      selected.logical_key,
      selected.generation,
      selected.check_run_id,
      "failure",
      evidenceDigest,
      now,
      now,
      selected.preparation_marker,
    );
    this.audit("hosted_gate_superseded", selected.logical_key, selected.generation, "gate-service", {
      replacement_logical_key: replacementLogicalKey,
      replacement_generation: replacementGeneration,
      outbox_delivery: "pending",
    }, now);
    this.ctx.storage.sql.exec(
      `UPDATE control_actions SET state='failed',updated_at=?
       WHERE logical_key=? AND generation=? AND state IN ('pending','accepted')`,
      now, selected.logical_key, selected.generation,
    );
    this.ctx.storage.sql.exec(
      `UPDATE allocations SET state='released',updated_at=?
       WHERE logical_key=? AND generation=? AND state='selected'`,
      now, selected.logical_key, selected.generation,
    );
  }

  private async reconcileCheckCreationIntents(now: number): Promise<void> {
    const intents = this.ctx.storage.sql.exec<CheckCreationIntentRow>(
      `SELECT * FROM check_creation_intents
       WHERE state='pending' AND post_attempted=1 AND next_attempt_at<=?
       ORDER BY next_attempt_at,intent_key LIMIT 10`,
      now,
    ).toArray();
    for (const intent of intents) {
      const [runId, runAttempt] = intent.owner.split(":", 2);
      const actor: OidcActor = {
        repository: this.env.GITHUB_REPOSITORY,
        repositoryId: intent.repository_id,
        workflowRef: this.env.OIDC_WORKFLOW_REF,
        jobWorkflowRef: this.env.OIDC_JOB_WORKFLOW_REF,
        runId: runId ?? "unknown",
        runAttempt: runAttempt ?? "unknown",
        subject: intent.actor_subject,
        tokenId: "durable-intent-reconciler",
      };
      const prepared = await prepareGitHubCheck(this.env, {
        repositoryId: intent.repository_id,
        prNumber: intent.pr_number,
        headSha: intent.head_sha,
        baseSha: intent.base_sha,
        testedMergeSha: intent.tested_merge_sha,
        actor,
      }, fetch, new Date(), false);
      if (prepared.state === "prepared") {
        const pool = this.ctx.storage.sql.exec<{ runner_pool_id: string }>(
          "SELECT runner_pool_id FROM pool_metadata WHERE singleton=1",
        ).one().runner_pool_id;
        await this.commitPreparedIntent(
          pool,
          intent.marker,
          prepared.check_run_id,
          intent.actor_subject,
          now,
          !prepared.tuple_current,
        );
        continue;
      }
      const overdue = intent.deadline_at <= now;
      if (overdue) {
        this.ctx.storage.transactionSync(() => {
          const current = this.intent(intent.intent_key);
          if (current === undefined || current.incident_at !== null) return;
          this.ctx.storage.sql.exec(
            "UPDATE check_creation_intents SET incident_at=? WHERE intent_key=? AND incident_at IS NULL",
            now,
            intent.intent_key,
          );
          this.audit("check_creation_reconciliation_overdue", null, null, "gate-service", {
            marker: intent.marker,
            repository_id: intent.repository_id,
            pr_number: intent.pr_number,
          }, now);
        });
      }
      const nextAttempts = intent.attempts + 1;
      const retryDelay = overdue
        ? Math.min(MAX_BACKOFF_MS, 2 ** Math.min(nextAttempts, 16) * 1_000)
        : 5_000;
      this.ctx.storage.sql.exec(
        `UPDATE check_creation_intents SET attempts=attempts+1,last_error=?,next_attempt_at=?,updated_at=?,
         state=CASE WHEN ?='blocked' THEN 'blocked' ELSE state END WHERE intent_key=? AND state='pending'`,
        overdue
          ? `creation reconciliation deadline exceeded: ${prepared.error}`
          : prepared.error,
        now + retryDelay,
        now,
        prepared.state,
        intent.intent_key,
      );
    }
  }

  private async scheduleEarlierAlarm(at: number): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null || at < existing) await this.ctx.storage.setAlarm(at);
  }

  private async expireAbandonedGates(now: number): Promise<void> {
    const expired = this.ctx.storage.sql.exec<GateRow>(
      `SELECT * FROM gates
       WHERE state='hosted_selected' AND hosted_deadline_at IS NOT NULL AND hosted_deadline_at<=?
       ORDER BY hosted_deadline_at,logical_key,generation`,
      now,
    ).toArray();
    for (const row of expired) {
      const evidenceDigest = await sha256Hex([
        "ci-gate-hosted-timeout-v1",
        row.logical_key,
        String(row.generation),
        row.tested_merge_sha,
        String(row.hosted_deadline_at),
      ].join("\n"));
      this.ctx.storage.transactionSync(() => {
        const current = this.gate(row.logical_key, row.generation);
        if (current.state !== "hosted_selected" || current.hosted_deadline_at === null
          || current.hosted_deadline_at > now) return;
        this.ctx.storage.sql.exec(
          `UPDATE gates SET state='hosted_failure',version=version+1,evidence_digest=?,updated_at=?
           WHERE logical_key=? AND generation=? AND state='hosted_selected'`,
          evidenceDigest,
          now,
          row.logical_key,
          row.generation,
        );
        this.ctx.storage.sql.exec(
          "UPDATE allocations SET state='released',updated_at=? WHERE logical_key=? AND generation=?",
          now,
          row.logical_key,
          row.generation,
        );
        this.ctx.storage.sql.exec(
          `UPDATE control_actions SET state='failed',updated_at=?
           WHERE logical_key=? AND generation=? AND state IN ('pending','accepted')`,
          now,
          row.logical_key,
          row.generation,
        );
        this.ctx.storage.sql.exec(
          `INSERT INTO check_outbox(
            outbox_key,logical_key,generation,check_run_id,conclusion,evidence_digest,
            state,attempts,next_attempt_at,last_attempt_at,last_error,delivered_at,created_at,
            preparation_marker
           ) VALUES (?,?,?,?,? ,?,'pending',0,?,NULL,NULL,NULL,?,?)`,
          `${row.logical_key}:${row.generation}:hosted_failure:${evidenceDigest}`,
          row.logical_key,
          row.generation,
          row.check_run_id,
          "failure",
          evidenceDigest,
          now,
          now,
          row.preparation_marker,
        );
        this.audit("hosted_gate_timeout", row.logical_key, row.generation, "gate-service-watchdog", {
          hosted_deadline_at: row.hosted_deadline_at,
          outbox_delivery: "pending",
        }, now);
      });
    }
  }

  private gate(logicalKey: string, generation: number): GateRow {
    const row = this.ctx.storage.sql
      .exec<GateRow>("SELECT * FROM gates WHERE logical_key=? AND generation=?", logicalKey, generation)
      .toArray()[0];
    if (row === undefined) throw new GateConflict("unknown gate generation");
    return row;
  }

  private latestGeneration(logicalKey: string): number {
    return this.ctx.storage.sql
      .exec<{ generation: number }>("SELECT MAX(generation) AS generation FROM gates WHERE logical_key=?", logicalKey)
      .one().generation;
  }

  private latestGenerationForAction(actionId: string): number {
    return this.ctx.storage.sql
      .exec<{ generation: number }>("SELECT generation FROM control_actions WHERE action_id=?", actionId)
      .one().generation;
  }

  private latestGenerationForLogicalAction(actionId: string): number {
    return this.ctx.storage.sql
      .exec<{ generation: number }>(
        `SELECT MAX(g.generation) AS generation
         FROM gates g JOIN control_actions a ON a.logical_key=g.logical_key
         WHERE a.action_id=?`,
        actionId,
      )
      .one().generation;
  }

  private snapshot(row: GateRow): GateSnapshot {
    return {
      logical_key: row.logical_key,
      generation: row.generation,
      version: row.version,
      state: row.state,
      runner_pool_id: row.runner_pool_id,
      owner: row.owner,
      check_run_id: row.check_run_id,
      tested_merge_sha: row.tested_merge_sha,
      evidence_digest: row.evidence_digest,
    };
  }

  private audit(
    eventType: string,
    logicalKey: string | null,
    generation: number | null,
    actor: string,
    detail: Record<string, unknown>,
    now: number,
  ): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO audit VALUES (NULL,?,?,?,?,?,?,?)",
      crypto.randomUUID(),
      eventType,
      logicalKey,
      generation,
      actor,
      JSON.stringify(detail),
      now,
    );
  }
}
