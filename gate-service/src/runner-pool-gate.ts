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
import { deliverGitHubCheck, type CheckDeliveryEvent } from "./github-checks";

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
  attempts: number;
  next_attempt_at: number;
}

const INERT_RECHECK_MS = 5 * 60 * 1_000;
const MAX_ALARM_BATCH = 10;
const MAX_BACKOFF_MS = 60 * 60 * 1_000;
const MAX_SERVER_RETRY_DELAY_MS = 24 * 60 * 60 * 1_000;

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
  }

  async acquire(runnerPoolId: string, raw: unknown, actor: OidcActor): Promise<GateSnapshot> {
    if (this.deliveryInProgress) throw new GateFenced("Check delivery is in progress");
    const input = acquireGateSchema.parse(raw);
    if (input.repository_id !== actor.repositoryId) throw new GateFenced("OIDC repository does not own request");
    const logicalKey = deriveLogicalKey(input.repository_id, input.pr_number, input.head_sha);
    const owner = `${actor.runId}:${actor.runAttempt}`;
    const now = Date.now();
    let result!: GateSnapshot;
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
      if (sameTuple) {
        if (latest.check_run_id !== input.check_run_id || latest.owner !== owner) {
          throw new GateConflict("same gate tuple has different check or owner invariants");
        }
        result = this.snapshot(latest);
        return;
      }
      const generation = (latest?.generation ?? 0) + 1;
      if (latest !== undefined) {
        this.ctx.storage.sql.exec(
          `UPDATE gates SET state='superseded',version=version+1,updated_at=?
           WHERE logical_key=? AND generation<? AND state='hosted_selected'`,
          now,
          logicalKey,
          generation,
        );
        this.ctx.storage.sql.exec(
          `UPDATE check_outbox SET state='blocked',last_error='superseded by a newer gate generation'
           WHERE logical_key=? AND generation<? AND state='pending'`,
          logicalKey,
          generation,
        );
        this.ctx.storage.sql.exec(
          `UPDATE control_actions SET state='failed',updated_at=?
           WHERE logical_key=? AND generation<? AND state IN ('pending','accepted')`,
          now,
          logicalKey,
          generation,
        );
        this.ctx.storage.sql.exec(
          `UPDATE allocations SET state='released',updated_at=?
           WHERE logical_key=? AND generation<? AND state='selected'`,
          now,
          logicalKey,
          generation,
        );
      }
      this.ctx.storage.sql.exec(
        "INSERT INTO gates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        logicalKey,
        generation,
        1,
        "hosted_selected",
        runnerPoolId,
        input.repository_id,
        input.pr_number,
        input.head_sha,
        input.base_sha,
        input.tested_merge_sha,
        input.check_run_id,
        owner,
        null,
        now,
        now,
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
      this.audit("hosted_gate_acquired", logicalKey, generation, actor.subject, {
        oidc_jti: actor.tokenId,
        local_execution: "structurally_disabled",
      }, now);
      result = this.snapshot(this.gate(logicalKey, generation));
    });
    return result;
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
          state,attempts,next_attempt_at,last_attempt_at,last_error,delivered_at,created_at
         ) VALUES (?,?,?,?,?,?,'pending',0,?,NULL,NULL,NULL,?)`,
        `${input.logical_key}:${input.generation}:${input.to_state}:${input.evidence_digest}`,
        input.logical_key,
        input.generation,
        current.check_run_id,
        conclusion,
        input.evidence_digest,
        now,
        now,
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
        "SELECT COUNT(*) AS count FROM check_outbox WHERE state='pending'",
      ).one().count;
      if (pending === 0) await this.ctx.storage.deleteAlarm();
      else await this.ctx.storage.setAlarm(Date.now() + INERT_RECHECK_MS);
      return;
    }
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
      `SELECT o.*,g.head_sha
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
    const next = this.ctx.storage.sql.exec<{ next_attempt_at: number | null }>(
      "SELECT MIN(next_attempt_at) AS next_attempt_at FROM check_outbox WHERE state='pending'",
    ).one().next_attempt_at;
    if (next === null) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    await this.ctx.storage.setAlarm(Math.max(Date.now(), next));
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
