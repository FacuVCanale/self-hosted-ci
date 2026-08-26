import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, it } from "vitest";
import { RunnerPoolGate } from "../src/legacy-runner-pool-gate";
import { LocalMergeRunnerPoolGate } from "../src/runner-pool-gate";

describe("legacy RunnerPoolGate lifecycle compatibility", () => {
  it("is a distinct implementation that preserves the v5 schema and empty alarm behavior", async ({ expect }) => {
    expect(RunnerPoolGate).not.toBe(LocalMergeRunnerPoolGate);
    const namespace = (env as unknown as {
      LEGACY_RUNNER_POOLS: DurableObjectNamespace<RunnerPoolGate>;
    }).LEGACY_RUNNER_POOLS;
    const stub = namespace.getByName("legacy-schema-v5");

    const result = await runInDurableObject(stub, async (instance: RunnerPoolGate) => {
      const runtime = instance as unknown as {
        ctx: DurableObjectState;
      };
      const migrations = [
        ...runtime.ctx.storage.sql.exec<{ id: number }>(
          "SELECT id FROM _sql_schema_migrations ORDER BY id",
        ),
      ].map(({ id }) => id);
      const tables = [
        ...runtime.ctx.storage.sql.exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        ),
      ].map(({ name }) => name);

      await instance.alarm();
      return {
        migrations,
        tables,
        nextAlarm: await runtime.ctx.storage.getAlarm(),
      };
    });

    expect(result.migrations).toEqual([1, 2, 3, 4, 5]);
    expect(result.tables).toContain("check_creation_intents");
    expect(result.tables).not.toContain("terminal_evidence");
    expect(result.nextAlarm).toBeNull();
  });
});
