#!/usr/bin/env bash
set -euo pipefail

# Executable half of overworld-ci-v1. It accepts no arguments or shell-code
# indirection; the immutable Action selects it after every identity check.

readonly EXPECTED_MEMORY_BYTES=4294967296
readonly MEMORY_FIT_LIMIT_BYTES=3865470566
readonly WATERFALL_REVISION=6df90210830b2ebe36eda6b96d91237914d000e4
readonly WATERFALL_ROOT=/opt/self-hosted-ci/overworld-deps/waterfall
readonly BACKEND_LOCK_SHA256=b235110fe83b4b3a4eafb337efc0bb8d7424aea33a72f0338b2192892ce79fdb
readonly FRONTEND_LOCK_SHA256=6004b42bc89358fc0d83f81f8015658246139ce830e1e569279700850e5d63b3
readonly BACKEND_MODULES=/opt/self-hosted-ci/overworld-deps/backend-node_modules
readonly FRONTEND_MODULES=/opt/self-hosted-ci/overworld-deps/frontend-node_modules
readonly STATE_ROOT="${RUNNER_TEMP:?RUNNER_TEMP is required}/overworld-ci-v1"
readonly MEMORY_LOG="$STATE_ROOT/memory.jsonl"
readonly MEMORY_SUMMARY="$STATE_ROOT/memory-summary.jsonl"
readonly PG16_BIN=/usr/lib/postgresql/16/bin
readonly PG17_BIN=/usr/lib/postgresql/17/bin
readonly PG16_DATA="$STATE_ROOT/postgres-16"
readonly PG17_DATA="$STATE_ROOT/postgres-17"
readonly PGSOCKET="$STATE_ROOT/postgres-socket"
readonly BACKEND_PGPORT=55432
readonly E2E_PGPORT=55433
readonly MINIO_DATA="$STATE_ROOT/minio"
readonly MINIO_PORT=59002
readonly BACKEND_PORT=3000
readonly FRONTEND_PORT=3001
readonly TESTED_MERGE_SHA="${PROFILE_TESTED_MERGE_SHA:?PROFILE_TESTED_MERGE_SHA is required}"
export GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 GIT_ATTR_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

ACTIVE_PHASE=
ACTIVE_SAMPLER_PID=
ACTIVE_SAMPLER_SENTINEL=
ACTIVE_OOM=0
ACTIVE_OOM_KILL=0
ACTIVE_PGDATA=
ACTIVE_PGBIN=

mkdir -p "$STATE_ROOT" "$PGSOCKET" "$MINIO_DATA"
chmod 700 "$STATE_ROOT" "$PGSOCKET" "$MINIO_DATA"
: > "$MEMORY_LOG"
: > "$MEMORY_SUMMARY"

read_cgroup_value() {
  local name=$1 value
  if [[ -r "/sys/fs/cgroup/$name" ]]; then value=$(cat "/sys/fs/cgroup/$name"); else value=0; fi
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$value"
}

read_memory_event() {
  local key=$1 value
  value=$(awk -v key="$key" '$1 == key { print $2 }' /sys/fs/cgroup/memory.events)
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$value"
}

memory_sampler() {
  local phase=$1 sentinel=$2 current peak swap_current swap_peak pids oom oom_kill
  while [[ -e "$sentinel" ]]; do
    current=$(read_cgroup_value memory.current)
    peak=$(read_cgroup_value memory.peak)
    swap_current=$(read_cgroup_value memory.swap.current)
    swap_peak=$(read_cgroup_value memory.swap.peak)
    pids=$(read_cgroup_value pids.current)
    oom=$(read_memory_event oom)
    oom_kill=$(read_memory_event oom_kill)
    printf '{"phase":"%s","epoch_seconds":%s,"memory_current_bytes":%s,"memory_peak_bytes":%s,"memory_swap_current_bytes":%s,"memory_swap_peak_bytes":%s,"pids_current":%s,"oom":%s,"oom_kill":%s}\n' \
      "$phase" "$(date +%s)" "$current" "$peak" "$swap_current" "$swap_peak" "$pids" "$oom" "$oom_kill" >> "$MEMORY_LOG"
    sleep 1
  done
}

start_phase_measurement() {
  local phase=$1
  [[ -z "$ACTIVE_PHASE" ]]
  ACTIVE_PHASE=$phase
  ACTIVE_OOM=$(read_memory_event oom)
  ACTIVE_OOM_KILL=$(read_memory_event oom_kill)
  ACTIVE_SAMPLER_SENTINEL="$STATE_ROOT/memory-$phase.running"
  : > "$ACTIVE_SAMPLER_SENTINEL"
  memory_sampler "$phase" "$ACTIVE_SAMPLER_SENTINEL" &
  ACTIVE_SAMPLER_PID=$!
}

finish_phase_measurement() {
  local phase=$1 oom_after oom_kill_after phase_peak phase_swap_peak oom_delta oom_kill_delta
  [[ "$ACTIVE_PHASE" == "$phase" ]]
  unlink "$ACTIVE_SAMPLER_SENTINEL" 2>/dev/null || true
  wait "$ACTIVE_SAMPLER_PID" 2>/dev/null || true
  oom_after=$(read_memory_event oom)
  oom_kill_after=$(read_memory_event oom_kill)
  oom_delta=$((oom_after - ACTIVE_OOM))
  oom_kill_delta=$((oom_kill_after - ACTIVE_OOM_KILL))
  # Enforce the limit from root-owned cgroup counters. JSONL is diagnostic
  # only: untrusted workload code may share the runner UID and mutate it.
  phase_peak=$(read_cgroup_value memory.peak)
  phase_swap_peak=$(read_cgroup_value memory.swap.peak)
  printf '{"phase":"%s","memory_peak_bytes":%s,"memory_swap_peak_bytes":%s,"oom_delta":%s,"oom_kill_delta":%s,"fit_limit_bytes":%s}\n' \
    "$phase" "$phase_peak" "$phase_swap_peak" "$oom_delta" "$oom_kill_delta" "$MEMORY_FIT_LIMIT_BYTES" | tee -a "$MEMORY_SUMMARY"
  ACTIVE_PHASE=
  ACTIVE_SAMPLER_PID=
  ACTIVE_SAMPLER_SENTINEL=
  (( oom_delta == 0 ))
  (( oom_kill_delta == 0 ))
  (( phase_peak < MEMORY_FIT_LIMIT_BYTES ))
}

require_image_contract() {
  local chromium_candidates headless_candidates
  (( EUID >= 1000 ))
  [[ ! -w /sys/fs/cgroup/memory.peak && ! -w /sys/fs/cgroup/memory.events ]]
  [[ $(cat /sys/fs/cgroup/memory.max) == "$EXPECTED_MEMORY_BYTES" ]]
  [[ $(bun --version) == 1.4.0 ]]
  [[ $(uv --version) == "uv 0.8.22" ]]
  [[ $(python3 --version) == "Python 3.12."* ]]
  [[ $($PG16_BIN/psql --version) == "psql (PostgreSQL) 16."* ]]
  [[ $($PG17_BIN/psql --version) == "psql (PostgreSQL) 17."* ]]
  [[ -x "$WATERFALL_ROOT/.venv/bin/python" ]]
  [[ $(<"$WATERFALL_ROOT/.self-hosted-ci-commit") == "$WATERFALL_REVISION" ]]
  chromium_candidates=(/opt/ms-playwright/chromium-1217*/chrome-linux*/chrome)
  [[ ${#chromium_candidates[@]} == 1 && -x ${chromium_candidates[0]} ]]
  headless_candidates=(/opt/ms-playwright/chromium_headless_shell-1217*/chrome-headless-shell-linux*/chrome-headless-shell)
  [[ ${#headless_candidates[@]} == 1 && -x ${headless_candidates[0]} ]]
  command -v minio mc bun uv curl unlink cp sha256sum stat >/dev/null
  [[ -x $PG16_BIN/initdb && -x $PG16_BIN/pg_ctl && -x $PG16_BIN/createdb ]]
  [[ -x $PG17_BIN/initdb && -x $PG17_BIN/pg_ctl && -x $PG17_BIN/createdb ]]
}

install_prebaked_node_modules() {
  local component=$1 expected_lock=$2 prebaked=$3 target="$component/node_modules" permissions
  [[ $(sha256sum "$component/bun.lock" | awk '{print $1}') == "$expected_lock" ]]
  [[ -d "$prebaked" && ! -L "$prebaked" && ! -e "$target" && ! -L "$target" ]]
  [[ $(stat -c %u "$prebaked") == 0 ]]
  permissions=$(stat -c %A "$prebaked")
  [[ ${permissions:5:1} != w && ${permissions:8:1} != w ]]
  cp -a "$prebaked" "$target"
  (cd "$component" && BUN_INSTALL_CACHE_DIR=/opt/self-hosted-ci/overworld-deps/bun-cache \
    bun install --frozen-lockfile --offline)
}

prepare_workspace() {
  local phase=$1
  [[ "$TESTED_MERGE_SHA" =~ ^[0-9a-f]{40}$ ]]
  [[ -d .git && ! -L .git && -d .git/objects && ! -L .git/objects ]]
  [[ ! -e .git/commondir && ! -e .git/config.worktree ]]
  [[ ! -e .git/info/attributes && ! -e .git/info/sparse-checkout && ! -e .git/modules ]]
  [[ -z $(/usr/bin/git for-each-ref --format='%(refname)' refs/replace) ]]
  [[ ! -e .git/objects/info/alternates && ! -e .git/info/grafts ]]
  printf '[core]\n\trepositoryformatversion = 0\n\tbare = false\n\thooksPath = /dev/null\n\tfsmonitor = false\n' > .git/config
  /usr/bin/git -c core.attributesFile=/dev/null reset --hard "$TESTED_MERGE_SHA" >/dev/null
  /usr/bin/git -c core.attributesFile=/dev/null clean -ffdx >/dev/null
  [[ $(/usr/bin/git rev-parse HEAD) == "$TESTED_MERGE_SHA" ]]
  [[ $(/usr/bin/git rev-parse 'HEAD^{tree}') == $(/usr/bin/git rev-parse "$TESTED_MERGE_SHA^{tree}") ]]
  case "$phase" in
    backend) install_prebaked_node_modules backend "$BACKEND_LOCK_SHA256" "$BACKEND_MODULES" ;;
    frontend|e2e)
      install_prebaked_node_modules backend "$BACKEND_LOCK_SHA256" "$BACKEND_MODULES"
      install_prebaked_node_modules frontend "$FRONTEND_LOCK_SHA256" "$FRONTEND_MODULES"
      ;;
    *) return 1 ;;
  esac
}

stop_postgres() {
  if [[ -n "$ACTIVE_PGDATA" && -s "$ACTIVE_PGDATA/PG_VERSION" ]]; then
    "$ACTIVE_PGBIN/pg_ctl" -D "$ACTIVE_PGDATA" -m immediate -w stop >/dev/null
  fi
  ACTIVE_PGDATA=
  ACTIVE_PGBIN=
}

stop_local_services() {
  local name pid
  for name in frontend backend minio; do
    if [[ -f "$STATE_ROOT/$name.pid" ]]; then
      pid=$(cat "$STATE_ROOT/$name.pid")
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      unlink "$STATE_ROOT/$name.pid" 2>/dev/null || true
    fi
  done
}

cleanup() {
  local status=$? log
  trap - EXIT INT TERM
  set +e
  if [[ -n "$ACTIVE_PHASE" ]]; then finish_phase_measurement "$ACTIVE_PHASE"; fi
  stop_local_services
  stop_postgres
  if (( status != 0 )); then
    for log in "$STATE_ROOT/backend.log" "$STATE_ROOT/frontend.log" "$STATE_ROOT/minio.log"; do
      if [[ -s "$log" ]]; then
        printf '=== failure log: %s ===\n' "$(basename "$log")" >&2
        tail -n 200 "$log" >&2
      fi
    done
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_postgres() {
  local major=$1 data=$2 port=$3 expected_postgis=$4 database bin
  bin="/usr/lib/postgresql/$major/bin"
  "$bin/initdb" -D "$data" --username=overworld --auth=trust --no-instructions >/dev/null
  "$bin/pg_ctl" -D "$data" -o "-F -k $PGSOCKET -p $port -h 127.0.0.1" -w start >/dev/null
  ACTIVE_PGDATA=$data
  ACTIVE_PGBIN=$bin
  for database in "${@:5}"; do "$bin/createdb" -h 127.0.0.1 -p "$port" -U overworld "$database"; done
  local extension_database=overworld
  [[ "$major" == 16 ]] && extension_database=drift
  "$bin/psql" -h 127.0.0.1 -p "$port" -U overworld -d "$extension_database" -c 'CREATE EXTENSION IF NOT EXISTS postgis' >/dev/null
  [[ $("$bin/psql" -h 127.0.0.1 -p "$port" -U overworld -d "$extension_database" -Atc "SELECT extversion FROM pg_extension WHERE extname='postgis'") == "$expected_postgis".* ]]
}

start_minio() {
  MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin minio server "$MINIO_DATA" \
    --address "127.0.0.1:$MINIO_PORT" >"$STATE_ROOT/minio.log" 2>&1 &
  echo $! > "$STATE_ROOT/minio.pid"
  for attempt in $(seq 1 30); do
    curl --fail --silent "http://127.0.0.1:$MINIO_PORT/minio/health/ready" >/dev/null && break
    [[ "$attempt" -lt 30 ]] || return 1
    sleep 1
  done
  mc alias set local "http://127.0.0.1:$MINIO_PORT" minioadmin minioadmin >/dev/null
  mc mb --ignore-existing local/overworld-e2e >/dev/null
}

phase_backend() {
  start_postgres 16 "$PG16_DATA" "$BACKEND_PGPORT" 3.4 overworld drift fieldnotebook dataevidence towerchannel
  export DATABASE_URL="postgresql://overworld@127.0.0.1:$BACKEND_PGPORT/overworld"
  export JWT_SECRET=ci-jwt-secret-not-a-real-key BETTER_AUTH_SECRET=ci-better-auth-secret-not-a-real-key
  export NODE_ENV=test WATERFALL_SOURCE_PATH="$WATERFALL_ROOT"
  uv sync --frozen --offline --check --project "$WATERFALL_ROOT"
  PYTHONPATH="$WATERFALL_ROOT:$WATERFALL_ROOT/src" "$WATERFALL_ROOT/.venv/bin/pyright" \
    backend/src/modules/methodology-obligations/waterfall-stage-push-contract.py
  (cd backend && bun run lint)
  (cd backend && bun run typecheck)
  (cd backend && bun run db:check-drift --database-url "postgresql://overworld@127.0.0.1:$BACKEND_PGPORT/drift")
  (cd backend && FIELD_NOTEBOOK_PG_URL="postgresql://overworld@127.0.0.1:$BACKEND_PGPORT/fieldnotebook" \
    DATA_EVIDENCE_PG_URL="postgresql://overworld@127.0.0.1:$BACKEND_PGPORT/dataevidence" \
    TOWER_CHANNEL_PG_URL="postgresql://overworld@127.0.0.1:$BACKEND_PGPORT/towerchannel" bun run test)
  start_minio
  (cd backend && export INVENTORY_REPORT_CONTRACT=true \
    TEST_DATABASE_URL="postgresql://overworld@127.0.0.1:$BACKEND_PGPORT/postgres" \
    WATERFALL_SOURCE_PATH="$WATERFALL_ROOT" S3_BUCKET=overworld-e2e \
    S3_ENDPOINT="http://127.0.0.1:$MINIO_PORT" S3_PUBLIC_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
    AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin; \
    bun test src/database/migration-0072-site-inflight.pg.test.ts; \
    bun test src/modules/inference/inference-run-site-inflight.pg.test.ts; \
    bun test src/modules/inference/inventory-to-report.stage-push.contract.pg.test.ts)
  stop_local_services
  stop_postgres
}

phase_frontend() {
  (cd frontend && bun run lint -- --max-warnings 0)
  (cd backend && bun run build:types)
  (cd frontend && bun run typecheck)
  (cd frontend && bun run test -- --ci)
}

phase_e2e() {
  start_postgres 17 "$PG17_DATA" "$E2E_PGPORT" 3.5 overworld
  start_minio
  export DATABASE_URL="postgresql://overworld@127.0.0.1:$E2E_PGPORT/overworld"
  export DB_MIGRATE=true DB_RESET=true JWT_SECRET=ci-jwt-secret-not-a-real-key
  export BETTER_AUTH_SECRET=ci-better-auth-secret-not-a-real-key BETTER_AUTH_URL="http://localhost:$BACKEND_PORT"
  export APP_URL="http://localhost:$FRONTEND_PORT" ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=123321
  export S3_BUCKET=overworld-e2e S3_REGION=us-east-1 S3_ENDPOINT="http://127.0.0.1:$MINIO_PORT"
  export S3_PUBLIC_ENDPOINT="http://127.0.0.1:$MINIO_PORT" AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
  (cd backend && exec env PORT=$BACKEND_PORT bun run src/index.ts) >"$STATE_ROOT/backend.log" 2>&1 &
  echo $! > "$STATE_ROOT/backend.pid"
  for attempt in $(seq 1 90); do
    curl --fail --silent "http://127.0.0.1:$BACKEND_PORT/ready" >/dev/null && break
    [[ "$attempt" -lt 90 ]] || return 1
    sleep 2
  done
  (cd frontend && exec env FRONTEND_PORT=$FRONTEND_PORT BACKEND_URL="http://127.0.0.1:$BACKEND_PORT" bun run dev) >"$STATE_ROOT/frontend.log" 2>&1 &
  echo $! > "$STATE_ROOT/frontend.pid"
  for attempt in $(seq 1 60); do
    curl --fail --silent "http://127.0.0.1:$FRONTEND_PORT" >/dev/null && break
    [[ "$attempt" -lt 60 ]] || return 1
    sleep 2
  done
  local pg_test
  local pg_tests=(
    src/modules/organization/invitations/service.pg.test.ts
    src/modules/auth/session.pg.test.ts
    src/modules/provider/producers/routes.pg.test.ts
    src/metrics/mrv-grid-sql.pg.test.ts
    src/modules/audit/service.pg.test.ts
    src/modules/inference/closure-pin.pg.test.ts
    src/modules/inference/mrv-freeze-lock.pg.test.ts
    src/audit/routes.pg.test.ts
    src/audit/routes-lot-mutations.pg.test.ts
    src/audit/routes-profile.pg.test.ts
    src/audit/routes-admin-ingest.pg.test.ts
    src/modules/portfolio/service.pg.test.ts
    src/modules/organization/projects/registry-submissions/service.pg.test.ts
    src/modules/observability/series-qc-data.pg.test.ts
    src/modules/quantification/flux-provenance.pg.test.ts
    src/modules/quantification/declared-deduction-assessments.pg.test.ts
    src/modules/inference/methodology-gate-migration.pg.test.ts
    src/database/dev-seed/san-joaquin.pg.test.ts
    src/modules/inference/series-coverage.pg.test.ts
    src/modules/reports/grants.pg.test.ts
    src/modules/explore/grants.pg.test.ts
    src/modules/dashboard/data/grants.pg.test.ts
    src/modules/inference/pushes.pg.test.ts
    src/modules/quantification/cycle-activity.pg.test.ts
    src/metrics/engine-adoption.pg.test.ts
    src/metrics/metrics-mv-gated.pg.test.ts
    src/database/migrate.pg.test.ts
    src/modules/internal/inference/idempotency.pg.test.ts
    src/modules/internal/inference/runs/runs.pg.test.ts
    src/modules/internal/cycles/closure-inputs/closure-inputs.pg.test.ts
    src/modules/producer/sites/cycles/methodology-profile/service.pg.test.ts
    src/modules/producer/sites/cycles/activity-declarations/service.pg.test.ts
    src/modules/methodology-obligations/service.pg.test.ts
    src/modules/internal/towers/sensor-data/export.pg.test.ts
  )
  for pg_test in "${pg_tests[@]}"; do (cd backend && TEST_DATABASE_URL="$DATABASE_URL" bun test "$pg_test"); done
  CI=true E2E_BASE_URL="http://localhost:$FRONTEND_PORT" PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    bun run --cwd frontend playwright test e2e/auth-flow.spec.ts e2e/a11y.spec.ts --reporter=list
  stop_local_services
  stop_postgres
}

require_image_contract
for phase in backend frontend e2e; do
  prepare_workspace "$phase"
  start_phase_measurement "$phase"
  "phase_$phase"
  finish_phase_measurement "$phase"
done
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '## Overworld local CI memory\n\n```json\n'
    cat "$MEMORY_SUMMARY"
    printf '```\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi
