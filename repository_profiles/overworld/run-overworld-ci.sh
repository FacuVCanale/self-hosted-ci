#!/usr/bin/env bash
set -euo pipefail

# Executable half of overworld-ci-v1. It accepts no arguments or shell-code
# indirection; the immutable Action selects it after every identity check.

readonly EXPECTED_MEMORY_BYTES=4294967296
# Incus/cgroup v2 stores memory.high at page granularity. This is the
# page-aligned value observed for the configured 90% of the 4 GiB hard limit.
readonly MEMORY_FIT_LIMIT_BYTES=3865468928
# The peak bound rejects material memory.high overshoot. Reclaim pressure is
# evaluated separately as time-normalized PSI stall budgets per phase because
# memory.events high counts reclaim attempts, not their duration or severity.
readonly MEMORY_HIGH_OVERSHOOT_TOLERANCE_BYTES=4194304
readonly MEMORY_PRESSURE_SOME_LIMIT_PERCENT=10
readonly MEMORY_PRESSURE_FULL_LIMIT_PERCENT=5
readonly WATERFALL_REVISION=6df90210830b2ebe36eda6b96d91237914d000e4
readonly WATERFALL_ROOT=/opt/self-hosted-ci/overworld-deps/waterfall
readonly BACKEND_LOCK_SHA256=b235110fe83b4b3a4eafb337efc0bb8d7424aea33a72f0338b2192892ce79fdb
readonly FRONTEND_LOCK_SHA256=6004b42bc89358fc0d83f81f8015658246139ce830e1e569279700850e5d63b3
readonly BACKEND_MODULES=/opt/self-hosted-ci/overworld-deps/backend-node_modules
readonly FRONTEND_MODULES=/opt/self-hosted-ci/overworld-deps/frontend-node_modules
readonly NEXT_NODE=/usr/local/bin/node
readonly NEXT_NODE_SHA256=3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327
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
readonly NEXT_FONT_ASSET_ROOT=/opt/self-hosted-ci/overworld-profile-assets
readonly NEXT_FONT_MOCK="$NEXT_FONT_ASSET_ROOT/next-font-google-mocked-responses.cjs"
readonly NEXT_FONT_MOCK_SHA256=c137ca4b0b65cea2c2f37f202ce2d174d0db55c36755ff43540bd24f98cf67ff
readonly GEIST_FONT="$NEXT_FONT_ASSET_ROOT/fonts/Geist[wght].ttf"
readonly GEIST_FONT_SHA256=73894e0448cae90a92b6c2f8732b7bb9acb7b94c418bff559dad4a18e1de9659
readonly GEIST_MONO_FONT="$NEXT_FONT_ASSET_ROOT/fonts/GeistMono[wght].ttf"
readonly GEIST_MONO_FONT_SHA256=d00e590b8eb3a59acc329b2d044fd143ae935090b7da33199ebee27cc7de8196
readonly FRAGMENT_MONO_FONT="$NEXT_FONT_ASSET_ROOT/fonts/FragmentMono-Regular.ttf"
readonly FRAGMENT_MONO_FONT_SHA256=0fe011f425873c2e0fc73a189e394e340ad48d2b9a99a576bdeec75cee000460
readonly TESTED_MERGE_SHA="${PROFILE_TESTED_MERGE_SHA:?PROFILE_TESTED_MERGE_SHA is required}"
export GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1 GIT_ATTR_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export UV_OFFLINE=1 UV_NO_SYNC=1

ACTIVE_PHASE=
ACTIVE_SAMPLER_PID=
ACTIVE_SAMPLER_SENTINEL=
ACTIVE_OOM=0
ACTIVE_OOM_KILL=0
ACTIVE_HIGH=0
ACTIVE_MAX=0
ACTIVE_PRESSURE_SOME=0
ACTIVE_PRESSURE_FULL=0
ACTIVE_STARTED_MONOTONIC_USEC=0
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

read_memory_pressure_total() {
  local stall=$1 line total
  line=$(awk -v stall="$stall" '$1 == stall { if (seen++) exit 2; print } END { if (!seen) exit 1 }' \
    /sys/fs/cgroup/memory.pressure) || return 1
  [[ "$line" =~ ^(some|full)\ avg10=[0-9]+\.[0-9]+\ avg60=[0-9]+\.[0-9]+\ avg300=[0-9]+\.[0-9]+\ total=[0-9]+$ ]] || return 1
  [[ ${BASH_REMATCH[1]} == "$stall" ]] || return 1
  total=${line##* total=}
  [[ "$total" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$total"
}

read_monotonic_usec() {
  local line seconds fraction fraction_usec
  line=$(awk 'NR == 1 { line = $0; next } { extra = 1 } END { if (NR != 1 || extra) exit 1; print line }' \
    /proc/uptime) || return 1
  [[ "$line" =~ ^([0-9]+)\.([0-9]{2})\ ([0-9]+)\.([0-9]{2})$ ]] || return 1
  seconds=${BASH_REMATCH[1]}
  fraction=${BASH_REMATCH[2]}
  while [[ ${#seconds} -gt 1 && ${seconds:0:1} == 0 ]]; do seconds=${seconds:1}; done
  if [[ ${#seconds} -gt 13 || ( ${#seconds} -eq 13 && "$seconds" > 9223372036854 ) ]]; then return 1; fi
  fraction_usec=$((10#$fraction * 10000))
  if [[ "$seconds" == 9223372036854 ]] && (( fraction_usec > 775807 )); then return 1; fi
  printf '%s' "$((10#$seconds * 1000000 + fraction_usec))"
}

reset_phase_measurement_state() {
  ACTIVE_PHASE=
  ACTIVE_SAMPLER_PID=
  ACTIVE_SAMPLER_SENTINEL=
  ACTIVE_OOM=0
  ACTIVE_OOM_KILL=0
  ACTIVE_HIGH=0
  ACTIVE_MAX=0
  ACTIVE_PRESSURE_SOME=0
  ACTIVE_PRESSURE_FULL=0
  ACTIVE_STARTED_MONOTONIC_USEC=0
}

memory_sampler() {
  local phase=$1 sentinel=$2 current peak swap_current swap_peak pids oom oom_kill high max pressure_some pressure_full
  while [[ -e "$sentinel" ]]; do
    current=$(read_cgroup_value memory.current)
    peak=$(read_cgroup_value memory.peak)
    swap_current=$(read_cgroup_value memory.swap.current)
    swap_peak=$(read_cgroup_value memory.swap.peak)
    pids=$(read_cgroup_value pids.current)
    oom=$(read_memory_event oom)
    oom_kill=$(read_memory_event oom_kill)
    high=$(read_memory_event high)
    max=$(read_memory_event max)
    pressure_some=$(read_memory_pressure_total some)
    pressure_full=$(read_memory_pressure_total full)
    printf '{"phase":"%s","epoch_seconds":%s,"memory_current_bytes":%s,"memory_peak_bytes":%s,"memory_swap_current_bytes":%s,"memory_swap_peak_bytes":%s,"pids_current":%s,"oom":%s,"oom_kill":%s,"memory_high_events":%s,"memory_max_events":%s,"memory_pressure_some_total_usec":%s,"memory_pressure_full_total_usec":%s}\n' \
      "$phase" "$(date +%s)" "$current" "$peak" "$swap_current" "$swap_peak" "$pids" "$oom" "$oom_kill" "$high" "$max" "$pressure_some" "$pressure_full" >> "$MEMORY_LOG"
    sleep 1
  done
}

start_phase_measurement() {
  local phase=$1 oom oom_kill high max pressure_some pressure_full started_monotonic_usec sentinel sampler_pid
  [[ -z "$ACTIVE_PHASE" ]]
  if ! oom=$(read_memory_event oom); then return 1; fi
  if ! oom_kill=$(read_memory_event oom_kill); then return 1; fi
  if ! high=$(read_memory_event high); then return 1; fi
  if ! max=$(read_memory_event max); then return 1; fi
  if ! pressure_some=$(read_memory_pressure_total some); then return 1; fi
  if ! pressure_full=$(read_memory_pressure_total full); then return 1; fi
  if ! started_monotonic_usec=$(read_monotonic_usec); then return 1; fi
  sentinel="$STATE_ROOT/memory-$phase.running"
  if ! : > "$sentinel"; then return 1; fi
  memory_sampler "$phase" "$sentinel" &
  sampler_pid=$!
  ACTIVE_PHASE=$phase
  ACTIVE_OOM=$oom
  ACTIVE_OOM_KILL=$oom_kill
  ACTIVE_HIGH=$high
  ACTIVE_MAX=$max
  ACTIVE_PRESSURE_SOME=$pressure_some
  ACTIVE_PRESSURE_FULL=$pressure_full
  ACTIVE_STARTED_MONOTONIC_USEC=$started_monotonic_usec
  ACTIVE_SAMPLER_SENTINEL=$sentinel
  ACTIVE_SAMPLER_PID=$sampler_pid
}

finish_phase_measurement() {
  local phase=$1 oom_after oom_kill_after high_after max_after pressure_some_after pressure_full_after finished_monotonic_usec
  local oom_before oom_kill_before high_before max_before pressure_some_before pressure_full_before started_monotonic_usec
  local phase_peak phase_swap_peak oom_delta oom_kill_delta high_delta max_delta pressure_some_delta pressure_full_delta
  local elapsed_usec pressure_some_budget pressure_full_budget pressure_some_ratio_basis_points pressure_full_ratio_basis_points
  local read_status=0 finalizer_status=0 sampler_status=0 sampler_pid sentinel
  [[ "$ACTIVE_PHASE" == "$phase" ]]
  sampler_pid=$ACTIVE_SAMPLER_PID
  sentinel=$ACTIVE_SAMPLER_SENTINEL
  oom_before=$ACTIVE_OOM
  oom_kill_before=$ACTIVE_OOM_KILL
  high_before=$ACTIVE_HIGH
  max_before=$ACTIVE_MAX
  pressure_some_before=$ACTIVE_PRESSURE_SOME
  pressure_full_before=$ACTIVE_PRESSURE_FULL
  started_monotonic_usec=$ACTIVE_STARTED_MONOTONIC_USEC
  if ! oom_after=$(read_memory_event oom); then read_status=1; fi
  if ! oom_kill_after=$(read_memory_event oom_kill); then read_status=1; fi
  if ! high_after=$(read_memory_event high); then read_status=1; fi
  if ! max_after=$(read_memory_event max); then read_status=1; fi
  if ! pressure_some_after=$(read_memory_pressure_total some); then read_status=1; fi
  if ! pressure_full_after=$(read_memory_pressure_total full); then read_status=1; fi
  if ! finished_monotonic_usec=$(read_monotonic_usec); then read_status=1; fi
  if ! phase_peak=$(read_cgroup_value memory.peak); then read_status=1; fi
  if ! phase_swap_peak=$(read_cgroup_value memory.swap.peak); then read_status=1; fi
  if ! unlink "$sentinel" 2>/dev/null; then finalizer_status=1; fi
  wait "$sampler_pid" 2>/dev/null || sampler_status=$?
  reset_phase_measurement_state
  (( read_status == 0 && finalizer_status == 0 )) || return 1
  oom_delta=$((oom_after - oom_before))
  oom_kill_delta=$((oom_kill_after - oom_kill_before))
  high_delta=$((high_after - high_before))
  max_delta=$((max_after - max_before))
  pressure_some_delta=$((pressure_some_after - pressure_some_before))
  pressure_full_delta=$((pressure_full_after - pressure_full_before))
  elapsed_usec=$((finished_monotonic_usec - started_monotonic_usec))
  (( elapsed_usec > 0 && pressure_some_delta >= 0 && pressure_full_delta >= 0 )) || return 1
  pressure_some_budget=$((elapsed_usec * MEMORY_PRESSURE_SOME_LIMIT_PERCENT / 100))
  pressure_full_budget=$((elapsed_usec * MEMORY_PRESSURE_FULL_LIMIT_PERCENT / 100))
  pressure_some_ratio_basis_points=$(((pressure_some_delta * 10000 + elapsed_usec - 1) / elapsed_usec))
  pressure_full_ratio_basis_points=$(((pressure_full_delta * 10000 + elapsed_usec - 1) / elapsed_usec))
  # Enforce the limit from root-owned cgroup counters. JSONL is diagnostic
  # only: untrusted workload code may share the runner UID and mutate it.
  printf '{"phase":"%s","memory_peak_bytes":%s,"memory_swap_peak_bytes":%s,"oom_delta":%s,"oom_kill_delta":%s,"memory_high_events_delta":%s,"memory_max_events_delta":%s,"memory_pressure_some_delta_usec":%s,"memory_pressure_full_delta_usec":%s,"phase_elapsed_monotonic_usec":%s,"memory_pressure_some_budget_usec":%s,"memory_pressure_full_budget_usec":%s,"memory_pressure_some_ratio_basis_points":%s,"memory_pressure_full_ratio_basis_points":%s,"memory_pressure_some_limit_percent":%s,"memory_pressure_full_limit_percent":%s,"fit_limit_bytes":%s,"memory_high_overshoot_tolerance_bytes":%s}\n' \
    "$phase" "$phase_peak" "$phase_swap_peak" "$oom_delta" "$oom_kill_delta" "$high_delta" "$max_delta" "$pressure_some_delta" "$pressure_full_delta" "$elapsed_usec" "$pressure_some_budget" "$pressure_full_budget" "$pressure_some_ratio_basis_points" "$pressure_full_ratio_basis_points" "$MEMORY_PRESSURE_SOME_LIMIT_PERCENT" "$MEMORY_PRESSURE_FULL_LIMIT_PERCENT" "$MEMORY_FIT_LIMIT_BYTES" "$MEMORY_HIGH_OVERSHOOT_TOLERANCE_BYTES" | tee -a "$MEMORY_SUMMARY"
  (( sampler_status == 0 && oom_delta == 0 && oom_kill_delta == 0 &&
     high_delta >= 0 && max_delta == 0 &&
     pressure_some_delta <= pressure_some_budget && pressure_full_delta <= pressure_full_budget &&
     phase_swap_peak == 0 &&
     phase_peak < MEMORY_FIT_LIMIT_BYTES + MEMORY_HIGH_OVERSHOOT_TOLERANCE_BYTES ))
}

require_image_contract() {
  local chromium_candidates headless_candidates privilege_helper=/usr/bin/sudo
  (( EUID >= 1000 ))
  [[ $(stat -c %U:%G:%a "$privilege_helper") == root:root:750 && ! -x "$privilege_helper" ]]
  [[ ! -w /sys/fs/cgroup/memory.peak && ! -w /sys/fs/cgroup/memory.events && ! -w /sys/fs/cgroup/memory.pressure ]]
  [[ -r /sys/fs/cgroup/memory.current && -r /sys/fs/cgroup/memory.peak ]]
  [[ -r /sys/fs/cgroup/memory.swap.current && -r /sys/fs/cgroup/memory.swap.peak ]]
  [[ -r /sys/fs/cgroup/memory.events && -r /sys/fs/cgroup/memory.pressure && -r /sys/fs/cgroup/pids.current ]]
  [[ $(cat /sys/fs/cgroup/memory.max) == "$EXPECTED_MEMORY_BYTES" ]]
  [[ $(cat /sys/fs/cgroup/memory.high) == "$MEMORY_FIT_LIMIT_BYTES" ]]
  [[ $(bun --version) == 1.4.0 ]]
  [[ $(node --version) == v22.23.2 ]]
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
  command -v minio mc node bun uv curl unlink cp sha256sum stat >/dev/null
  [[ -x $PG16_BIN/initdb && -x $PG16_BIN/pg_ctl && -x $PG16_BIN/createdb ]]
  [[ -x $PG17_BIN/initdb && -x $PG17_BIN/pg_ctl && -x $PG17_BIN/createdb ]]
}

install_prebaked_node_modules() {
  local component expected_lock prebaked target cache temporary permissions
  component=$1
  expected_lock=$2
  prebaked=$3
  target="$component/node_modules"
  cache="$STATE_ROOT/bun-cache-$component"
  temporary="$STATE_ROOT/bun-tmp-$component"
  [[ $(sha256sum "$component/bun.lock" | awk '{print $1}') == "$expected_lock" ]]
  [[ -d "$prebaked" && ! -L "$prebaked" && ! -e "$target" && ! -L "$target" ]]
  [[ $(stat -c %u "$prebaked") == 0 ]]
  permissions=$(stat -c %A "$prebaked")
  [[ ${permissions:5:1} != w && ${permissions:8:1} != w ]]
  cp -a "$prebaked" "$target"
  mkdir -p "$cache" "$temporary"
  chmod 700 "$cache" "$temporary"
  if [[ "$component" == backend ]]; then
    (cd "$component" && BUN_INSTALL_CACHE_DIR="$cache" TMPDIR="$temporary" \
      bun install --frozen-lockfile --offline --ignore-scripts)
  else
    (cd "$component" && bun -e \
      'require("./node_modules/next/dist/server/node-environment-extensions/console-file.js")')
  fi
}

normalize_checkout_worktree_config() {
  local worktree_config=.git/config.worktree runner_identity
  if [[ ! -e "$worktree_config" && ! -L "$worktree_config" ]]; then return 0; fi
  [[ -f "$worktree_config" && ! -L "$worktree_config" ]]
  runner_identity="$(id -u):$(id -g)"
  [[ $(stat -c %u:%g:%a:%s "$worktree_config") == "$runner_identity:644:83" ]]
  [[ $(sha256sum "$worktree_config" | awk '{print $1}') == 443a5f645c23c3d0c0aa09f634b2ad111d46ef61946b598a2fb311678ab47454 ]]
  unlink "$worktree_config"
  [[ ! -e "$worktree_config" && ! -L "$worktree_config" ]]
}

prepare_workspace() {
  local phase=$1
  [[ "$TESTED_MERGE_SHA" =~ ^[0-9a-f]{40}$ ]]
  [[ -d .git && ! -L .git && -d .git/objects && ! -L .git/objects ]]
  [[ ! -e .git/commondir ]]
  # actions/checkout disables sparse checkout through a worktree-local config.
  # Accept only that exact inert file, then remove it before replacing .git/config.
  normalize_checkout_worktree_config
  [[ ! -e .git/info/attributes && ! -e .git/info/sparse-checkout && ! -e .git/modules ]]
  [[ -z $(/usr/bin/git for-each-ref --format='%(refname)' refs/replace) ]]
  [[ ! -e .git/objects/info/alternates && ! -e .git/info/grafts ]]
  printf '[core]\n\trepositoryformatversion = 0\n\tbare = false\n\thooksPath = /dev/null\n\tfsmonitor = false\n' > .git/config
  [[ ! -e .git/index.lock ]]
  unlink .git/index 2>/dev/null || true
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

reset_backend_service_data() {
  local path runner_identity
  [[ "$PG16_DATA" == "$STATE_ROOT/postgres-16" ]] || return 1
  [[ "$MINIO_DATA" == "$STATE_ROOT/minio" ]] || return 1
  runner_identity="$(id -u):$(id -g)"
  for path in "$PG16_DATA" "$MINIO_DATA"; do
    if [[ -e "$path" || -L "$path" ]]; then
      [[ -d "$path" && ! -L "$path" ]] || return 1
      [[ $(stat -c '%u:%g:%a' "$path") == "$runner_identity:700" ]] || return 1
    fi
  done
  rm -rf -- "$PG16_DATA" "$MINIO_DATA"
  [[ ! -e "$PG16_DATA" && ! -L "$PG16_DATA" ]] || return 1
  [[ ! -e "$MINIO_DATA" && ! -L "$MINIO_DATA" ]] || return 1
  mkdir "$MINIO_DATA"
  chmod 700 "$MINIO_DATA"
  [[ $(stat -c '%u:%g:%a' "$MINIO_DATA") == "$runner_identity:700" ]] || return 1
}

stop_local_service() {
  local name=$1 pid
  if [[ -f "$STATE_ROOT/$name.pid" ]]; then
    pid=$(cat "$STATE_ROOT/$name.pid")
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    unlink "$STATE_ROOT/$name.pid" 2>/dev/null || true
  fi
}

stop_local_services() {
  local name
  for name in frontend backend minio; do stop_local_service "$name"; done
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
  "$bin/pg_ctl" -D "$data" -o "-F -c shared_buffers=32MB -k $PGSOCKET -p $port -h 127.0.0.1" -w start >/dev/null
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
  uv --no-config pip check --python "$WATERFALL_ROOT/.venv/bin/python"
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
  reset_backend_service_data
}

phase_frontend() {
  (cd frontend && bun ./node_modules/.bin/eslint --max-warnings 0)
  (cd backend && bun run build:types)
  (cd frontend && bun ./node_modules/.bin/tsc --noEmit)
  (cd frontend && NODE_ENV=test bun ./node_modules/.bin/jest --ci)
}

start_backend() {
  (cd backend && exec env PORT=$BACKEND_PORT bun run src/index.ts) >"$STATE_ROOT/backend.log" 2>&1 &
  echo $! > "$STATE_ROOT/backend.pid"
  for attempt in $(seq 1 90); do
    curl --fail --silent "http://127.0.0.1:$BACKEND_PORT/ready" >/dev/null && break
    [[ "$attempt" -lt 90 ]] || return 1
    sleep 2
  done
}

require_pinned_root_file() {
  local path=$1 expected_sha256=$2 metadata
  [[ -f "$path" && ! -L "$path" ]] || return 1
  metadata=$(stat -c '%u:%g:%a' "$path") || return 1
  [[ "$metadata" == 0:0:644 ]] || return 1
  [[ $(sha256sum "$path" | awk '{print $1}') == "$expected_sha256" ]] || return 1
}

require_pinned_root_executable() {
  local path=$1 expected_sha256=$2 metadata
  [[ -f "$path" && ! -L "$path" ]] || return 1
  metadata=$(stat -c '%u:%g:%a' "$path") || return 1
  [[ "$metadata" == 0:0:755 ]] || return 1
  [[ $(sha256sum "$path" | awk '{print $1}') == "$expected_sha256" ]] || return 1
}

require_next_font_mock() {
  [[ -d "$NEXT_FONT_ASSET_ROOT" && ! -L "$NEXT_FONT_ASSET_ROOT" ]] || return 1
  [[ $(stat -c '%u:%g:%a' "$NEXT_FONT_ASSET_ROOT") == 0:0:755 ]] || return 1
  [[ -d "$NEXT_FONT_ASSET_ROOT/fonts" && ! -L "$NEXT_FONT_ASSET_ROOT/fonts" ]] || return 1
  [[ $(stat -c '%u:%g:%a' "$NEXT_FONT_ASSET_ROOT/fonts") == 0:0:755 ]] || return 1
  require_pinned_root_file "$NEXT_FONT_MOCK" "$NEXT_FONT_MOCK_SHA256"
  require_pinned_root_file "$GEIST_FONT" "$GEIST_FONT_SHA256"
  require_pinned_root_file "$GEIST_MONO_FONT" "$GEIST_MONO_FONT_SHA256"
  require_pinned_root_file "$FRAGMENT_MONO_FONT" "$FRAGMENT_MONO_FONT_SHA256"
}

start_frontend() {
  require_next_font_mock
  require_pinned_root_executable "$NEXT_NODE" "$NEXT_NODE_SHA256"
  (cd frontend && exec env NODE_OPTIONS=--max-old-space-size=1024 \
    NEXT_FONT_GOOGLE_MOCKED_RESPONSES="$NEXT_FONT_MOCK" \
    FRONTEND_PORT=$FRONTEND_PORT BACKEND_URL="http://127.0.0.1:$BACKEND_PORT" \
    "$NEXT_NODE" ./node_modules/next/dist/bin/next dev --webpack -p "$FRONTEND_PORT") >"$STATE_ROOT/frontend.log" 2>&1 &
  echo $! > "$STATE_ROOT/frontend.pid"
  for attempt in $(seq 1 60); do
    curl --fail --silent "http://127.0.0.1:$FRONTEND_PORT" >/dev/null && break
    [[ "$attempt" -lt 60 ]] || return 1
    sleep 2
  done
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
  start_backend
  stop_local_service backend
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
  start_backend
  start_frontend
  (cd frontend && CI=true E2E_BASE_URL="http://localhost:$FRONTEND_PORT" PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    bun ./node_modules/.bin/playwright test e2e/auth-flow.spec.ts e2e/a11y.spec.ts --reporter=list)
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
