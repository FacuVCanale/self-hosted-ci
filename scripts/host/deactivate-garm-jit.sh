#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/garm-jit-transaction-lib.sh"
usage(){ printf 'usage: %s [--plan] | --apply --incus-project ci-jit --garm-cli-home /run/self-hosted-ci/garm-cli --acknowledge-external-github-mutation --acknowledge-local-ci-deactivation\n' "$0" >&2; exit 2; }
mode=plan; incus_project=""; garm_cli_home=""; ack_external=false; ack_deactivation=false
while [[ $# -gt 0 ]]; do case "$1" in --plan) mode=plan;shift;; --apply) mode=apply;shift;; --incus-project) incus_project="$2";shift 2;; --garm-cli-home) garm_cli_home="$2";shift 2;; --acknowledge-external-github-mutation) ack_external=true;shift;; --acknowledge-local-ci-deactivation) ack_deactivation=true;shift;; *) usage;; esac; done
if [[ "$mode" == plan ]]; then printf '%s\n' '{"mode":"plan","external_calls":"not_performed","host_changes":false,"sequence":["restore policy and GARM","stop broker admission","recover disable-drain-delete allocations","prove all target scale-set inventories and Incus empty","stop GARM and policy"]}'; exit 0; fi
[[ "$ack_external" == true && "$ack_deactivation" == true ]]||die "--apply requires both explicit acknowledgements"
[[ "$incus_project" == ci-jit && "$garm_cli_home" == "$GARM_RUNTIME_HOME" ]]||die "exact Incus project and garm-cli home are required"
require_exact_distro; acquire_transaction_lock; require_command_contracts; require_real_policy_units; require_base_health; require_health_configuration
require_root_regular_file "$ACTIVATION_SENTINEL" 0600
systemctl start "$POLICY_SERVICE" "$PROXY_SERVICE"; [[ -e "$NETWORK_SENTINEL" ]]||create_network_sentinel
systemctl start "$GARM_SERVICE"; systemctl is-active --quiet "$GARM_SERVICE"||die "GARM recovery unavailable"; wait_for_garm_cli||die "GARM recovery API did not become ready"
systemctl stop "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"; systemctl is-active --quiet "$OUTBOUND_WORKER_SERVICE"&&die "outbound worker remains active"; systemctl is-active --quiet "$BROKER_SERVICE"&&die "broker admission remains active"
GARM_SESSION_FAILURE_QUARANTINE=true; export GARM_SESSION_FAILURE_QUARANTINE
recover_allocations||die "allocation recovery failed; GARM and policy remain active"
zero_runtime_state||die "zero scale-set/Incus proof failed; GARM and policy remain active"
stop_after_zero
printf '%s\n' '{"status":"deactivated","broker_active":false,"outbound_worker_active":false,"zero_scale_sets":true,"zero_incus_instances":true,"policy_stopped_after_zero":true}'
