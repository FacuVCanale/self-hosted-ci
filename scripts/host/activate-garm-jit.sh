#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/garm-jit-transaction-lib.sh"
usage(){ printf 'usage: %s [--plan] | --apply --incus-project ci-jit --garm-cli-home /run/self-hosted-ci/garm-cli --acknowledge-external-github-mutation --acknowledge-local-ci-activation\n' "$0" >&2; exit 2; }
mode=plan; incus_project=""; garm_cli_home=""; ack_external=false; ack_activation=false
while [[ $# -gt 0 ]]; do case "$1" in --plan) mode=plan;shift;; --apply) mode=apply;shift;; --incus-project) incus_project="$2";shift 2;; --garm-cli-home) garm_cli_home="$2";shift 2;; --acknowledge-external-github-mutation) ack_external=true;shift;; --acknowledge-local-ci-activation) ack_activation=true;shift;; *) usage;; esac; done
if [[ "$mode" == plan ]]; then printf '%s\n' '{"mode":"plan","external_calls":"not_performed","host_changes":false,"sequence":["verify broker and outbound worker configuration and zero runtime","start policy and proxy","start GARM","prove zero scale sets and instances","start allocation broker","start outbound worker"]}'; exit 0; fi
[[ "$ack_external" == true && "$ack_activation" == true ]]||die "--apply requires both explicit acknowledgements"
[[ "$incus_project" == ci-jit && "$garm_cli_home" == "$GARM_RUNTIME_HOME" ]]||die "exact Incus project and garm-cli home are required"
require_exact_distro; acquire_transaction_lock; require_command_contracts; require_live_artifact_contract; require_real_policy_units
systemctl start "$BOUNDARY_SERVICE"; systemctl is-active --quiet "$BOUNDARY_SERVICE"||die "boundary verification failed"
require_base_health; require_health_configuration
[[ ! -e "$ACTIVATION_SENTINEL" && ! -e "$NETWORK_SENTINEL" ]]||die "prior activation state exists; run deactivation to reconcile it"
systemctl is-active --quiet "$GARM_SERVICE" && die "GARM must be inactive"; systemctl is-active --quiet "$BROKER_SERVICE" && die "broker must be inactive"; systemctl is-active --quiet "$OUTBOUND_WORKER_SERVICE" && die "outbound worker must be inactive"
incus_project_empty||die "Incus project is not empty"
sentinel_created=false; manager_started=false
rollback(){ local status="$1"; trap - ERR INT TERM EXIT; set +e; systemctl stop "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE" >/dev/null 2>&1; if [[ "$manager_started" == true ]]; then recover_allocations||{ printf 'rollback blocked: allocation recovery failed; GARM and policy remain active\n' >&2; exit "$status"; }; stop_after_zero; elif [[ "$sentinel_created" == true ]]; then incus_project_empty||exit "$status"; remove_activation_sentinel; systemctl stop "$PROXY_SERVICE" "$POLICY_SERVICE"; remove_network_sentinel; fi; exit "$status"; }
trap 'rollback $?' ERR INT TERM EXIT
create_activation_sentinel; sentinel_created=true
systemctl enable --now "$POLICY_SERVICE" "$PROXY_SERVICE"; create_network_sentinel
manager_started=true; systemctl enable --now "$GARM_SERVICE"; systemctl is-active --quiet "$GARM_SERVICE"||die "GARM failed"
zero_runtime_state||die "activation requires zero scale sets and instances"
systemctl enable --now "$BROKER_SERVICE"; systemctl is-active --quiet "$BROKER_SERVICE"||die "broker failed"
zero_runtime_state||die "broker startup left transient runtime"
systemctl enable --now "$OUTBOUND_WORKER_SERVICE"; systemctl is-active --quiet "$OUTBOUND_WORKER_SERVICE"||die "outbound worker failed or runtime authority is not ready"
trap - ERR INT TERM EXIT
printf '%s\n' '{"status":"activated","broker_active":true,"outbound_worker_active":true,"zero_scale_sets":true,"zero_idle_instances":true,"policy_active":true}'
