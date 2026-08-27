#!/usr/bin/env bash
readonly GARM_SERVICE=self-hosted-ci-garm.service BROKER_SERVICE=self-hosted-ci-allocation-broker.service OUTBOUND_WORKER_SERVICE=self-hosted-ci-outbound-worker.service BOUNDARY_SERVICE=self-hosted-ci-boundary-verify.service POLICY_SERVICE=self-hosted-ci-network-policy.service PROXY_SERVICE=self-hosted-ci-egress-proxy.service HEALTH_TIMER=self-hosted-ci-health-heartbeat.timer
readonly ACTIVATION_SENTINEL=/etc/self-hosted-ci/ACTIVATION_APPROVED NETWORK_SENTINEL=/etc/self-hosted-ci/runner-network-v2.enabled HEALTH_STATE=/etc/self-hosted-ci/garm/health-state.json BROKER_CONFIG=/etc/self-hosted-ci/garm/allocation-broker.json BROKER_PUBLIC_KEY=/etc/self-hosted-ci/garm/allocation-authority-public-key.pem
readonly GARM_CONFIG=/etc/self-hosted-ci/garm/config.toml PROVIDER_CONFIG=/etc/self-hosted-ci/garm/garm-provider-incus.toml GARM_SESSION_HELPER=/usr/local/lib/self-hosted-ci/garm-cli-session.py BROKER_CLI=/usr/local/lib/self-hosted-ci/garm-allocation-broker.py LIVE_JOB_VERIFIER=/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py LIVE_CONTRACT_VERIFIER=/usr/local/lib/self-hosted-ci/verify-live-artifact-contract.py GARM_RUNTIME_HOME=/run/self-hosted-ci/garm-cli NETWORK_POLICY_SCRIPT=/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh
die(){ printf 'garm-jit transaction blocked: %s\n' "$*" >&2; exit 1; }
acquire_transaction_lock(){ command -v flock >/dev/null||die "flock is required"; exec 9>/run/self-hosted-ci-garm-jit.lock; flock -n 9||die "another transaction is active"; }
require_root_regular_file(){ local p="$1" m="$2" a; [[ -f "$p" && ! -L "$p" && "$(stat -c '%u:%h' "$p")" == 0:1 ]]||die "$p metadata unsafe"; a="$(stat -c '%a' "$p")"; (( (8#$a & ~8#$m)==0 ))||die "$p permissions too broad"; }
require_exact_distro(){ [[ "$EUID" -eq 0 && "${WSL_DISTRO_NAME:-}" == Ubuntu-24.04-CI ]]||die "exact root WSL distro required"; grep -qi wsl2 /proc/sys/kernel/osrelease||die "WSL2 required"; }
require_command_contracts(){ command -v systemctl >/dev/null; command -v incus >/dev/null; for p in /usr/local/bin/garm /usr/local/bin/garm-cli "$GARM_SESSION_HELPER" "$BROKER_CLI" "$LIVE_JOB_VERIFIER"; do [[ -x "$p" && ! -L "$p" ]]||die "$p absent or unsafe"; done; for p in "$GARM_CONFIG" "$PROVIDER_CONFIG" "$HEALTH_STATE" "$BROKER_CONFIG" "$BROKER_PUBLIC_KEY" /etc/self-hosted-ci/garm/incus-client.crt /etc/self-hosted-ci/garm/incus-client.key /etc/self-hosted-ci/garm/incus-server.crt; do require_root_regular_file "$p" 0640; done; openssl x509 -in /etc/self-hosted-ci/garm/incus-client.crt -noout -checkend 2592000 >/dev/null||die "provider client certificate expires within 30 days"; grep -Fqx 'project_name = "ci-jit"' "$PROVIDER_CONFIG"||die "provider project drifted"; grep -Fqx 'url = "https://127.0.0.1:8443"' "$PROVIDER_CONFIG"||die "provider endpoint drifted"; grep -Fqx 'include_default_profile = false' "$PROVIDER_CONFIG"||die "provider may inherit default profile"; ! grep -Eq 'unix_socket|skip_verify *= *true|project_name = "default"' "$PROVIDER_CONFIG"||die "provider privilege bypass"; id garm-manager >/dev/null; id -nG garm-manager|tr ' ' '\n'|grep -Eq '^(incus|incus-admin|sudo|admin|wheel)$'&&die "garm-manager belongs to a forbidden privileged group"||true; }
require_live_artifact_contract(){ require_root_regular_file "$LIVE_CONTRACT_VERIFIER" 0755; "$LIVE_CONTRACT_VERIFIER" --evidence /etc/self-hosted-ci/runner-boundary-v2.json --measurement-root /etc/self-hosted-ci/host-evidence --reviewer-public-key /etc/self-hosted-ci/boundary-reviewer-public-key.pem --pinned-fingerprint-file /etc/self-hosted-ci/boundary-reviewer-key.sha256 >/dev/null||die "signed live artifact contract is invalid or drifted"; }
require_real_policy_units(){ local u c; for u in "$POLICY_SERVICE" "$PROXY_SERVICE" "$GARM_SERVICE" "$BROKER_SERVICE" "$OUTBOUND_WORKER_SERVICE"; do c="$(systemctl cat "$u")"||die "cannot inspect $u"; [[ "$c" == *ExecStart=* && "$c" != */usr/bin/false* ]]||die "$u is inert"; done; [[ "$(systemctl cat "$GARM_SERVICE")" != *SupplementaryGroups=incus-admin* ]]||die "host-wide Incus admin forbidden"; }
require_base_health(){ systemctl is-active --quiet incus.service; systemctl is-active --quiet "$BOUNDARY_SERVICE"; systemctl is-active --quiet "$HEALTH_TIMER"; }
require_health_configuration(){ python3 - "$HEALTH_STATE" "$BROKER_CONFIG" "$LIVE_JOB_VERIFIER" <<'PY' || die "broker health contract invalid"
import json,sys
h=json.load(open(sys.argv[1])); b=json.load(open(sys.argv[2]))
if set(h)!={"schema_version","garm_cli_home","manager_configured","provider_configured","image_configured","broker_configured","zero_scale_sets","image","targets"} or h["schema_version"]!=3: raise SystemExit()
if not all(h[k] is True for k in ("manager_configured","provider_configured","image_configured","broker_configured","zero_scale_sets")): raise SystemExit()
if b.get("live_job_verifier")!=sys.argv[3] or b.get("targets")!=h["targets"] or not h["targets"]: raise SystemExit()
if b.get("garm_cli_home")!=h["garm_cli_home"] or b.get("provider_name")!="incus_ci_jit" or h["image"]!={"alias":b.get("image_alias"),"fingerprint":b.get("image_fingerprint")}: raise SystemExit()
PY
}
garm_cli(){ "$GARM_SESSION_HELPER" run -- --format json "$@"&&return; local s=$?; [[ "${GARM_SESSION_FAILURE_QUARANTINE:-false}" == true ]]&&"$NETWORK_POLICY_SCRIPT" quarantine >/dev/null 2>&1||true; return "$s"; }
configured_scale_sets_empty(){ local rows flag id inv; rows="$(python3 - "$BROKER_CONFIG" <<'PY'
import json,sys
for t in json.load(open(sys.argv[1]))["targets"].values(): print(t["entity_flag"]+"\t"+t["entity_id"])
PY
)"||return; while IFS=$'\t' read -r flag id; do [[ -z "$flag" ]]&&continue; inv="$(garm_cli scaleset list "$flag" "$id")"||return; python3 - "$inv" <<'PY' || return
import json,sys
if json.loads(sys.argv[1])!=[]: raise SystemExit()
PY
done <<<"$rows"; }
incus_project_empty(){ local v; v="$(incus list --project ci-jit --format json)"||return; python3 - "$v" <<'PY'
import json,sys
if json.loads(sys.argv[1])!=[]: raise SystemExit()
PY
}
zero_runtime_state(){ configured_scale_sets_empty&&incus_project_empty; }
recover_allocations(){ GARM_SESSION_FAILURE_QUARANTINE=true "$BROKER_CLI" recover >/dev/null&&zero_runtime_state; }
durable_write(){ python3 - "$1" "$2" <<'PY'
import json,os,sys,tempfile
p=sys.argv[1]; v=json.loads(sys.argv[2]); fd,t=tempfile.mkstemp(prefix=".state.",dir=os.path.dirname(p)); os.fchmod(fd,0o600); os.fchown(fd,0,0)
with os.fdopen(fd,"w") as f: json.dump(v,f,sort_keys=True,separators=(",",":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
os.replace(t,p); d=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)
PY
}
create_activation_sentinel(){ [[ ! -e "$ACTIVATION_SENTINEL" ]]||return 1; durable_write "$ACTIVATION_SENTINEL" '{"schema_version":2,"allocation_mode":"transient-broker"}'; }
create_network_sentinel(){ [[ ! -e "$NETWORK_SENTINEL" ]]||return 1; durable_write "$NETWORK_SENTINEL" '{"schema_version":1,"policy":"runner-network-v2","state":"active"}'; }
remove_durable_file(){ python3 - "$1" <<'PY'
import os,sys
try: os.unlink(sys.argv[1])
except FileNotFoundError: pass
d=os.open(os.path.dirname(sys.argv[1]),os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)
PY
}
remove_activation_sentinel(){ remove_durable_file "$ACTIVATION_SENTINEL"; }; remove_network_sentinel(){ remove_durable_file "$NETWORK_SENTINEL"; }
stop_after_zero(){ zero_runtime_state||die "runtime not empty"; systemctl disable --now "$OUTBOUND_WORKER_SERVICE" "$BROKER_SERVICE"; systemctl disable --now "$GARM_SERVICE"; remove_activation_sentinel; systemctl stop "$PROXY_SERVICE" "$POLICY_SERVICE"; remove_network_sentinel; }
