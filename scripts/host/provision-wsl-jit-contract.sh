#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_DISTRO="Ubuntu-24.04-CI"
readonly TARGET_ROOT="/etc/self-hosted-ci"
readonly STATE_ROOT="/var/lib/self-hosted-ci"
readonly SERVICE_NAME="self-hosted-ci-garm.service"

die() { printf 'wsl-jit provisioning blocked: %s\n' "$*" >&2; exit 1; }

make_service_inert() {
  local service="$1" load_state enabled_state
  if ! load_state="$(systemctl show --property=LoadState --value "${service}" 2>/dev/null)"; then
    die "could not observe load state for ${service}"
  fi
  [[ -n "${load_state}" ]] || die "empty load state for ${service}"
  [[ "${load_state}" == "not-found" ]] && return 0
  systemctl stop "${service}" || die "could not stop ${service}"
  enabled_state="$(systemctl is-enabled "${service}" 2>/dev/null)" || true
  [[ -n "${enabled_state}" ]] || die "could not observe enablement state for ${service}"
  if [[ "${enabled_state}" == "enabled" || "${enabled_state}" == "enabled-runtime" || "${enabled_state}" == "indirect" ]]; then
    systemctl disable "${service}" || die "could not disable ${service}"
  elif [[ "${enabled_state}" != "disabled" && "${enabled_state}" != "static" && "${enabled_state}" != "masked" ]]; then
    die "${service} has unexpected enablement state: ${enabled_state}"
  fi
  ! systemctl is-active --quiet "${service}" || die "${service} remains active"
  enabled_state="$(systemctl is-enabled "${service}" 2>/dev/null)" || true
  [[ "${enabled_state}" != "enabled" && "${enabled_state}" != "enabled-runtime" && "${enabled_state}" != "indirect" ]] || \
    die "${service} remains enabled"
}

usage() {
  printf 'usage: %s [--plan] | --apply (--evidence FILE | --bootstrap-evidence FILE --windows-observation FILE --wsl-observation FILE --public-manifest FILE --expected-bootstrap-nonce HEX32) --reviewer-public-key FILE --reviewer-key-fingerprint SHA256 --acknowledge-host-mutation --acknowledge-dedicated-boundary\n' "$0" >&2
  exit 2
}

mode="plan"
evidence=""
bootstrap_evidence=""
windows_observation=""
wsl_observation=""
public_manifest=""
expected_bootstrap_nonce=""
ack_mutation=false
ack_boundary=false
reviewer_public_key=""
reviewer_key_fingerprint=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) mode="plan"; shift ;;
    --apply) mode="apply"; shift ;;
    --evidence) [[ $# -ge 2 ]] || usage; evidence="$2"; shift 2 ;;
    --bootstrap-evidence) [[ $# -ge 2 ]] || usage; bootstrap_evidence="$2"; shift 2 ;;
    --windows-observation) [[ $# -ge 2 ]] || usage; windows_observation="$2"; shift 2 ;;
    --wsl-observation) [[ $# -ge 2 ]] || usage; wsl_observation="$2"; shift 2 ;;
    --public-manifest) [[ $# -ge 2 ]] || usage; public_manifest="$2"; shift 2 ;;
    --expected-bootstrap-nonce) [[ $# -ge 2 ]] || usage; expected_bootstrap_nonce="$2"; shift 2 ;;
    --reviewer-public-key) [[ $# -ge 2 ]] || usage; reviewer_public_key="$2"; shift 2 ;;
    --reviewer-key-fingerprint) [[ $# -ge 2 ]] || usage; reviewer_key_fingerprint="$2"; shift 2 ;;
    --acknowledge-host-mutation) ack_mutation=true; shift ;;
    --acknowledge-dedicated-boundary) ack_boundary=true; shift ;;
    *) usage ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ "${mode}" == "plan" ]]; then
  cat <<EOF
INERT PLAN ONLY — no host changes were made.
1. Verify a dedicated non-admin Windows account owns the dedicated WSL distro.
2. Verify Incus, GARM, the pinned runner image, and default-deny proxy-only egress.
3. Validate a complete runner-boundary-v2 evidence bundle.
4. Install contract templates; keep ${SERVICE_NAME} disabled until a separate activation action.
Production GitHub registration and external activation are outside this script.
EOF
  exit 0
fi

[[ "${ack_mutation}" == true && "${ack_boundary}" == true ]] || die "--apply requires both explicit acknowledgements"
if [[ -n "${bootstrap_evidence}" ]]; then
  [[ -z "${evidence}" && -r "${bootstrap_evidence}" && -r "${windows_observation}" && -r "${wsl_observation}" && -r "${public_manifest}" && "${expected_bootstrap_nonce}" =~ ^[0-9a-f]{32}$ ]] || die "bootstrap apply requires exact readable bootstrap, observation, public manifest files, and a 128-bit lowercase-hex challenge, without runner evidence"
  contract_mode="bootstrap-inert"
else
  [[ -n "${evidence}" && -r "${evidence}" && -z "${windows_observation}" && -z "${wsl_observation}" && -z "${public_manifest}" && -z "${expected_bootstrap_nonce}" ]] || die "final apply requires only a readable --evidence bundle"
  contract_mode="runner-final"
fi
[[ -n "${reviewer_public_key}" && -r "${reviewer_public_key}" ]] || die "--apply requires a readable reviewer public key"
[[ "${reviewer_key_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || die "--apply requires the exact reviewer key SHA-256 fingerprint"
[[ "${EUID}" -eq 0 ]] || die "--apply must run as root"
[[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || die "host must be Ubuntu 24.04"
grep -qi 'wsl2' /proc/sys/kernel/osrelease || die "host must be WSL2"
[[ "${WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}" ]] || die "WSL_DISTRO_NAME must be ${EXPECTED_DISTRO}"
if [[ "${contract_mode}" == "bootstrap-inert" ]]; then
  python3 "${repo_root}/scripts/host/verify-wsl-jit-bootstrap.py" \
    --evidence "${bootstrap_evidence}" --windows-observation "${windows_observation}" \
    --wsl-observation "${wsl_observation}" --public-manifest "${public_manifest}" \
    --reviewer-public-key "${reviewer_public_key}" \
    --pinned-fingerprint "${reviewer_key_fingerprint}" \
    --expected-nonce "${expected_bootstrap_nonce}" >/dev/null || \
    die "bootstrap boundary does not authorize inert provisioning"
else
  python3 "${repo_root}/scripts/host/verify-wsl-jit-readiness.py" \
    --evidence "${evidence}" --measurement-root "$(dirname "${evidence}")" \
    --reviewer-public-key "${reviewer_public_key}" --pinned-fingerprint "${reviewer_key_fingerprint}" >/dev/null || \
    die "runner-boundary evidence is not fully verified"
fi
command -v systemctl >/dev/null || die "systemd is required"
command -v incus >/dev/null || die "Incus is not installed"
command -v garm >/dev/null || die "GARM is not installed"
id garm-manager >/dev/null 2>&1 || die "dedicated garm-manager account is absent"
if id -nG garm-manager | tr ' ' '\n' | grep -Eq '^(incus|incus-admin|sudo|admin|wheel)$'; then
  die "garm-manager belongs to a forbidden privileged group"
fi
service_enablement="$(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null)" || true
[[ "${service_enablement}" != "enabled" && "${service_enablement}" != "enabled-runtime" && "${service_enablement}" != "indirect" ]] || \
  die "${SERVICE_NAME} must be disabled before provisioning"
if [[ "${contract_mode}" == "bootstrap-inert" ]]; then
  [[ ! -e "${TARGET_ROOT}/ACTIVATION_APPROVED" ]] || die "bootstrap requires activation approval to be absent"
  [[ ! -e "${TARGET_ROOT}/outbound-worker.runtime-ready" ]] || die "bootstrap requires runtime-ready state to be absent"
fi
if [[ "${contract_mode}" == "bootstrap-inert" ]]; then
  for inert_service in garm.service self-hosted-ci-boundary-verify.service self-hosted-ci-network-policy.service self-hosted-ci-egress-proxy.service self-hosted-ci-allocation-broker.service self-hosted-ci-outbound-worker.service self-hosted-ci-canary.target self-hosted-ci-canary-broker.service self-hosted-ci-canary-cleanup.service self-hosted-ci-canary-egress-proxy.service self-hosted-ci-canary-garm.service self-hosted-ci-canary-network-policy.service "${SERVICE_NAME}"; do
    make_service_inert "${inert_service}"
  done
fi

install -d -o root -g root -m 0750 "${TARGET_ROOT}" "${TARGET_ROOT}/garm" "${TARGET_ROOT}/incus"
install -d -o root -g root -m 0700 "${STATE_ROOT}"
install -d -o root -g root -m 0700 "${STATE_ROOT}/health"
install -d -o root -g root -m 0700 "${STATE_ROOT}/garm" "${STATE_ROOT}/outbound-worker"
if [[ "${contract_mode}" == "bootstrap-inert" ]]; then
  install -d -o root -g root -m 0700 "${TARGET_ROOT}/bootstrap" "${STATE_ROOT}/bootstrap"
  rm -f "${STATE_ROOT}/bootstrap/bootstrap-install-receipt-v1.json"
fi
install -d -o root -g root -m 0755 "/usr/local/lib/self-hosted-ci/github_automation"
install -d -o root -g root -m 0755 "/usr/local/libexec/self-hosted-ci"
install -d -o root -g root -m 0755 "/usr/local/share/self-hosted-ci/schemas"
install -o root -g root -m 0755 "${repo_root}/scripts/host/verify-wsl-jit-readiness.py" "/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/verify-live-artifact-contract.py" "/usr/local/lib/self-hosted-ci/verify-live-artifact-contract.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/collect-wsl-jit-measurements.py" "/usr/local/lib/self-hosted-ci/collect-wsl-jit-measurements.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/collect-health-snapshot.py" "/usr/local/lib/self-hosted-ci/collect-health-snapshot.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/garm-cli-session.py" "/usr/local/lib/self-hosted-ci/garm-cli-session.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/update-health-heartbeat.py" "/usr/local/lib/self-hosted-ci/update-health-heartbeat.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/install-wsl-jit-evidence.py" "/usr/local/lib/self-hosted-ci/install-wsl-jit-evidence.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/garm-allocation-broker.py" "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/github-live-job-verifier.py" "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/runner-job-started-hook.py" "/usr/local/lib/self-hosted-ci/runner-job-started-hook.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/outbound-coordinator-worker.py" "/usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/install-outbound-worker-runtime.py" "/usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/jit-pilot-terminal-monitor.py" "/usr/local/lib/self-hosted-ci/jit-pilot-terminal-monitor.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/verify-bootstrap-install.py" "/usr/local/lib/self-hosted-ci/verify-bootstrap-install.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/sign-jit-canary-authorization.py" "/usr/local/lib/self-hosted-ci/sign-jit-canary-authorization.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/verify-jit-canary-authorization.py" "/usr/local/lib/self-hosted-ci/verify-jit-canary-authorization.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/build-wsl-jit-lifecycle-evidence.py" "/usr/local/lib/self-hosted-ci/build-wsl-jit-lifecycle-evidence.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/run-wsl-jit-canary-matrix.py" "/usr/local/lib/self-hosted-ci/run-wsl-jit-canary-matrix.py"
install -d -o root -g root -m 0755 /usr/local/lib/self-hosted-ci/github_automation
for python_module in __init__.py bootstrap_boundary.py canary_boundary.py canary_worker.py crypto.py host_security.py runner_boundary.py runner_jit.py runner_jit_broker.py github.py github_adapter.py check_delivery.py inventory.py policy.py registry.py coordinator.py outbound_worker.py worker_authority.py gatestore.py jit_pilot.py local_approval.py; do
  install -o root -g root -m 0644 "${repo_root}/github_automation/${python_module}" "/usr/local/lib/self-hosted-ci/github_automation/${python_module}"
done
for schema_file in jit-canary-authorization-v1.schema.json runner-lifecycle-proof-v1.schema.json; do
  install -o root -g root -m 0644 "${repo_root}/schemas/${schema_file}" "/usr/local/share/self-hosted-ci/schemas/${schema_file}"
done
for collector_script in collect-wsl-jit-semantic-observations.py collect-wsl-jit-semantic-observations.sh verify-wsl-jit-bootstrap.py; do
  install -o root -g root -m 0755 "${repo_root}/scripts/host/${collector_script}" "/usr/local/lib/self-hosted-ci/${collector_script}"
done
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-allocation-broker.service" "/etc/systemd/system/self-hosted-ci-allocation-broker.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-outbound-worker.service" "/etc/systemd/system/self-hosted-ci-outbound-worker.service"
for transaction_script in prepare-incus-runner-image.sh configure-garm-jit.sh activate-garm-jit.sh deactivate-garm-jit.sh garm-jit-transaction-lib.sh; do
  install -o root -g root -m 0755 "${repo_root}/scripts/host/${transaction_script}" "/usr/local/lib/self-hosted-ci/${transaction_script}"
done
if [[ "${contract_mode}" == "runner-final" ]]; then
  "/usr/local/lib/self-hosted-ci/install-wsl-jit-evidence.py" \
    --evidence "${evidence}" --measurement-root "$(dirname "${evidence}")" \
    --target-root "${TARGET_ROOT}" >/dev/null
fi
install -o root -g root -m 0640 "${repo_root}/templates/garm/config.toml.example" "${TARGET_ROOT}/garm/config.toml.example"
install -o root -g root -m 0640 "${repo_root}/templates/incus/runner-profile.yaml" "${TARGET_ROOT}/incus/runner-profile.yaml"
install -d -o root -g root -m 0755 "/usr/local/share/self-hosted-ci"
install -o root -g root -m 0644 "${repo_root}/templates/garm/garm-provider-incus.toml" "/usr/local/share/self-hosted-ci/garm-provider-incus.toml"
install -o root -g root -m 0644 "${repo_root}/templates/garm/outbound-worker.json.example" "/usr/local/share/self-hosted-ci/outbound-worker.json.example"
install -o root -g root -m 0644 "${repo_root}/templates/garm/worker-app-authority.json.example" "/usr/local/share/self-hosted-ci/worker-app-authority.json.example"
for app_contract in runner-manager-app dispatcher-app live-job-verifier-app; do
  install -o root -g root -m 0644 "${repo_root}/templates/garm/${app_contract}.json.example" "/usr/local/share/self-hosted-ci/${app_contract}.json.example"
done
install -o root -g root -m 0755 "${repo_root}/scripts/host/install-incus-garm-tls.sh" "/usr/local/lib/self-hosted-ci/install-incus-garm-tls.sh"
"/usr/local/lib/self-hosted-ci/install-incus-garm-tls.sh" --apply \
  --provider-template "/usr/local/share/self-hosted-ci/garm-provider-incus.toml" \
  --acknowledge-loopback-tls-boundary >/dev/null
install -o root -g root -m 0755 "${repo_root}/scripts/host/install-runner-network-runtime.sh" "/usr/local/lib/self-hosted-ci/install-runner-network-runtime.sh"
bash "${repo_root}/scripts/host/install-runner-network-runtime.sh" >/dev/null
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-network-quarantine.service" "/etc/systemd/system/self-hosted-ci-network-quarantine.service"
systemctl daemon-reload
systemctl enable --now self-hosted-ci-network-quarantine.service
systemctl is-enabled --quiet self-hosted-ci-network-quarantine.service || die "network quarantine is not reboot-persistent"
systemctl is-active --quiet self-hosted-ci-network-quarantine.service || die "network quarantine did not become active"
if [[ "${contract_mode}" == "runner-final" ]]; then
  install -o root -g root -m 0644 "${reviewer_public_key}" "${TARGET_ROOT}/boundary-reviewer-public-key.pem"
  printf '%s\n' "${reviewer_key_fingerprint}" >"${TARGET_ROOT}/boundary-reviewer-key.sha256"
  chmod 0644 "${TARGET_ROOT}/boundary-reviewer-key.sha256"
  python3 "/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py" \
    --evidence "${TARGET_ROOT}/runner-boundary-v2.json" \
    --measurement-root "${TARGET_ROOT}/host-evidence" \
    --reviewer-public-key "${TARGET_ROOT}/boundary-reviewer-public-key.pem" \
    --pinned-fingerprint "${reviewer_key_fingerprint}" >/dev/null || \
    die "installed runner-boundary evidence failed post-install verification"
fi
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-boundary-verify.service" "/etc/systemd/system/self-hosted-ci-boundary-verify.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-garm.service" "/etc/systemd/system/${SERVICE_NAME}"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-network-policy.service" "/etc/systemd/system/self-hosted-ci-network-policy.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-egress-proxy.service" "/etc/systemd/system/self-hosted-ci-egress-proxy.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-health-heartbeat.service" "/etc/systemd/system/self-hosted-ci-health-heartbeat.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-health-heartbeat.timer" "/etc/systemd/system/self-hosted-ci-health-heartbeat.timer"
for canary_unit in self-hosted-ci-canary.target self-hosted-ci-canary-broker.service self-hosted-ci-canary-cleanup.service self-hosted-ci-canary-egress-proxy.service self-hosted-ci-canary-garm.service self-hosted-ci-canary-network-policy.service; do
  install -o root -g root -m 0644 "${repo_root}/packaging/systemd/${canary_unit}" "/etc/systemd/system/${canary_unit}"
done
systemctl daemon-reload
rm -f "${TARGET_ROOT}/ACTIVATION_APPROVED"
if [[ "${contract_mode}" == "runner-final" ]]; then
  /usr/local/lib/self-hosted-ci/verify-live-artifact-contract.py \
    --evidence "${TARGET_ROOT}/runner-boundary-v2.json" \
    --measurement-root "${TARGET_ROOT}/host-evidence" \
    --reviewer-public-key "${TARGET_ROOT}/boundary-reviewer-public-key.pem" \
    --pinned-fingerprint "${reviewer_key_fingerprint}" >/dev/null || \
    die "installed live runtime artifacts failed signed-contract verification"
  systemctl start self-hosted-ci-boundary-verify.service
  systemctl is-active --quiet self-hosted-ci-boundary-verify.service || die "boundary verification unit did not become active"
  systemctl enable --now self-hosted-ci-health-heartbeat.timer
else
  for inert_service in garm.service self-hosted-ci-boundary-verify.service self-hosted-ci-network-policy.service self-hosted-ci-egress-proxy.service self-hosted-ci-allocation-broker.service self-hosted-ci-outbound-worker.service self-hosted-ci-canary.target self-hosted-ci-canary-broker.service self-hosted-ci-canary-cleanup.service self-hosted-ci-canary-egress-proxy.service self-hosted-ci-canary-garm.service self-hosted-ci-canary-network-policy.service; do
    make_service_inert "${inert_service}"
  done
  install -o root -g root -m 0600 "${bootstrap_evidence}" "${TARGET_ROOT}/bootstrap/bootstrap-boundary-v1.signed.json"
  install -o root -g root -m 0600 "${public_manifest}" "${TARGET_ROOT}/bootstrap/bootstrap-public-manifest-v1.json"
  install -o root -g root -m 0600 "${reviewer_public_key}" "${TARGET_ROOT}/bootstrap/reviewer-public-key.pem"
  printf '%s\n' "${reviewer_key_fingerprint}" >"${TARGET_ROOT}/bootstrap/reviewer-key.sha256"
  chmod 0600 "${TARGET_ROOT}/bootstrap/reviewer-key.sha256"
  install -o root -g root -m 0755 "${repo_root}/scripts/host/provision-wsl-jit-contract.sh" "${TARGET_ROOT}/bootstrap/provision-wsl-jit-contract.sh"
  /usr/local/lib/self-hosted-ci/verify-bootstrap-install.py --write-receipt || \
    die "installed inert bootstrap failed exact target remeasurement"
fi
make_service_inert "${SERVICE_NAME}"
printf 'Contract templates installed in %s mode. %s remains disabled; no runner was registered.\n' "${contract_mode}" "${SERVICE_NAME}"
