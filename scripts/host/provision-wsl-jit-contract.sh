#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_DISTRO="Ubuntu-24.04-CI"
readonly TARGET_ROOT="/etc/self-hosted-ci"
readonly STATE_ROOT="/var/lib/self-hosted-ci"
readonly SERVICE_NAME="self-hosted-ci-garm.service"

die() { printf 'wsl-jit provisioning blocked: %s\n' "$*" >&2; exit 1; }

usage() {
  printf 'usage: %s [--plan] | --apply --evidence FILE --reviewer-public-key FILE --reviewer-key-fingerprint SHA256 --acknowledge-host-mutation --acknowledge-dedicated-boundary\n' "$0" >&2
  exit 2
}

mode="plan"
evidence=""
ack_mutation=false
ack_boundary=false
reviewer_public_key=""
reviewer_key_fingerprint=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) mode="plan"; shift ;;
    --apply) mode="apply"; shift ;;
    --evidence) [[ $# -ge 2 ]] || usage; evidence="$2"; shift 2 ;;
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
[[ -n "${evidence}" && -r "${evidence}" ]] || die "--apply requires a readable --evidence bundle"
[[ -n "${reviewer_public_key}" && -r "${reviewer_public_key}" ]] || die "--apply requires a readable reviewer public key"
[[ "${reviewer_key_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || die "--apply requires the exact reviewer key SHA-256 fingerprint"
[[ "${EUID}" -eq 0 ]] || die "--apply must run as root"
[[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || die "host must be Ubuntu 24.04"
grep -qi 'wsl2' /proc/sys/kernel/osrelease || die "host must be WSL2"
[[ "${WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}" ]] || die "WSL_DISTRO_NAME must be ${EXPECTED_DISTRO}"
python3 "${repo_root}/scripts/host/verify-wsl-jit-readiness.py" \
  --evidence "${evidence}" --measurement-root "$(dirname "${evidence}")" \
  --reviewer-public-key "${reviewer_public_key}" --pinned-fingerprint "${reviewer_key_fingerprint}" >/dev/null || \
  die "runner-boundary evidence is not fully verified"
command -v systemctl >/dev/null || die "systemd is required"
command -v incus >/dev/null || die "Incus is not installed"
command -v garm >/dev/null || die "GARM is not installed"
id garm-manager >/dev/null 2>&1 || die "dedicated garm-manager account is absent"
getent group incus-admin >/dev/null || die "dedicated Incus administrative group is absent"
id -nG garm-manager | tr ' ' '\n' | grep -qx incus-admin || die "garm-manager cannot access the dedicated Incus provider"
if id -nG garm-manager | tr ' ' '\n' | grep -Eq '^(sudo|admin|wheel)$'; then
  die "garm-manager belongs to an interactive privileged group"
fi
systemctl is-enabled --quiet "${SERVICE_NAME}" && die "${SERVICE_NAME} must be disabled before provisioning"

install -d -o root -g root -m 0750 "${TARGET_ROOT}" "${TARGET_ROOT}/garm" "${TARGET_ROOT}/incus"
install -d -o root -g root -m 0700 "${STATE_ROOT}"
install -d -o root -g root -m 0700 "${STATE_ROOT}/health"
install -d -o root -g root -m 0755 "/usr/local/lib/self-hosted-ci/github_automation"
install -o root -g root -m 0755 "${repo_root}/scripts/host/verify-wsl-jit-readiness.py" "/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/collect-wsl-jit-measurements.py" "/usr/local/lib/self-hosted-ci/collect-wsl-jit-measurements.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/collect-health-snapshot.py" "/usr/local/lib/self-hosted-ci/collect-health-snapshot.py"
install -o root -g root -m 0755 "${repo_root}/scripts/host/update-health-heartbeat.py" "/usr/local/lib/self-hosted-ci/update-health-heartbeat.py"
for module in __init__.py crypto.py host_security.py runner_boundary.py; do
  install -o root -g root -m 0644 "${repo_root}/github_automation/${module}" "/usr/local/lib/self-hosted-ci/github_automation/${module}"
done
install -o root -g root -m 0640 "${repo_root}/templates/garm/config.toml.example" "${TARGET_ROOT}/garm/config.toml.example"
install -o root -g root -m 0640 "${repo_root}/templates/incus/runner-profile.yaml" "${TARGET_ROOT}/incus/runner-profile.yaml"
install -o root -g root -m 0644 "${reviewer_public_key}" "${TARGET_ROOT}/boundary-reviewer-public-key.pem"
printf '%s\n' "${reviewer_key_fingerprint}" >"${TARGET_ROOT}/boundary-reviewer-key.sha256"
chmod 0644 "${TARGET_ROOT}/boundary-reviewer-key.sha256"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-boundary-verify.service" "/etc/systemd/system/self-hosted-ci-boundary-verify.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-garm.service" "/etc/systemd/system/${SERVICE_NAME}"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-network-policy.service" "/etc/systemd/system/self-hosted-ci-network-policy.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-egress-proxy.service" "/etc/systemd/system/self-hosted-ci-egress-proxy.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-health-heartbeat.service" "/etc/systemd/system/self-hosted-ci-health-heartbeat.service"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-health-heartbeat.timer" "/etc/systemd/system/self-hosted-ci-health-heartbeat.timer"
systemctl daemon-reload
systemctl enable --now self-hosted-ci-health-heartbeat.timer
systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
rm -f "${TARGET_ROOT}/ACTIVATION_APPROVED"
printf 'Contract templates installed. %s remains disabled; no runner was registered.\n' "${SERVICE_NAME}"
