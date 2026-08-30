#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_DISTRO="Ubuntu-24.04-CI"
readonly RUNNER_USER="ci-runner"
readonly INSTALL_DIR="/opt/self-hosted-ci"
readonly STATE_DIR="/var/lib/self-hosted-ci"
readonly EVIDENCE_FILE="${STATE_DIR}/bootstrap-evidence.json"

die() {
  printf 'bootstrap error: %s\n' "$*" >&2
  exit 1
}

render_wsl_conf() {
  cat <<'EOF'
[boot]
systemd=true

[automount]
enabled=false
mountFsTab=false

[interop]
enabled=false
appendWindowsPath=false
EOF
}

if [[ "${1:-}" == "--print-wsl-conf" ]]; then
  render_wsl_conf
  exit 0
fi

[[ $# -eq 0 ]] || die "usage: $0 [--print-wsl-conf]"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"

# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || die "host must be Ubuntu"
[[ "${VERSION_ID:-}" == "24.04" ]] || die "host must be Ubuntu 24.04"
[[ -r /proc/sys/kernel/osrelease ]] || die "kernel release is unavailable"
grep -qi 'wsl2' /proc/sys/kernel/osrelease || die "host must be WSL2"
[[ "${WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}" ]] || die "WSL_DISTRO_NAME must be ${EXPECTED_DISTRO}"
command -v useradd >/dev/null 2>&1 || die "useradd is unavailable"
command -v usermod >/dev/null 2>&1 || die "usermod is unavailable"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is unavailable"

if ! getent passwd "${RUNNER_USER}" >/dev/null; then
  useradd --create-home --shell /bin/bash --user-group "${RUNNER_USER}"
fi

runner_uid="$(id -u "${RUNNER_USER}")"
[[ "${runner_uid}" -ge 1000 ]] || die "${RUNNER_USER} must be an unprivileged account"
[[ "$(id -gn "${RUNNER_USER}")" == "${RUNNER_USER}" ]] || die "${RUNNER_USER} must have a dedicated primary group"
[[ "$(getent passwd "${RUNNER_USER}" | cut -d: -f6)" == "/home/${RUNNER_USER}" ]] || \
  die "${RUNNER_USER} must use /home/${RUNNER_USER}"
[[ "$(getent passwd "${RUNNER_USER}" | cut -d: -f7)" == "/bin/bash" ]] || \
  usermod --shell /bin/bash "${RUNNER_USER}"
passwd --lock "${RUNNER_USER}" >/dev/null
[[ "$(passwd --status "${RUNNER_USER}" | awk '{print $2}')" == "L" ]] || die "${RUNNER_USER} password is not locked"

for privileged_group in sudo admin wheel docker lxd; do
  if getent group "${privileged_group}" >/dev/null && id -nG "${RUNNER_USER}" | tr ' ' '\n' | grep -Fxq "${privileged_group}"; then
    gpasswd --delete "${RUNNER_USER}" "${privileged_group}" >/dev/null
  fi
done

if grep -R -Eqs "(^|[[:space:],:])${RUNNER_USER}([[:space:],:]|$)" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
  die "explicit sudoers authorization exists for ${RUNNER_USER}"
fi
if id -nG "${RUNNER_USER}" | tr ' ' '\n' | grep -Eq '^(sudo|admin|wheel)$'; then
  die "${RUNNER_USER} still belongs to a privileged group"
fi

install -d -o root -g "${RUNNER_USER}" -m 0750 "${INSTALL_DIR}"
if [[ ! -d "${STATE_DIR}" ]]; then
  install -d -o root -g "${RUNNER_USER}" -m 0750 "${STATE_DIR}"
fi
install -d -o "${RUNNER_USER}" -g "${RUNNER_USER}" -m 0700 "${STATE_DIR}/work"
install -d -o "${RUNNER_USER}" -g "${RUNNER_USER}" -m 0700 "${STATE_DIR}/tmp"
runner_home="$(getent passwd "${RUNNER_USER}" | cut -d: -f6)"
[[ -n "${runner_home}" && -d "${runner_home}" ]] || die "runner home is unavailable"
chown "${RUNNER_USER}:${RUNNER_USER}" "${runner_home}"
chmod 0700 "${runner_home}"

wsl_conf_tmp="$(mktemp)"
evidence_tmp="$(mktemp)"
cleanup() {
  rm -f "${wsl_conf_tmp}" "${evidence_tmp}"
}
trap cleanup EXIT
render_wsl_conf >"${wsl_conf_tmp}"
install -o root -g root -m 0644 "${wsl_conf_tmp}" /etc/wsl.conf

[[ "$(stat -c '%U:%G:%a' "${INSTALL_DIR}")" == "root:${RUNNER_USER}:750" ]] || die "invalid ${INSTALL_DIR} permissions"
[[ "$(stat -c '%U:%G:%a' "${STATE_DIR}")" == "root:${RUNNER_USER}:750" ]] || die "invalid ${STATE_DIR} permissions"
[[ "$(stat -c '%U:%G:%a' "${STATE_DIR}/work")" == "${RUNNER_USER}:${RUNNER_USER}:700" ]] || die "invalid work permissions"
cmp -s "${wsl_conf_tmp}" /etc/wsl.conf || die "wsl.conf verification failed"

wsl_conf_sha256="$(sha256sum /etc/wsl.conf | cut -d' ' -f1)"
generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
cat >"${evidence_tmp}" <<EOF
{
  "schema_version": 1,
  "status": "bootstrapped-restart-required",
  "generated_at": "${generated_at}",
  "platform": "wsl2",
  "distro_name": "${EXPECTED_DISTRO}",
  "os_id": "ubuntu",
  "os_version": "24.04",
  "runner_user": "${RUNNER_USER}",
  "runner_uid": ${runner_uid},
  "install_directory": "${INSTALL_DIR}",
  "state_directory": "${STATE_DIR}",
  "wsl_conf_sha256": "sha256:${wsl_conf_sha256}",
  "checks": {
    "dedicated_distro": true,
    "non_sudo_runner_user": true,
    "password_locked": true,
    "systemd_configured": true,
    "automount_disabled": true,
    "interop_disabled": true,
    "permissions_verified": true,
    "runner_registered": false,
    "secrets_managed": false
  }
}
EOF
install -o root -g "${RUNNER_USER}" -m 0640 "${evidence_tmp}" "${EVIDENCE_FILE}"

printf 'Bootstrap complete. Evidence: %s\n' "${EVIDENCE_FILE}"
printf 'Terminate and restart %s before any further host verification.\n' "${EXPECTED_DISTRO}"
