#!/usr/bin/env bash
set -euo pipefail

readonly RUNNER_USER="ci-runner"
readonly INSTALL_DIR="/opt/self-hosted-ci/actions-runner"
readonly METADATA_FILE="${INSTALL_DIR}/.self-hosted-ci-install"
readonly RELEASE_BASE_URL="https://github.com/actions/runner/releases/download"
readonly EXPECTED_DISTRO="Ubuntu-24.04"

die() {
  printf 'actions-runner verification error: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s --version <X.Y.Z> --sha256 <64 lowercase or uppercase hex characters>\n' "$0" >&2
  exit 2
}

version=""
expected_sha256=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || usage
      version="$2"
      shift 2
      ;;
    --sha256)
      [[ $# -ge 2 ]] || usage
      expected_sha256="${2,,}"
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must have X.Y.Z form without a v prefix"
[[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be exactly 64 hexadecimal characters"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -r /etc/os-release ]] || die "/etc/os-release is unavailable"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || die "host must be Ubuntu 24.04"
[[ -r /proc/sys/kernel/osrelease ]] || die "kernel release is unavailable"
grep -qi 'wsl2' /proc/sys/kernel/osrelease || die "host must be WSL2"
[[ "${WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}" ]] || die "WSL_DISTRO_NAME must be ${EXPECTED_DISTRO}"
getent passwd "${RUNNER_USER}" >/dev/null || die "${RUNNER_USER} does not exist"
[[ -d "${INSTALL_DIR}" ]] || die "${INSTALL_DIR} is absent"
[[ -f "${METADATA_FILE}" ]] || die "installation metadata is absent"

expected_url="${RELEASE_BASE_URL}/v${version}/actions-runner-linux-x64-${version}.tar.gz"
installed_version="$(sed -n 's/^version=//p' "${METADATA_FILE}")"
installed_sha256="$(sed -n 's/^archive_sha256=//p' "${METADATA_FILE}")"
installed_url="$(sed -n 's/^source_url=//p' "${METADATA_FILE}")"
[[ "${installed_version}" == "${version}" ]] || die "installed version does not match ${version}"
[[ "${installed_sha256}" == "${expected_sha256}" ]] || die "installed archive SHA-256 does not match"
[[ "${installed_url}" == "${expected_url}" ]] || die "installed source URL is not the expected official release URL"

[[ "$(stat -c '%U:%G:%a' "${INSTALL_DIR}")" == "root:${RUNNER_USER}:750" ]] || \
  die "invalid installation directory ownership or mode"
[[ "$(stat -c '%U:%G:%a' "${METADATA_FILE}")" == "root:${RUNNER_USER}:640" ]] || \
  die "invalid metadata ownership or mode"
[[ -f "${INSTALL_DIR}/config.sh" && -f "${INSTALL_DIR}/run.sh" ]] || die "runner scripts are incomplete"
[[ -x "${INSTALL_DIR}/bin/Runner.Listener" ]] || die "Runner.Listener is absent or not executable"

if find "${INSTALL_DIR}" ! -user root -print -quit | grep -q .; then
  die "installation contains files not owned by root"
fi
if find "${INSTALL_DIR}" ! -group "${RUNNER_USER}" -print -quit | grep -q .; then
  die "installation contains files outside the ${RUNNER_USER} group"
fi
if find "${INSTALL_DIR}" \( -type f -o -type d \) -perm /0007 -print -quit | grep -q .; then
  die "installation grants permissions to other users"
fi
if find "${INSTALL_DIR}" \( -type f -o -type d \) -perm /0020 -print -quit | grep -q .; then
  die "installation is writable by ${RUNNER_USER}"
fi
while IFS= read -r -d '' link_path; do
  link_target="$(readlink "${link_path}")"
  [[ "${link_target}" != /* ]] || die "installation contains an absolute symlink: ${link_path}"
  resolved_target="$(readlink -f "${link_path}")"
  [[ "${resolved_target}" == "${INSTALL_DIR}"/* ]] || die "installation symlink escapes its root: ${link_path}"
done < <(find "${INSTALL_DIR}" -type l -print0)
if grep -R -Eqs "(^|[[:space:],:])${RUNNER_USER}([[:space:],:]|$)" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
  die "explicit sudoers authorization exists for ${RUNNER_USER}"
fi
if id -nG "${RUNNER_USER}" | tr ' ' '\n' | grep -Eq '^(sudo|admin|wheel)$'; then
  die "${RUNNER_USER} belongs to a privileged group"
fi

printf 'Verified GitHub Actions Runner %s (%s) at %s.\n' \
  "${version}" "${expected_sha256}" "${INSTALL_DIR}"
