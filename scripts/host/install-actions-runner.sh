#!/usr/bin/env bash
set -euo pipefail

readonly RUNNER_USER="ci-runner"
readonly INSTALL_DIR="/opt/self-hosted-ci/actions-runner"
readonly RELEASE_BASE_URL="https://github.com/actions/runner/releases/download"
readonly EXPECTED_DISTRO="Ubuntu-24.04-CI"

die() {
  printf 'actions-runner install error: %s\n' "$*" >&2
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
getent passwd "${RUNNER_USER}" >/dev/null || die "${RUNNER_USER} does not exist; run host bootstrap first"
[[ "$(id -u "${RUNNER_USER}")" -ge 1000 ]] || die "${RUNNER_USER} must be unprivileged"
if grep -R -Eqs "(^|[[:space:],:])${RUNNER_USER}([[:space:],:]|$)" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
  die "explicit sudoers authorization exists for ${RUNNER_USER}"
fi
if id -nG "${RUNNER_USER}" | tr ' ' '\n' | grep -Eq '^(sudo|admin|wheel)$'; then
  die "${RUNNER_USER} belongs to a privileged group"
fi

for command in curl sha256sum tar install find stat; do
  command -v "${command}" >/dev/null 2>&1 || die "${command} is unavailable"
done

readonly archive_name="actions-runner-linux-x64-${version}.tar.gz"
readonly download_url="${RELEASE_BASE_URL}/v${version}/${archive_name}"
readonly metadata_name=".self-hosted-ci-install"

if [[ -f "${INSTALL_DIR}/${metadata_name}" ]]; then
  installed_version="$(sed -n 's/^version=//p' "${INSTALL_DIR}/${metadata_name}")"
  installed_sha256="$(sed -n 's/^archive_sha256=//p' "${INSTALL_DIR}/${metadata_name}")"
  if [[ "${installed_version}" == "${version}" && "${installed_sha256}" == "${expected_sha256}" ]]; then
    "$(dirname "$0")/verify-actions-runner.sh" --version "${version}" --sha256 "${expected_sha256}"
    printf 'GitHub Actions Runner %s is already installed and verified.\n' "${version}"
    exit 0
  fi
fi

parent_dir="$(dirname "${INSTALL_DIR}")"
install -d -o root -g "${RUNNER_USER}" -m 0750 "${parent_dir}"
work_dir="$(mktemp -d "${parent_dir}/.actions-runner-install.XXXXXX")"
archive_path="${work_dir}/${archive_name}"
extract_dir="${work_dir}/payload"
replacement_dir="${parent_dir}/.actions-runner-new.$$"
backup_dir="${parent_dir}/.actions-runner-old.$$"

cleanup() {
  rm -rf -- "${work_dir}" "${replacement_dir}"
}
trap cleanup EXIT

curl --fail --show-error --silent --location \
  --proto '=https' --tlsv1.2 \
  --output "${archive_path}" "${download_url}"
printf '%s  %s\n' "${expected_sha256}" "${archive_path}" | sha256sum --check --status || \
  die "SHA-256 verification failed for ${archive_name}"

mkdir "${extract_dir}"
tar --extract --gzip --file "${archive_path}" --directory "${extract_dir}" \
  --no-same-owner --no-same-permissions
[[ -f "${extract_dir}/config.sh" ]] || die "verified archive does not contain config.sh"
[[ -f "${extract_dir}/run.sh" ]] || die "verified archive does not contain run.sh"
[[ -x "${extract_dir}/bin/Runner.Listener" ]] || die "verified archive does not contain executable Runner.Listener"

mv -- "${extract_dir}" "${replacement_dir}"
printf 'version=%s\narchive_sha256=%s\nsource_url=%s\n' \
  "${version}" "${expected_sha256}" "${download_url}" >"${replacement_dir}/${metadata_name}"
chown -R root:"${RUNNER_USER}" "${replacement_dir}"
chmod -R u=rwX,g=rX,o= "${replacement_dir}"
chmod 0640 "${replacement_dir}/${metadata_name}"

if [[ -e "${INSTALL_DIR}" ]]; then
  mv -- "${INSTALL_DIR}" "${backup_dir}"
fi
if ! mv -- "${replacement_dir}" "${INSTALL_DIR}"; then
  [[ ! -e "${backup_dir}" ]] || mv -- "${backup_dir}" "${INSTALL_DIR}"
  die "failed to activate replacement"
fi
if ! "$(dirname "$0")/verify-actions-runner.sh" --version "${version}" --sha256 "${expected_sha256}"; then
  rm -rf -- "${INSTALL_DIR}"
  [[ ! -e "${backup_dir}" ]] || mv -- "${backup_dir}" "${INSTALL_DIR}"
  die "replacement failed post-install verification; previous installation was restored"
fi
rm -rf -- "${backup_dir}"
printf 'Installed GitHub Actions Runner %s at %s. Registration was not performed.\n' \
  "${version}" "${INSTALL_DIR}"
