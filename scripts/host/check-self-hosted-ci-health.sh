#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly validator="${script_dir}/validate-health-snapshot.py"
readonly remote_snapshot="/C:/ProgramData/self-hosted-ci/health/current.json"

usage() { printf 'usage: %s --ssh-target <host> --service-account-sid <SID> [--distro <name>]\n' "$0" >&2; exit 2; }
ssh_target=""; service_sid=""; distro_name="Ubuntu-24.04-CI"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-target) [[ $# -ge 2 ]] || usage; ssh_target="$2"; shift 2 ;;
    --service-account-sid) [[ $# -ge 2 ]] || usage; service_sid="$2"; shift 2 ;;
    --distro) [[ $# -ge 2 ]] || usage; distro_name="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ "${ssh_target}" =~ ^[A-Za-z0-9._@:-]+$ && "${ssh_target}" != -* ]] || usage
[[ "${service_sid}" =~ ^S-1-[0-9]+(-[0-9]+)+$ ]] || usage
[[ "${distro_name}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || usage
[[ -r "${validator}" ]] || { printf 'health check error: validator unavailable\n' >&2; exit 1; }
for command in mktemp python3 sftp; do command -v "${command}" >/dev/null 2>&1 || { printf 'health check error: %s unavailable\n' "${command}" >&2; exit 1; }; done
temporary="$(mktemp -d)"
trap 'find "${temporary}" -depth -delete 2>/dev/null || true' EXIT
snapshot="${temporary}/current.json"; batch="${temporary}/sftp.batch"
printf 'get %s %s\n' "${remote_snapshot}" "${snapshot}" >"${batch}"
chmod 0600 "${batch}"
if ! sftp -q -oBatchMode=yes -oConnectTimeout=15 -b "${batch}" -- "${ssh_target}" >/dev/null; then
  printf 'health check error: snapshot transport failed\n' >&2; exit 1
fi
[[ -f "${snapshot}" && ! -L "${snapshot}" ]] || { printf 'health check error: snapshot missing\n' >&2; exit 5; }
python3 "${validator}" --snapshot "${snapshot}" --expected-sid "${service_sid}" --expected-distro "${distro_name}"
