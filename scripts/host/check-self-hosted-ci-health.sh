#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly probe_script="${script_dir}/get-self-hosted-ci-health.ps1"

usage() {
  printf 'usage: %s --ssh-target <host> --service-account-sid <SID> [--distro <name>]\n' "$0" >&2
  exit 2
}

ssh_target=""
service_sid=""
distro_name="Ubuntu-24.04-CI"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-target)
      [[ $# -ge 2 ]] || usage
      ssh_target="$2"
      shift 2
      ;;
    --service-account-sid)
      [[ $# -ge 2 ]] || usage
      service_sid="$2"
      shift 2
      ;;
    --distro)
      [[ $# -ge 2 ]] || usage
      distro_name="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ -n "${ssh_target}" ]] || usage
[[ "${service_sid}" =~ ^S-1-[0-9]+(-[0-9]+)+$ ]] || {
  printf 'health check error: invalid Windows SID\n' >&2
  exit 2
}
[[ "${distro_name}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || {
  printf 'health check error: invalid WSL distro name\n' >&2
  exit 2
}
[[ -r "${probe_script}" ]] || {
  printf 'health check error: missing probe %s\n' "${probe_script}" >&2
  exit 1
}
for command in base64 fold ssh; do
  command -v "${command}" >/dev/null 2>&1 || {
    printf 'health check error: %s is unavailable\n' "${command}" >&2
    exit 1
  }
done

probe_base64="$({
  printf '& {\n'
  cat "${probe_script}"
  printf '\n} -ExpectedDistroName '\''%s'\'' -ExpectedServiceAccountSid '\''%s'\''\n' \
    "${distro_name}" "${service_sid}"
} | base64 | tr -d '\r\n')"

{
  printf "\$b=''\n"
  chunk=""
  while IFS= read -r chunk || [[ -n "${chunk}" ]]; do
    printf "\$b+='%s'\n" "${chunk}"
  done < <(printf '%s' "${probe_base64}" | fold -w 2048)
  printf 'Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))\n'
} | ssh -- "${ssh_target}" powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -
