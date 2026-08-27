#!/usr/bin/env bash
set -euo pipefail

readonly bridge="ci-jit-isolated"
readonly gateway="10.254.0.1"
readonly squid_config="/etc/self-hosted-ci/network/squid.conf"
readonly callback_proxy="/usr/local/lib/self-hosted-ci/garm-callback-proxy.py"

die() { printf 'runner proxy: %s\n' "$*" >&2; exit 1; }

check() {
  command -v ip >/dev/null || die "ip is unavailable"
  command -v squid >/dev/null || die "squid is unavailable"
  command -v python3 >/dev/null || die "python3 is unavailable"
  [[ -r "${squid_config}" ]] || die "squid configuration is unreadable"
  [[ -x "${callback_proxy}" ]] || die "callback proxy is not executable"
  ip -4 -o address show dev "${bridge}" | grep -Fq " ${gateway}/28 " || die "bridge address drift"
  squid -k parse -f "${squid_config}" >/dev/null
}

run() {
  check
  local callback_pid squid_pid status=1
  python3 "${callback_proxy}" --listen-host "${gateway}" --listen-port 8080 --upstream-host 127.0.0.1 --upstream-port 9997 &
  callback_pid=$!
  squid -N -f "${squid_config}" &
  squid_pid=$!
  trap 'kill "${callback_pid}" "${squid_pid}" 2>/dev/null || true; wait "${callback_pid}" "${squid_pid}" 2>/dev/null || true' EXIT INT TERM
  wait -n "${callback_pid}" "${squid_pid}" || status=$?
  die "proxy component exited unexpectedly (status ${status})"
}

case "${1:-}" in
  check) check ;;
  run) run ;;
  *) die "usage: $0 check|run" ;;
esac
