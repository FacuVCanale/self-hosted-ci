#!/usr/bin/env bash
set -euo pipefail

readonly table_family="inet"
readonly table_name="self_hosted_ci"
readonly bridge="ci-jit-isolated"
readonly runner_subnet="10.254.0.0/28"

die() { printf 'runner network policy: %s\n' "$*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "must run as root"
command -v nft >/dev/null || die "nft is unavailable"

apply_policy() {
  [[ -d "/sys/class/net/${bridge}" ]] || die "${bridge} is absent"
  local existing=""
  if nft list table "${table_family}" "${table_name}" >/dev/null 2>&1; then
    existing="delete table ${table_family} ${table_name}"
  fi
  # nft consumes the complete batch transactionally. A parse/apply failure
  # leaves the previous table intact instead of exposing a partially updated
  # bridge policy.
  nft -f - <<EOF
${existing}
table ${table_family} ${table_name} {
  chain runner_input {
    type filter hook input priority -10; policy accept;
    iifname "${bridge}" udp sport 68 udp dport 67 counter accept
    iifname "${bridge}" ip saddr != ${runner_subnet} counter drop
    iifname "${bridge}" ip saddr ${runner_subnet} tcp dport { 3128, 8079, 8080 } ct state new,established counter accept
    iifname "${bridge}" counter drop
  }

  chain runner_forward {
    type filter hook forward priority -10; policy accept;
    iifname "${bridge}" counter drop
    oifname "${bridge}" counter drop
  }
}
EOF
}

verify_policy() {
  local rules
  rules="$(nft -nn list table "${table_family}" "${table_name}")" || die "managed table is absent"
  grep -Fq "iifname \"${bridge}\" ip saddr != ${runner_subnet}" <<<"${rules}" || die "source-subnet guard drift"
  grep -Fq 'udp sport 68 udp dport 67' <<<"${rules}" || die "DHCP exception drift"
  grep -Eq 'tcp dport \{ (3128, 8079, 8080|3128, 8080, 8079|8079, 3128, 8080|8079, 8080, 3128|8080, 3128, 8079|8080, 8079, 3128) \}' <<<"${rules}" || die "managed endpoint exception drift"
  [[ "$(grep -Fc "iifname \"${bridge}\"" <<<"${rules}")" -ge 4 ]] || die "runner input policy incomplete"
  grep -Fq "oifname \"${bridge}\" counter packets" <<<"${rules}" || die "runner forward deny drift"
}

quarantine_policy() {
  local existing=""
  if nft list table "${table_family}" "${table_name}" >/dev/null 2>&1; then
    existing="delete table ${table_family} ${table_name}"
  fi
  # Stopping the service replaces the active exceptions with an atomic bridge
  # quarantine. Shutdown, failed dependencies and operator stops therefore do
  # not create a transient fail-open path.
  nft -f - <<EOF
${existing}
table ${table_family} ${table_name} {
  chain runner_input {
    type filter hook input priority -10; policy accept;
    iifname "${bridge}" counter drop
  }
  chain runner_forward {
    type filter hook forward priority -10; policy accept;
    iifname "${bridge}" counter drop
    oifname "${bridge}" counter drop
  }
}
EOF
}

case "${1:-}" in
  apply) apply_policy; verify_policy ;;
  verify) verify_policy ;;
  quarantine) quarantine_policy ;;
  *) die "usage: $0 apply|verify|quarantine" ;;
esac
