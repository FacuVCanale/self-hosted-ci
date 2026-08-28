#!/usr/bin/env bash
set -euo pipefail

readonly table_family="inet"
readonly table_name="self_hosted_ci"
readonly bridge="ci-jit-isolated"
readonly runner_subnet="10.254.0.0/28"
readonly proxy_uid="$(id -u proxy)"
readonly resolver="10.255.255.254"

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
  set forbidden_v4 {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }
  }
  set forbidden_v6 {
    type ipv6_addr
    flags interval
    elements = { ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 }
  }

  chain runner_input {
    type filter hook input priority -10; policy accept;
    iifname "${bridge}" udp sport 68 udp dport 67 counter accept
    iifname "${bridge}" ip saddr != ${runner_subnet} counter drop
    iifname "${bridge}" ip saddr ${runner_subnet} ip daddr 10.254.0.1 udp dport 53 counter accept
    iifname "${bridge}" ip saddr ${runner_subnet} ip daddr 10.254.0.1 tcp dport 53 counter accept
    iifname "${bridge}" ip saddr ${runner_subnet} tcp dport { 3128, 8079, 8080 } ct state new,established counter accept
    iifname "${bridge}" counter drop
  }

  chain runner_forward {
    type filter hook forward priority -10; policy accept;
    iifname "${bridge}" counter drop
    oifname "${bridge}" counter drop
  }

  chain proxy_output {
    type filter hook output priority -10; policy accept;
    meta skuid ${proxy_uid} oifname "lo" counter accept
    meta skuid ${proxy_uid} ip daddr ${resolver} counter accept
    meta skuid ${proxy_uid} ip daddr @forbidden_v4 counter drop
    meta skuid ${proxy_uid} ip6 daddr @forbidden_v6 counter drop
  }
}
EOF
}

verify_policy() {
  local rules
  rules="$(nft -nn list table "${table_family}" "${table_name}")" || die "managed table is absent"
  grep -Fq "iifname \"${bridge}\" ip saddr != ${runner_subnet}" <<<"${rules}" || die "source-subnet guard drift"
  grep -Fq 'udp sport 68 udp dport 67' <<<"${rules}" || die "DHCP exception drift"
  grep -Fq 'ip daddr 10.254.0.1 udp dport 53' <<<"${rules}" || die "UDP DNS exception drift"
  grep -Fq 'ip daddr 10.254.0.1 tcp dport 53' <<<"${rules}" || die "TCP DNS exception drift"
  grep -Eq 'tcp dport \{ (3128, 8079, 8080|3128, 8080, 8079|8079, 3128, 8080|8079, 8080, 3128|8080, 3128, 8079|8080, 8079, 3128) \}' <<<"${rules}" || die "managed endpoint exception drift"
  [[ "$(grep -Fc "iifname \"${bridge}\"" <<<"${rules}")" -ge 6 ]] || die "runner input policy incomplete"
  grep -Fq "oifname \"${bridge}\" counter packets" <<<"${rules}" || die "runner forward deny drift"
  grep -Fq "meta skuid ${proxy_uid} ip daddr ${resolver} counter packets" <<<"${rules}" || die "proxy resolver exception drift"
  grep -Fq "meta skuid ${proxy_uid} ip daddr @forbidden_v4" <<<"${rules}" || die "proxy IPv4 rebinding guard drift"
  grep -Fq "meta skuid ${proxy_uid} ip6 daddr @forbidden_v6" <<<"${rules}" || die "proxy IPv6 rebinding guard drift"
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
  set forbidden_v4 {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }
  }
  set forbidden_v6 {
    type ipv6_addr
    flags interval
    elements = { ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 }
  }
  chain runner_input {
    type filter hook input priority -10; policy accept;
    iifname "${bridge}" counter drop
  }
  chain runner_forward {
    type filter hook forward priority -10; policy accept;
    iifname "${bridge}" counter drop
    oifname "${bridge}" counter drop
  }
  chain proxy_output {
    type filter hook output priority -10; policy accept;
    meta skuid ${proxy_uid} oifname "lo" counter accept
    meta skuid ${proxy_uid} ip daddr ${resolver} counter accept
    meta skuid ${proxy_uid} ip daddr @forbidden_v4 counter drop
    meta skuid ${proxy_uid} ip6 daddr @forbidden_v6 counter drop
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
