#!/usr/bin/env bash
set -euo pipefail

readonly target_root="/etc/self-hosted-ci"
readonly library_root="/usr/local/lib/self-hosted-ci"

die() { printf 'network runtime install blocked: %s\n' "$*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ ! -e "${target_root}/ACTIVATION_APPROVED" ]] || die "activation sentinel must be absent"
for command in nft squid python3 systemctl; do
  command -v "${command}" >/dev/null || die "${command} is unavailable"
done
id proxy >/dev/null 2>&1 || die "dedicated proxy account is absent"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
install -d -o root -g proxy -m 0750 "${target_root}/network"
install -d -o root -g root -m 0755 "${library_root}"
install -o root -g proxy -m 0640 "${repo_root}/packaging/network/squid.conf" "${target_root}/network/squid.conf"
install -o root -g root -m 0755 "${repo_root}/scripts/host/apply-runner-network-policy.sh" "${library_root}/apply-runner-network-policy.sh"
install -o root -g root -m 0755 "${repo_root}/scripts/host/run-egress-proxies.sh" "${library_root}/run-egress-proxies.sh"
install -o root -g root -m 0755 "${repo_root}/scripts/host/garm-callback-proxy.py" "${library_root}/garm-callback-proxy.py"
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-network-policy.service" /etc/systemd/system/self-hosted-ci-network-policy.service
install -o root -g root -m 0644 "${repo_root}/packaging/systemd/self-hosted-ci-egress-proxy.service" /etc/systemd/system/self-hosted-ci-egress-proxy.service
systemctl daemon-reload
systemctl disable --now self-hosted-ci-egress-proxy.service self-hosted-ci-network-policy.service >/dev/null 2>&1 || true
[[ ! -e "${target_root}/ACTIVATION_APPROVED" ]] || die "installer must not create activation sentinel"
printf '{"status":"installed-inert","activation_approved":false,"external_calls":false}\n'
