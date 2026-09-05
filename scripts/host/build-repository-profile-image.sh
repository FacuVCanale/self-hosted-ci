#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT=ci-jit
readonly SQUID_CONFIG=/etc/self-hosted-ci/network/squid.conf
readonly FENCED_SERVICES=(self-hosted-ci-garm.service self-hosted-ci-allocation-broker.service self-hosted-ci-outbound-worker.service)
readonly TRANSACTION_LIB=/usr/local/lib/self-hosted-ci/garm-jit-transaction-lib.sh

die(){ printf 'repository-profile image build blocked: %s\n' "$*" >&2; exit 1; }
usage(){
  printf 'usage: %s [--plan] | --apply --profile-directory DIR --repository-profile FILE --expected-profile-digest SHA256 --base-fingerprint SHA256 --expected-manifest-sha256 SHA256 --candidate-alias ALIAS --overworld-bundle FILE --overworld-bundle-sha256 SHA256 --expected-overworld-commit SHA --waterfall-bundle FILE --waterfall-bundle-sha256 SHA256 --expected-waterfall-commit SHA --https-proxy http://10.254.0.1:3128 --acknowledge-temporary-build-egress --acknowledge-new-image-publication\n' "$0" >&2
  exit 2
}

mode=plan; profile_dir=''; repository_profile=''; profile_digest=''; base_fingerprint=''; manifest_sha=''; candidate_alias=''; https_proxy=''
overworld_bundle=''; overworld_bundle_sha=''; overworld_commit=''; waterfall_bundle=''; waterfall_bundle_sha=''; waterfall_commit=''
ack_egress=false; ack_publish=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) mode=plan; shift ;;
    --apply) mode=apply; shift ;;
    --profile-directory) [[ $# -ge 2 ]]||usage; profile_dir="$2"; shift 2 ;;
    --repository-profile) [[ $# -ge 2 ]]||usage; repository_profile="$2"; shift 2 ;;
    --expected-profile-digest) [[ $# -ge 2 ]]||usage; profile_digest="$2"; shift 2 ;;
    --base-fingerprint) [[ $# -ge 2 ]]||usage; base_fingerprint="$2"; shift 2 ;;
    --expected-manifest-sha256) [[ $# -ge 2 ]]||usage; manifest_sha="$2"; shift 2 ;;
    --candidate-alias) [[ $# -ge 2 ]]||usage; candidate_alias="$2"; shift 2 ;;
    --overworld-bundle) [[ $# -ge 2 ]]||usage; overworld_bundle="$2"; shift 2 ;;
    --overworld-bundle-sha256) [[ $# -ge 2 ]]||usage; overworld_bundle_sha="$2"; shift 2 ;;
    --expected-overworld-commit) [[ $# -ge 2 ]]||usage; overworld_commit="$2"; shift 2 ;;
    --waterfall-bundle) [[ $# -ge 2 ]]||usage; waterfall_bundle="$2"; shift 2 ;;
    --waterfall-bundle-sha256) [[ $# -ge 2 ]]||usage; waterfall_bundle_sha="$2"; shift 2 ;;
    --expected-waterfall-commit) [[ $# -ge 2 ]]||usage; waterfall_commit="$2"; shift 2 ;;
    --https-proxy) [[ $# -ge 2 ]]||usage; https_proxy="$2"; shift 2 ;;
    --acknowledge-temporary-build-egress) ack_egress=true; shift ;;
    --acknowledge-new-image-publication) ack_publish=true; shift ;;
    *) usage ;;
  esac
done

if [[ "${mode}" == plan ]]; then
  printf '%s\n' '{"mode":"plan","project":"ci-jit","network":"ci-jit-isolated","builder_privileged":false,"builder_nesting":false,"credentials":"forbidden","alias_reuse":false,"garm_and_worker_fenced":true,"runtime_must_be_empty":true,"build_egress":"temporary exact-domain allowlist","postcondition":"restore signed GitHub-only Squid config and prior service state","host_changes":false,"external_calls":"not_performed"}'
  exit 0
fi

[[ "${EUID}" -eq 0 ]]||die '--apply must run as root'
[[ "${WSL_DISTRO_NAME:-}" == Ubuntu-24.04-CI ]]||die 'exact WSL distro is required'
grep -qi wsl2 /proc/sys/kernel/osrelease||die 'WSL2 is required'
[[ "${ack_egress}" == true && "${ack_publish}" == true ]]||die '--apply requires both acknowledgements'
for digest in "${base_fingerprint}" "${manifest_sha}" "${profile_digest}" "${overworld_bundle_sha}" "${waterfall_bundle_sha}"; do
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]||die 'fingerprints and bundle digests must be lowercase SHA-256'
done
[[ "${overworld_commit}" =~ ^[0-9a-f]{40}$ && "${waterfall_commit}" =~ ^[0-9a-f]{40}$ ]]||die 'bundle commits must be exact lowercase Git SHAs'
[[ "${candidate_alias}" =~ ^overworld-pr-v1-[0-9a-f]{12,64}$ ]]||die 'candidate alias must be content-addressed and profile-scoped'
[[ "${https_proxy}" == http://10.254.0.1:3128 ]]||die 'build proxy must be exact runner-network-v2 endpoint'
[[ -d "${profile_dir}" && ! -L "${profile_dir}" ]]||die 'profile directory is absent or unsafe'
[[ -f "${repository_profile}" && ! -L "${repository_profile}" ]]||die 'repository profile is absent or unsafe'
[[ "$(sha256sum "${repository_profile}"|cut -d' ' -f1)" == "${profile_digest}" ]]||die 'repository profile digest drifted'
for bundle in "${overworld_bundle}" "${waterfall_bundle}"; do [[ -f "${bundle}" && ! -L "${bundle}" ]]||die 'source bundle is absent or unsafe'; done
[[ "$(sha256sum "${overworld_bundle}"|cut -d' ' -f1)" == "${overworld_bundle_sha}" ]]||die 'Overworld bundle digest drifted'
[[ "$(sha256sum "${waterfall_bundle}"|cut -d' ' -f1)" == "${waterfall_bundle_sha}" ]]||die 'Waterfall bundle digest drifted'
git bundle list-heads "${overworld_bundle}"|awk '{print $1}'|grep -Fxq "${overworld_commit}"||die 'Overworld commit is not an advertised bundle head'
git bundle list-heads "${waterfall_bundle}"|awk '{print $1}'|grep -Fxq "${waterfall_commit}"||die 'Waterfall commit is not an advertised bundle head'
for file in manifest.json provision.py verify.py squid-build.conf; do
  [[ -f "${profile_dir}/${file}" && ! -L "${profile_dir}/${file}" ]]||die "profile ${file} is absent or unsafe"
done
[[ "$(sha256sum "${profile_dir}/manifest.json"|cut -d' ' -f1)" == "${manifest_sha}" ]]||die 'manifest digest drifted'
[[ -f "${TRANSACTION_LIB}" && ! -L "${TRANSACTION_LIB}" ]]||die 'GARM transaction library is absent'
[[ -f "${SQUID_CONFIG}" && ! -L "${SQUID_CONFIG}" ]]||die 'signed Squid policy is absent'
command -v incus >/dev/null; command -v squid >/dev/null; command -v python3 >/dev/null; command -v git >/dev/null

# Reuse the production transaction lock and its exact zero-scale-set checks.
source "${TRANSACTION_LIB}"
acquire_transaction_lock
zero_runtime_state||die 'GARM scale sets and ci-jit instances must both be empty'

workdir="$(mktemp -d /run/self-hosted-ci/profile-image.XXXXXX)"
chmod 0700 "${workdir}"
cp --preserve=all -- "${SQUID_CONFIG}" "${workdir}/squid.conf.before"
builder="overworld-image-builder-${RANDOM}${RANDOM}"
published_fingerprint=''; alias_published=false; transaction_succeeded=false; squid_replaced=false
declare -A was_active
for service in "${FENCED_SERVICES[@]}"; do
  if systemctl is-active --quiet "${service}"; then was_active["${service}"]=true; else was_active["${service}"]=false; fi
done

cleanup(){
  local status=$?
  trap - ERR EXIT
  set +e
  incus delete "${builder}" --project "${PROJECT}" --force >/dev/null 2>&1
  if [[ "${transaction_succeeded}" != true && "${alias_published}" == true ]]; then
    if [[ -z "${published_fingerprint}" ]]; then
      published_fingerprint="$(python3 - "${candidate_alias}" "$(incus image alias list --project "${PROJECT}" --format json 2>/dev/null)" <<'PY' 2>/dev/null
import json,sys
rows=[r for r in json.loads(sys.argv[2]) if r.get("name")==sys.argv[1]]
print(rows[0].get("target","") if len(rows)==1 else "")
PY
)"
    fi
    incus image alias delete "${candidate_alias}" --project "${PROJECT}" >/dev/null 2>&1
    if [[ -n "${published_fingerprint}" && "${published_fingerprint}" != "${base_fingerprint}" ]]; then
      aliases="$(incus image alias list --project "${PROJECT}" --format json 2>/dev/null)"
      if python3 - "${published_fingerprint}" "${aliases}" <<'PY' >/dev/null 2>&1
import json,sys
if any(r.get("target")==sys.argv[1] for r in json.loads(sys.argv[2])): raise SystemExit(1)
PY
      then incus image delete "${published_fingerprint}" --project "${PROJECT}" >/dev/null 2>&1; fi
    fi
  fi
  if [[ "${squid_replaced}" == true ]]; then
    cp --preserve=all -- "${workdir}/squid.conf.before" "${SQUID_CONFIG}"
    squid -k parse -f "${SQUID_CONFIG}" >/dev/null 2>&1
    systemctl restart "${PROXY_SERVICE}" >/dev/null 2>&1
    cmp -s -- "${workdir}/squid.conf.before" "${SQUID_CONFIG}"||status=1
  fi
  for service in "${FENCED_SERVICES[@]}"; do
    if [[ "${was_active[${service}]}" == true ]]; then systemctl start "${service}" >/dev/null 2>&1||status=1; fi
  done
  rm -rf --one-file-system "${workdir}"
  exit "${status}"
}
trap cleanup EXIT

systemctl stop self-hosted-ci-outbound-worker.service self-hosted-ci-allocation-broker.service self-hosted-ci-garm.service
incus_project_empty||die 'ci-jit instance inventory changed while fencing build services'
systemctl is-active --quiet "${PROXY_SERVICE}"||die 'egress proxy must already be active'
squid -k parse -f "${profile_dir}/squid-build.conf" >/dev/null 2>&1||die 'build-only Squid policy is invalid'
squid_replaced=true
cp --preserve=mode,ownership,timestamps -- "${profile_dir}/squid-build.conf" "${SQUID_CONFIG}"
systemctl restart "${PROXY_SERVICE}"

python3 - "${candidate_alias}" "$(incus image alias list --project "${PROJECT}" --format json)" <<'PY' || die 'candidate alias already exists'
import json,sys
if any(row.get("name")==sys.argv[1] for row in json.loads(sys.argv[2])): raise SystemExit(1)
PY
python3 - "${base_fingerprint}" "$(incus image list "${base_fingerprint}" --project "${PROJECT}" --format json)" <<'PY' || die 'base fingerprint is absent or ambiguous'
import json,sys
rows=[r for r in json.loads(sys.argv[2]) if r.get("fingerprint")==sys.argv[1]]
if len(rows)!=1 or rows[0].get("type")!="container" or rows[0].get("architecture")!="x86_64": raise SystemExit(1)
PY

incus init "${base_fingerprint}" "${builder}" --project "${PROJECT}" --profile ci-jit
incus config set "${builder}" --project "${PROJECT}" security.privileged=false security.nesting=false security.idmap.isolated=true
incus config show "${builder}" --project "${PROJECT}" --expanded --format json >"${workdir}/builder.json"
python3 - "${workdir}/builder.json" <<'PY' || die 'builder confinement contract failed'
import json,sys
v=json.load(open(sys.argv[1])); c=v.get("config",{}); d=v.get("devices",{})
if c.get("security.privileged")!="false" or c.get("security.nesting")!="false" or c.get("security.idmap.isolated")!="true": raise SystemExit(1)
if set(d)!={"eth0","root"} or d["eth0"].get("network")!="ci-jit-isolated" or d["root"].get("type")!="disk": raise SystemExit(1)
if any(x.get("type") in {"proxy","unix-char","unix-block"} for x in d.values()): raise SystemExit(1)
PY
incus start "${builder}" --project "${PROJECT}"
for file in manifest.json provision.py verify.py; do
  incus file push "${profile_dir}/${file}" "${builder}/run/self-hosted-ci-profile-build/${file}" --project "${PROJECT}" --create-dirs --mode=0700
done
incus file push "${repository_profile}" "${builder}/run/self-hosted-ci-profile-build/profile.json" --project "${PROJECT}" --create-dirs --mode=0600
incus file push "${overworld_bundle}" "${builder}/run/self-hosted-ci-profile-build/overworld.bundle" --project "${PROJECT}" --create-dirs --mode=0600
incus file push "${waterfall_bundle}" "${builder}/run/self-hosted-ci-profile-build/waterfall.bundle" --project "${PROJECT}" --create-dirs --mode=0600
python3 - "${overworld_commit}" "${overworld_bundle_sha}" "${waterfall_commit}" "${waterfall_bundle_sha}" >"${workdir}/bundle-inputs.json" <<'PY'
import json,sys
print(json.dumps(dict(zip(("overworld_commit","overworld_bundle_sha256","waterfall_commit","waterfall_bundle_sha256"),sys.argv[1:])),sort_keys=True,separators=(",",":")))
PY
incus file push "${workdir}/bundle-inputs.json" "${builder}/run/self-hosted-ci-profile-build/bundle-inputs.json" --project "${PROJECT}" --create-dirs --mode=0600
incus exec "${builder}" --project "${PROJECT}" --env "HTTPS_PROXY=${https_proxy}" --env "HTTP_PROXY=${https_proxy}" --env "NO_PROXY=127.0.0.1,localhost" -- /usr/bin/python3 /run/self-hosted-ci-profile-build/provision.py
incus exec "${builder}" --project "${PROJECT}" -- /usr/bin/python3 /run/self-hosted-ci-profile-build/verify.py
incus exec "${builder}" --project "${PROJECT}" -- /bin/sh -ceu 'rm -rf /run/self-hosted-ci-profile-build /root/.cache /root/.bun /tmp/* /var/tmp/*; test ! -e /root/.npmrc; test ! -e /root/.netrc; test ! -e /root/.config/gh/hosts.yml'
incus stop "${builder}" --project "${PROJECT}" --timeout 60
incus publish "${builder}" --project "${PROJECT}" --alias "${candidate_alias}" >/dev/null
alias_published=true
published_fingerprint="$(python3 - "${candidate_alias}" "$(incus image alias list --project "${PROJECT}" --format json)" <<'PY'
import json,sys
rows=[r for r in json.loads(sys.argv[2]) if r.get("name")==sys.argv[1]]
if len(rows)!=1 or not isinstance(rows[0].get("target"),str) or len(rows[0]["target"])!=64: raise SystemExit(1)
print(rows[0]["target"])
PY
)"||die 'published image alias postcondition failed'
[[ "${published_fingerprint}" != "${base_fingerprint}" ]]||die 'provisioned image unexpectedly equals its base fingerprint'
incus image list "${published_fingerprint}" --project "${PROJECT}" --format json >"${workdir}/published.json"
python3 - "${published_fingerprint}" "${workdir}/published.json" <<'PY' || die 'published fingerprint postcondition failed'
import json,sys
rows=[r for r in json.load(open(sys.argv[2])) if r.get("fingerprint")==sys.argv[1]]
if len(rows)!=1 or rows[0].get("type")!="container" or rows[0].get("architecture")!="x86_64": raise SystemExit(1)
PY
incus delete "${builder}" --project "${PROJECT}"
transaction_succeeded=true
printf '{"status":"built","project":"%s","profile":"overworld-pr-v1","base_fingerprint":"%s","manifest_sha256":"%s","candidate_alias":"%s","fingerprint":"%s","builder_privileged":false,"builder_nesting":false,"credentials_persisted":false,"alias_moved":false}\n' \
  "${PROJECT}" "${base_fingerprint}" "${manifest_sha}" "${candidate_alias}" "${published_fingerprint}"
