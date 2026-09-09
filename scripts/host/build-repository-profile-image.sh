#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT=ci-jit
readonly FENCED_SERVICES=(self-hosted-ci-garm.service self-hosted-ci-allocation-broker.service self-hosted-ci-outbound-worker.service)
readonly BUILD_PROXY_UNIT=self-hosted-ci-profile-build-proxy.service
readonly TRANSACTION_LIB=/usr/local/lib/self-hosted-ci/garm-jit-transaction-lib.sh
readonly PROFILE_ASSETS=(
  next-font-google-mocked-responses.cjs
  fonts/FragmentMono-OFL.txt
  fonts/FragmentMono-Regular.ttf
  fonts/Geist-OFL.txt
  fonts/GeistMono-OFL.txt
  'fonts/GeistMono[wght].ttf'
  'fonts/Geist[wght].ttf'
  fonts/README.md
)
readonly PUBLISH_SENTINELS=(
  /etc/self-hosted-ci/repository-profile-image-v1.json
  /usr/local/bin/node
  /opt/self-hosted-ci/node_modules/pyright/package.json
  /opt/self-hosted-ci/overworld-deps/frontend-node_modules/react/package.json
  /opt/self-hosted-ci/overworld-deps/frontend-node_modules/next/package.json
  /opt/self-hosted-ci/overworld-deps/frontend-node_modules/next/dist/server/dev/browser-logs/receive-logs.js
  /opt/self-hosted-ci/overworld-deps/frontend-node_modules/next/dist/server/dev/browser-logs/file-logger.js
  /opt/self-hosted-ci/overworld-profile-assets/next-font-google-mocked-responses.cjs
  /opt/self-hosted-ci/overworld-profile-assets/fonts/FragmentMono-OFL.txt
  /opt/self-hosted-ci/overworld-profile-assets/fonts/FragmentMono-Regular.ttf
  /opt/self-hosted-ci/overworld-profile-assets/fonts/Geist-OFL.txt
  /opt/self-hosted-ci/overworld-profile-assets/fonts/GeistMono-OFL.txt
  '/opt/self-hosted-ci/overworld-profile-assets/fonts/GeistMono[wght].ttf'
  '/opt/self-hosted-ci/overworld-profile-assets/fonts/Geist[wght].ttf'
  /opt/self-hosted-ci/overworld-profile-assets/fonts/README.md
)

die(){ printf 'repository-profile image build blocked: %s\n' "$*" >&2; exit 1; }
cloud_init_status_decision(){
  local phase=$1 status_json=$2
  python3 - "${phase}" "${status_json}" <<'PY'
import json
import re
import sys

phase, status_path = sys.argv[1:]
if phase not in {"preflight", "wait"}:
    print("cloud-init readiness parser received an invalid phase", file=sys.stderr)
    raise SystemExit(1)

try:
    with open(status_path, encoding="utf-8") as stream:
        value = json.load(stream)
except (OSError, UnicodeError, json.JSONDecodeError):
    print(f"cloud-init {phase} returned invalid JSON", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(value, dict):
    print(f"cloud-init {phase} JSON root is not an object", file=sys.stderr)
    raise SystemExit(1)

status = value.get("status")
extended_status = value.get("extended_status")
boot_status_code = value.get("boot_status_code")
errors = value.get("errors")
recoverable_errors = value.get("recoverable_errors")

safe_state = re.compile(r"^[a-z][a-z -]{0,31}$")
safe_boot_codes = {"enabled-by-generator", "disabled-by-generator"}
if not isinstance(status, str) or not safe_state.fullmatch(status):
    status = "<invalid>"
if not isinstance(extended_status, str) or not safe_state.fullmatch(extended_status):
    extended_status = "<invalid>"
if not isinstance(boot_status_code, str) or boot_status_code not in safe_boot_codes:
    boot_status_code = "<invalid>"
if not isinstance(errors, list) or not isinstance(recoverable_errors, dict):
    print(
        f"cloud-init {phase} status schema is invalid: "
        f"status={status} extended_status={extended_status} boot_status_code={boot_status_code}",
        file=sys.stderr,
    )
    raise SystemExit(1)
if errors or recoverable_errors:
    print(
        f"cloud-init {phase} reported errors: "
        f"status={status} extended_status={extended_status} boot_status_code={boot_status_code} "
        f"errors_count={len(errors)} recoverable_error_groups={len(recoverable_errors)}",
        file=sys.stderr,
    )
    raise SystemExit(1)

enabled = boot_status_code == "enabled-by-generator"
if status == "done" and extended_status == "done" and enabled:
    print("terminal")
elif status == "disabled" and extended_status == "disabled" and boot_status_code == "disabled-by-generator":
    # cloud-init handle_status_args historically returns rc=0 for this clean
    # terminal state; accepting it preserves that contract without invoking
    # the blocking query_systemctl(wait=True) path.
    print("terminal")
elif phase == "preflight" and status == extended_status and status in {"running", "not started"} and enabled:
    print("wait")
else:
    print(
        f"cloud-init {phase} status is not accepted: "
        f"status={status} extended_status={extended_status} boot_status_code={boot_status_code}",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
}
wait_for_cloud_init_readiness(){
  local instance=$1 decision rc
  local preflight_json="${workdir}/cloud-init-preflight.json"
  local preflight_stderr="${workdir}/cloud-init-preflight.stderr"
  local waited_json="${workdir}/cloud-init-wait.json"
  local waited_stderr="${workdir}/cloud-init-wait.stderr"

  if incus exec "${instance}" --project "${PROJECT}" -- \
    /usr/bin/timeout -k 10s 15s /usr/bin/cloud-init status --format=json \
    >"${preflight_json}" 2>"${preflight_stderr}"; then
    rc=0
  else
    rc=$?
  fi
  if [[ "${rc}" -ne 0 ]]; then
    printf 'cloud-init preflight command failed: rc=%s\n' "${rc}" >&2
    return 1
  fi
  decision="$(cloud_init_status_decision preflight "${preflight_json}")" || return 1
  [[ "${decision}" == terminal ]] && return 0
  [[ "${decision}" == wait ]] || { printf 'cloud-init preflight parser returned an invalid decision\n' >&2; return 1; }

  if incus exec "${instance}" --project "${PROJECT}" -- \
    /usr/bin/timeout -k 10s 180s /usr/bin/cloud-init status --wait --format=json \
    >"${waited_json}" 2>"${waited_stderr}"; then
    rc=0
  else
    rc=$?
  fi
  if [[ "${rc}" -ne 0 ]]; then
    printf 'cloud-init wait command failed: rc=%s\n' "${rc}" >&2
    return 1
  fi
  decision="$(cloud_init_status_decision wait "${waited_json}")" || return 1
  [[ "${decision}" == terminal ]] || { printf 'cloud-init wait parser returned an invalid decision\n' >&2; return 1; }
}
inspect_running_sentinels(){
  local instance=$1 phase=$2
  shift 2
  incus exec "${instance}" --project "${PROJECT}" -- /bin/sh -ceu '
    phase=$1
    shift
    failed=0
    ancestors=""
    for path do
      case "$path" in *=*) continue ;; esac
      case "$path" in
        /opt/*)
          directory=${path%/*}
          while :; do
            case " $ancestors " in *" $directory "*) ;; *) ancestors="$ancestors $directory" ;; esac
            [ "$directory" = /opt ] && break
            directory=${directory%/*}
          done
          ;;
      esac
      if [ ! -f "$path" ] || [ -L "$path" ]; then
        printf "%s sentinel missing or unsafe: %s\n" "$phase" "$path" >&2
        failed=1
        continue
      fi
      metadata=$(stat -c "uid=%u gid=%g mode=%a links=%h size=%s device=%d" -- "$path")
      printf "%s sentinel metadata: path=%s %s\n" "$phase" "$path" "$metadata"
      case "$metadata" in uid=0\ gid=0\ *) ;; *) printf "%s sentinel ownership is not root:root: %s\n" "$phase" "$path" >&2; failed=1 ;; esac
      mount=""
      if ! mount=$(findmnt -rn -T "$path" -o TARGET,SOURCE,FSTYPE); then
        printf "%s sentinel mount lookup failed: %s\n" "$phase" "$path" >&2
        failed=1
      elif [ -n "$mount" ]; then
        printf "%s sentinel mount: path=%s %s\n" "$phase" "$path" "$mount"
        if [ "${mount%% *}" != / ]; then printf "%s sentinel mount target is not rootfs: %s\n" "$phase" "$path" >&2; failed=1; fi
      else
        printf "%s sentinel mount lookup failed: %s\n" "$phase" "$path" >&2
        failed=1
      fi
      expected=""
      for candidate do case "$candidate" in "$path="*) expected=${candidate#*=} ;; esac; done
      if [ -n "$expected" ]; then
        actual=$(sha256sum -- "$path" | awk "{print \$1}")
        printf "%s sentinel sha256: path=%s sha256=%s\n" "$phase" "$path" "$actual"
        if [ "$actual" != "$expected" ]; then printf "%s sentinel digest changed: %s\n" "$phase" "$path" >&2; failed=1; fi
      fi
    done
    for directory in $ancestors; do
      if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        printf "%s sentinel ancestor missing or unsafe: %s\n" "$phase" "$directory" >&2
        failed=1
        continue
      fi
      metadata=$(stat -c "uid=%u gid=%g mode=%a links=%h size=%s device=%d" -- "$directory")
      printf "%s sentinel ancestor metadata: path=%s %s\n" "$phase" "$directory" "$metadata"
      case "$metadata" in uid=0\ gid=0\ *) ;; *) printf "%s sentinel ancestor ownership is not root:root: %s\n" "$phase" "$directory" >&2; failed=1 ;; esac
      mount=""
      if ! mount=$(findmnt -rn -T "$directory" -o TARGET,SOURCE,FSTYPE); then
        printf "%s sentinel ancestor mount lookup failed: %s\n" "$phase" "$directory" >&2
        failed=1
      elif [ -n "$mount" ]; then
        printf "%s sentinel ancestor mount: path=%s %s\n" "$phase" "$directory" "$mount"
        if [ "${mount%% *}" != / ]; then printf "%s sentinel ancestor mount target is not rootfs: %s\n" "$phase" "$directory" >&2; failed=1; fi
      else
        printf "%s sentinel ancestor mount lookup failed: %s\n" "$phase" "$directory" >&2
        failed=1
      fi
    done
    exit "$failed"
  ' sentinel-check "${phase}" "${PUBLISH_SENTINELS[@]}" "$@"
}
inspect_running_device_contract(){
  local instance=$1
  incus exec "${instance}" --project "${PROJECT}" -- /bin/sh -ceu '
    [ -c /dev/null ] && [ ! -L /dev/null ] \
      || { printf "published-verifier /dev/null is not a safe character device\n" >&2; exit 1; }
    metadata=$(stat -c "uid=%u gid=%g mode=%a major=%t minor=%T" -- /dev/null)
    printf "published-verifier /dev/null metadata: %s\n" "$metadata"
    device_identity=$(stat -c "mode=%a major=%t minor=%T" -- /dev/null)
    [ "$device_identity" = "mode=666 major=1 minor=3" ] \
      || { printf "published-verifier /dev/null metadata drifted\n" >&2; exit 1; }
    mount=""
    if ! mount=$(findmnt -rn -T /dev -o TARGET,SOURCE,FSTYPE); then
      printf "published-verifier /dev mount lookup failed\n" >&2
      exit 1
    fi
    [ -n "$mount" ] || { printf "published-verifier /dev mount lookup was empty\n" >&2; exit 1; }
    printf "published-verifier /dev mount: %s\n" "$mount"
    [ "${mount%% *}" = /dev ] || { printf "published-verifier /dev mount target drifted\n" >&2; exit 1; }
    [ "${mount##* }" = tmpfs ] || { printf "published-verifier /dev mount filesystem drifted\n" >&2; exit 1; }
    runuser -u runner -- /usr/bin/python3 -c "import os; fd = os.open(\"/dev/null\", os.O_RDONLY); data = os.read(fd, 1); raise SystemExit(0 if data == b\"\" else 1)" \
      || { printf "published-verifier /dev/null did not return EOF for runner\n" >&2; exit 1; }
    runuser -u runner -- /bin/sh -ceu "printf probe > /dev/null" \
      || { printf "published-verifier /dev/null is not writable by runner\n" >&2; exit 1; }
  '
}
assert_incus_archive_exclude_contract(){
  local dropin='/etc/systemd/system/incus.service.d/ci-jit-archive-excludes.conf'
  local marker='/etc/self-hosted-ci/incus-archive-exclude-compat.json'
  local expected_marker='{"dropin_sha256":"022d29bc0b515c7e325fb95d62c5b3824d2bc1fa6504b9385ad68df0bcc6b8a8","incus_package":"6.0.0-1ubuntu0.3","nested_dev_canary_passed":true,"root_dev_exclusion_preserved":true,"schema_version":1}'
  local package_version environment dropin_content marker_content
  if package_version="$(dpkg-query -W -f='${Version}' incus)"; then
    :
  else
    die 'Incus package version cannot be established'
  fi
  [[ "${package_version}" == '6.0.0-1ubuntu0.3' ]] \
    || die 'Incus package is outside the anchored archive compatibility contract'
  [[ -f "${dropin}" && ! -L "${dropin}" ]] \
    || die 'Incus anchored archive drop-in is absent or unsafe'
  [[ "$(stat -c '%u:%g:%a:%h' -- "${dropin}")" == '0:0:644:1' ]] \
    || die 'Incus anchored archive drop-in metadata drifted'
  dropin_content="$(<"${dropin}")" \
    || die 'Incus anchored archive drop-in content cannot be read'
  [[ "${dropin_content}" == $'[Service]\nEnvironment=TAR_OPTIONS=--anchored' ]] \
    || die 'Incus anchored archive drop-in content drifted'
  [[ -f "${marker}" && ! -L "${marker}" ]] \
    || die 'Incus anchored archive compatibility marker is absent or unsafe'
  [[ "$(stat -c '%u:%g:%a:%h' -- "${marker}")" == '0:0:600:1' ]] \
    || die 'Incus anchored archive compatibility marker metadata drifted'
  marker_content="$(<"${marker}")" \
    || die 'Incus anchored archive compatibility marker cannot be read'
  [[ "${marker_content}" == "${expected_marker}" ]] \
    || die 'Incus anchored archive compatibility marker content drifted'
  systemctl show incus.service --property=DropInPaths --value \
    | tr ' ' '\n' | grep -Fxq -- "${dropin}" \
    || die 'Incus anchored archive drop-in is not loaded'
  environment="$(systemctl show incus.service --property=Environment --value)" \
    || die 'Incus service environment cannot be established'
  printf '%s\n' "${environment}" | tr ' ' '\n' | grep -Fxq 'TAR_OPTIONS=--anchored' \
    || die 'Incus service does not expose anchored archive extraction'
}
assert_host_dev_null_contract(){
  local metadata
  [[ -c /dev/null && ! -L /dev/null ]]||die 'host /dev/null is not a safe character device'
  metadata="$(stat -c 'uid=%u gid=%g mode=%a major=%t minor=%T' -- /dev/null)" \
    || die 'host /dev/null metadata cannot be read'
  printf 'host /dev/null metadata: %s\n' "${metadata}"
  [[ "${metadata}" == 'uid=0 gid=0 mode=666 major=1 minor=3' ]] \
    || die 'host /dev/null metadata drifted'
  printf probe > /dev/null||die 'host /dev/null is not writable'
}
usage(){
  printf 'usage: %s [--plan] | --apply --profile-directory DIR --repository-profile FILE --expected-profile-digest SHA256 --base-fingerprint SHA256 --expected-manifest-sha256 SHA256 --candidate-alias ALIAS --overworld-bundle FILE --overworld-bundle-sha256 SHA256 --expected-overworld-commit SHA --waterfall-bundle FILE --waterfall-bundle-sha256 SHA256 --expected-waterfall-commit SHA --https-proxy http://10.254.0.1:8079 --acknowledge-temporary-build-egress --acknowledge-new-image-publication\n' "$0" >&2
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
  printf '%s\n' '{"mode":"plan","project":"ci-jit","network":"ci-jit-isolated","builder_privileged":false,"builder_nesting":false,"credentials":"forbidden","alias_reuse":false,"garm_and_worker_fenced":true,"runtime_must_be_empty":true,"build_egress":"isolated exact-domain proxy on fenced broker port 8079","production_proxy_policy_mutated":false,"postcondition":"stop isolated build proxy and restore prior service state","host_changes":false,"external_calls":"not_performed"}'
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
[[ "${https_proxy}" == http://10.254.0.1:8079 ]]||die 'build proxy must be the isolated build-only endpoint on the fenced broker port'
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
command -v incus >/dev/null; command -v squid >/dev/null; command -v python3 >/dev/null; command -v git >/dev/null
assert_incus_archive_exclude_contract

# Reuse the production transaction lock and its exact zero-scale-set checks.
source "${TRANSACTION_LIB}"
acquire_transaction_lock
zero_runtime_state||die 'GARM scale sets and ci-jit instances must both be empty'

install -d -o root -g root -m 0700 /var/lib/self-hosted-ci/profile-image-build
workdir="$(mktemp -d /var/lib/self-hosted-ci/profile-image-build/transaction.XXXXXX)"
chmod 0700 "${workdir}"
builder="overworld-image-builder-${RANDOM}${RANDOM}"
published_verifier="${builder}-published"
published_fingerprint=''; alias_published=false; transaction_succeeded=false
declare -A was_active
for service in "${FENCED_SERVICES[@]}"; do
  if systemctl is-active --quiet "${service}"; then was_active["${service}"]=true; else was_active["${service}"]=false; fi
done

cleanup(){
  local status=$?
  trap - ERR EXIT
  set +e
  if incus list "${builder}" --project "${PROJECT}" --format csv -c n 2>/dev/null | grep -Fxq "${builder}"; then
    incus delete "${builder}" --project "${PROJECT}" --force >/dev/null 2>&1||status=1
  fi
  if incus list "${builder}" --project "${PROJECT}" --format csv -c n 2>/dev/null | grep -Fxq "${builder}"; then status=1; fi
  if incus list "${published_verifier}" --project "${PROJECT}" --format csv -c n 2>/dev/null | grep -Fxq "${published_verifier}"; then
    incus delete "${published_verifier}" --project "${PROJECT}" --force >/dev/null 2>&1||status=1
  fi
  if incus list "${published_verifier}" --project "${PROJECT}" --format csv -c n 2>/dev/null | grep -Fxq "${published_verifier}"; then status=1; fi
  if [[ "${transaction_succeeded}" != true && "${alias_published}" == true ]]; then
    if [[ -z "${published_fingerprint}" ]]; then
      published_fingerprint="$(python3 - "${candidate_alias}" "$(incus image alias list --project "${PROJECT}" --format json 2>/dev/null)" <<'PY' 2>/dev/null
import json,sys
rows=[r for r in json.loads(sys.argv[2]) if r.get("name")==sys.argv[1]]
print(rows[0].get("target","") if len(rows)==1 else "")
PY
)"
    fi
    incus image alias delete "${candidate_alias}" --project "${PROJECT}" >/dev/null 2>&1||status=1
    if incus image alias list --project "${PROJECT}" --format csv -c n 2>/dev/null | grep -Fxq "${candidate_alias}"; then status=1; fi
    if [[ -n "${published_fingerprint}" && "${published_fingerprint}" != "${base_fingerprint}" ]]; then
      aliases="$(incus image alias list --project "${PROJECT}" --format json 2>/dev/null)"
      if python3 - "${published_fingerprint}" "${aliases}" <<'PY' >/dev/null 2>&1
import json,sys
if any(r.get("target")==sys.argv[1] for r in json.loads(sys.argv[2])): raise SystemExit(1)
PY
      then incus image delete "${published_fingerprint}" --project "${PROJECT}" >/dev/null 2>&1||status=1; fi
    fi
  fi
  systemctl stop "${BUILD_PROXY_UNIT}" >/dev/null 2>&1||status=1
  systemctl is-active --quiet "${BUILD_PROXY_UNIT}" && status=1
  if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)8079$'; then status=1; fi
  systemctl reset-failed "${BUILD_PROXY_UNIT}" >/dev/null 2>&1||true
  for service in "${FENCED_SERVICES[@]}"; do
    if [[ "${was_active[${service}]}" == true ]]; then
      systemctl start "${service}" >/dev/null 2>&1||status=1
      systemctl is-active --quiet "${service}"||status=1
    else
      systemctl is-active --quiet "${service}" && status=1
    fi
  done
  rm -rf --one-file-system "${workdir}"
  exit "${status}"
}
trap cleanup EXIT

systemctl stop self-hosted-ci-outbound-worker.service self-hosted-ci-allocation-broker.service self-hosted-ci-garm.service
incus_project_empty||die 'ci-jit instance inventory changed while fencing build services'
systemctl is-active --quiet "${PROXY_SERVICE}"||die 'egress proxy must already be active'
squid -k parse -f "${profile_dir}/squid-build.conf" >/dev/null 2>&1||die 'build-only Squid policy is invalid'
systemctl is-active --quiet "${BUILD_PROXY_UNIT}" && die 'stale build-only proxy unit is active'
systemd-run --quiet --unit="${BUILD_PROXY_UNIT%.service}" \
  --collect --property=Type=simple --property=RuntimeMaxSec=2h \
  --property=TimeoutStopSec=30s --property=KillMode=control-group \
  --property="Conflicts=${FENCED_SERVICES[*]}" \
  /usr/sbin/squid -N -f "${profile_dir}/squid-build.conf"
systemctl is-active --quiet "${BUILD_PROXY_UNIT}"||die 'isolated build-only proxy failed to start'

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
incus query "/1.0/instances/${builder}?project=${PROJECT}&recursion=1" >"${workdir}/builder.json"
python3 - "${workdir}/builder.json" <<'PY' || die 'builder confinement contract failed'
import json,sys
v=json.load(open(sys.argv[1])); v=v.get("metadata",v); c=v.get("expanded_config",v.get("config",{})); d=v.get("expanded_devices",v.get("devices",{}))
if c.get("security.privileged")!="false" or c.get("security.nesting")!="false" or c.get("security.idmap.isolated")!="true": raise SystemExit(1)
if set(d)!={"eth0","root"} or d["eth0"].get("network")!="ci-jit-isolated" or d["root"].get("type")!="disk": raise SystemExit(1)
if any(x.get("type") in {"proxy","unix-char","unix-block"} for x in d.values()): raise SystemExit(1)
PY
assert_host_dev_null_contract
incus start "${builder}" --project "${PROJECT}"
wait_for_cloud_init_readiness "${builder}" || die 'builder cloud-init readiness guard failed'
for file in manifest.json provision.py verify.py; do
  incus file push "${profile_dir}/${file}" "${builder}/run/self-hosted-ci-profile-build/${file}" --project "${PROJECT}" --create-dirs --mode=0700
done
for profile_asset in "${PROFILE_ASSETS[@]}"; do
  incus file push "${profile_dir}/profile-assets/${profile_asset}" \
    "${builder}/run/self-hosted-ci-profile-build/profile-assets/${profile_asset}" \
    --project "${PROJECT}" --create-dirs --mode=0600
done
incus file push "${repository_profile}" "${builder}/run/self-hosted-ci-profile-build/profile.json" --project "${PROJECT}" --create-dirs --mode=0600
incus file push "${overworld_bundle}" "${builder}/run/self-hosted-ci-profile-build/overworld.bundle" --project "${PROJECT}" --create-dirs --mode=0600
incus file push "${waterfall_bundle}" "${builder}/run/self-hosted-ci-profile-build/waterfall.bundle" --project "${PROJECT}" --create-dirs --mode=0600
python3 - "${overworld_commit}" "${overworld_bundle_sha}" "${waterfall_commit}" "${waterfall_bundle_sha}" >"${workdir}/bundle-inputs.json" <<'PY'
import json,sys
print(json.dumps(dict(zip(("overworld_commit","overworld_bundle_sha256","waterfall_commit","waterfall_bundle_sha256"),sys.argv[1:])),sort_keys=True,separators=(",",":")))
PY
incus file push "${workdir}/bundle-inputs.json" "${builder}/run/self-hosted-ci-profile-build/bundle-inputs.json" --project "${PROJECT}" --create-dirs --mode=0600
if ! incus exec "${builder}" --project "${PROJECT}" \
  --env "HTTPS_PROXY=${https_proxy}" --env "HTTP_PROXY=${https_proxy}" --env "NO_PROXY=127.0.0.1,localhost" \
  --env "https_proxy=${https_proxy}" --env "http_proxy=${https_proxy}" --env "no_proxy=127.0.0.1,localhost" \
  -- /usr/bin/python3 /run/self-hosted-ci-profile-build/provision.py; then
  incus exec "${builder}" --project "${PROJECT}" -- /bin/sh -c \
    'printf "builder memory.events:\n" >&2; cat /sys/fs/cgroup/memory.events >&2' || true
  die 'image provisioning failed'
fi
incus exec "${builder}" --project "${PROJECT}" -- /usr/bin/python3 /run/self-hosted-ci-profile-build/verify.py \
  || die 'provisioned image verification failed'
incus exec "${builder}" --project "${PROJECT}" -- /bin/sh -ceu '
  sealed=/opt/self-hosted-ci/.frontend-node-modules-sealed
  test -f "$sealed/next/dist/server/dev/browser-logs/file-logger.js"
' || die 'Next.js browser log sealing failed'
incus exec "${builder}" --project "${PROJECT}" -- /bin/sh -ceu '
  required=/opt/self-hosted-ci/overworld-deps/frontend-node_modules/next/dist/server/dev/browser-logs/file-logger.js
  rm -rf /run/self-hosted-ci-profile-build || { echo "build staging cleanup failed" >&2; exit 1; }
  rm -rf /root/.cache /root/.bun || { echo "root cache cleanup failed" >&2; exit 1; }
  rm -rf /tmp/* || { echo "tmp cleanup failed" >&2; exit 1; }
  rm -rf /var/tmp/* || { echo "var-tmp cleanup failed" >&2; exit 1; }
  target=/opt/self-hosted-ci/overworld-deps/frontend-node_modules
  legacy="${target%_*}-${target#*_}"
  rm -rf "$target"
  mv /opt/self-hosted-ci/.frontend-node-modules-sealed "$target"
  test ! -e /opt/self-hosted-ci/.frontend-node-modules-sealed || { echo "frontend dependency seal persisted" >&2; exit 1; }
  test ! -e /root/.npmrc || { echo "npm credential file persisted" >&2; exit 1; }
  test ! -e /root/.netrc || { echo "netrc credential file persisted" >&2; exit 1; }
  test ! -e /root/.config/gh/hosts.yml || { echo "GitHub CLI credential file persisted" >&2; exit 1; }
  test -f "$required" || { echo "required Next.js browser log module missing after cleanup" >&2; exit 1; }
  test ! -e "$legacy" || { echo "legacy frontend dependency path persisted" >&2; exit 1; }
' \
  || die 'provisioned image cleanup verification failed'
inspect_running_sentinels "${builder}" builder-post-cleanup \
  || die 'builder post-cleanup sentinel verification failed'
incus exec "${builder}" --project "${PROJECT}" -- sha256sum -- "${PUBLISH_SENTINELS[@]}" \
  | tee "${workdir}/publish-sentinels.sha256" \
  || die 'builder sentinel digest inventory failed'
incus exec "${builder}" --project "${PROJECT}" -- /bin/sync \
  || die 'provisioned image sync failed'
if ! incus stop "${builder}" --project "${PROJECT}" --timeout 60; then
  incus stop "${builder}" --project "${PROJECT}" --force
fi
incus list "${builder}" --project "${PROJECT}" --format csv -c s | grep -Fxq STOPPED \
  || die 'builder did not reach the stopped state before publication'
sentinel_probe="${workdir}/sentinel-probe"
: >"${sentinel_probe}"
chmod 0600 "${sentinel_probe}"
[[ -f "${sentinel_probe}" && ! -L "${sentinel_probe}" ]] \
  || die 'sentinel probe destination is unsafe'
[[ "$(stat -c 'uid=%u gid=%g mode=%a' -- "${sentinel_probe}")" == 'uid=0 gid=0 mode=600' ]] \
  || die 'sentinel probe destination metadata drifted'
for sentinel in "${PUBLISH_SENTINELS[@]}"; do
  : >"${sentinel_probe}"
  incus file pull "${builder}${sentinel}" - --project "${PROJECT}" >"${sentinel_probe}" \
    || die "stopped-builder rootfs is missing or cannot expose sentinel: ${sentinel}"
done
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
published_export_dir="${workdir}/published-export"
mkdir -m 0700 "${published_export_dir}"
incus image export "${published_fingerprint}" "${published_export_dir}/image" --project "${PROJECT}" \
  || die 'published image export failed'
python3 - "${published_export_dir}" "${workdir}/publish-sentinels.sha256" "${PUBLISH_SENTINELS[@]}" <<'PY' \
  || die 'published image tar sentinel verification failed'
import hashlib
from pathlib import Path
import sys
import tarfile

export_dir = Path(sys.argv[1])
inventory_path = Path(sys.argv[2])
sentinels = sys.argv[3:]
archives = [path for path in export_dir.iterdir() if path.is_file() and not path.is_symlink()]
if len(archives) != 1:
    raise SystemExit(f"published image export is ambiguous: regular_archive_count={len(archives)}")
expected = {}
for line in inventory_path.read_text(encoding="utf-8").splitlines():
    fields = line.split(maxsplit=1)
    if len(fields) != 2 or len(fields[0]) != 64 or fields[1] in expected:
        raise SystemExit("published image sentinel digest inventory is malformed")
    expected[fields[1]] = fields[0]
if set(expected) != set(sentinels):
    raise SystemExit("published image sentinel digest inventory is incomplete")
with tarfile.open(archives[0], mode="r|*") as archive:
    wanted = {f"rootfs/{sentinel.removeprefix('/')}": sentinel for sentinel in sentinels}
    seen = set()
    while True:
        member = archive.next()
        if member is None:
            break
        try:
            sentinel = wanted.get(member.name)
            if sentinel is None:
                continue
            if member.name in seen:
                raise SystemExit(f"published image archive contains a duplicate member: {member.name}")
            seen.add(member.name)
            if not member.isfile() or member.uid != 0 or member.gid != 0:
                raise SystemExit(f"published image archive sentinel is unsafe: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise SystemExit(f"published image archive sentinel cannot be read: {member.name}")
            digest = hashlib.sha256()
            with stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual = digest.hexdigest()
            print(f"published image archive sentinel: path={member.name} uid={member.uid} gid={member.gid} sha256={actual}")
            if actual != expected[sentinel]:
                raise SystemExit(f"published image archive sentinel digest changed: {member.name}")
        finally:
            archive.members.clear()
    missing = set(wanted) - seen
    if missing:
        raise SystemExit(f"published image archive sentinels are missing: count={len(missing)}")
PY
incus delete "${builder}" --project "${PROJECT}"
incus init "${published_fingerprint}" "${published_verifier}" --project "${PROJECT}" --profile ci-jit
for sentinel in "${PUBLISH_SENTINELS[@]}"; do
  : >"${sentinel_probe}"
  if incus file pull "${published_verifier}${sentinel}" - --project "${PROJECT}" >"${sentinel_probe}" 2>"${workdir}/initialized-verifier-sentinel.stderr"; then
    printf 'initialized-verifier pre-start sentinel present: %s\n' "${sentinel}"
  else
    printf 'initialized-verifier pre-start sentinel absent or inaccessible (diagnostic only): %s\n' "${sentinel}" >&2
  fi
done
assert_host_dev_null_contract
incus start "${published_verifier}" --project "${PROJECT}"
expected_sentinel_digests=()
while read -r digest sentinel; do
  expected_sentinel_digests+=("${sentinel}=${digest}")
done <"${workdir}/publish-sentinels.sha256"
[[ "${#expected_sentinel_digests[@]}" -eq "${#PUBLISH_SENTINELS[@]}" ]] \
  || die 'builder sentinel digest inventory is incomplete'
inspect_running_sentinels "${published_verifier}" published-verifier-post-start "${expected_sentinel_digests[@]}" \
  || die 'published image boot sentinel verification failed'
inspect_running_device_contract "${published_verifier}" \
  || die 'published image boot device verification failed'
incus exec "${published_verifier}" --project "${PROJECT}" -- /bin/sh -ceu '
  root=/opt/self-hosted-ci/overworld-deps/frontend-node_modules
  link="$root/.bin/eslint"
  test -d "$root" && test ! -L "$root"
  test -L "$link"
  target=$(readlink -- "$link")
  case "$target" in /*) echo "published frontend eslint launcher is absolute" >&2; exit 1;; esac
  resolved=$(readlink -f -- "$link")
  case "$resolved" in "$root"/*) ;; *) echo "published frontend eslint launcher escapes its root" >&2; exit 1;; esac
  test "$resolved" = "$root/eslint/bin/eslint.js"
  test -f "$resolved" && test ! -L "$resolved"
  test -f "$root/eslint/package.json" && test ! -L "$root/eslint/package.json"
  workspace=$(mktemp -d /var/tmp/self-hosted-ci-eslint-verify.XXXXXX)
  cleanup(){ rm -rf -- "$workspace"; }
  trap cleanup EXIT
  trap "exit 1" HUP INT TERM
  mkdir -p "$workspace/frontend/node_modules"
  chmod 0755 "$workspace" "$workspace/frontend" "$workspace/frontend/node_modules"
  cp -al "$root/." "$workspace/frontend/node_modules/"
  runuser -u runner -- bun "$workspace/frontend/node_modules/.bin/eslint" --version
  cleanup
  test ! -e "$workspace"
  trap - EXIT HUP INT TERM
' || die 'published image frontend eslint launcher verification failed'
incus delete "${published_verifier}" --project "${PROJECT}" --force
if incus list "${published_verifier}" --project "${PROJECT}" --format csv -c n | grep -Fxq "${published_verifier}"; then
  die 'published image verifier cleanup failed'
fi
transaction_succeeded=true
printf '{"status":"built","project":"%s","profile":"overworld-pr-v1","base_fingerprint":"%s","manifest_sha256":"%s","candidate_alias":"%s","fingerprint":"%s","builder_privileged":false,"builder_nesting":false,"credentials_persisted":false,"alias_moved":false}\n' \
  "${PROJECT}" "${base_fingerprint}" "${manifest_sha}" "${candidate_alias}" "${published_fingerprint}"
