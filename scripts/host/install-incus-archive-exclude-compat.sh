#!/usr/bin/env bash
set -Eeuo pipefail

export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

readonly EXPECTED_DISTRO='Ubuntu-24.04-CI'
readonly EXPECTED_INCUS_PACKAGE='6.0.0-1ubuntu0.3'
readonly SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TRANSACTION_LIB="${SCRIPT_DIRECTORY}/garm-jit-transaction-lib.sh"
readonly PROJECT='ci-jit'
readonly PROFILE='ci-jit'
readonly DROPIN_DIRECTORY='/etc/systemd/system/incus.service.d'
readonly DROPIN_PATH="${DROPIN_DIRECTORY}/ci-jit-archive-excludes.conf"
readonly DROPIN_SHA256='022d29bc0b515c7e325fb95d62c5b3824d2bc1fa6504b9385ad68df0bcc6b8a8'
readonly MARKER_DIRECTORY='/etc/self-hosted-ci'
readonly MARKER_PATH='/etc/self-hosted-ci/incus-archive-exclude-compat.json'
readonly MARKER_CONTENT='{"dropin_sha256":"022d29bc0b515c7e325fb95d62c5b3824d2bc1fa6504b9385ad68df0bcc6b8a8","incus_package":"6.0.0-1ubuntu0.3","nested_dev_canary_passed":true,"root_dev_exclusion_preserved":true,"schema_version":1}'
readonly CANARY_VALUE='nested-dev-preserved'

usage() {
  printf 'usage: %s [--plan] | --apply --acknowledge-incus-service-mutation\n' "$0" >&2
  exit 64
}

mode='plan'
acknowledged=false
while (( $# )); do
  case "$1" in
    --plan) mode='plan'; shift ;;
    --apply) mode='apply'; shift ;;
    --acknowledge-incus-service-mutation) acknowledged=true; shift ;;
    *) usage ;;
  esac
done

if [[ "${mode}" == 'plan' ]]; then
  printf '{"mode":"plan","host_changes":false,"incus_package":"%s","dropin":"%s","canary":"image-import-init-nested-dev","project":"%s"}\n' \
    "${EXPECTED_INCUS_PACKAGE}" "${DROPIN_PATH}" "${PROJECT}"
  exit 0
fi
[[ "${acknowledged}" == true ]] || usage

phase='preflight'
workdir=''
dropin_staging=''
canary_image=''
canary_instance=''
canary_image_fingerprint=''
preexisting_image_inventory=''
canary_import_attempted=false
canary_image_owned=false
canary_instance_attempted=false

fail() {
  printf 'incus archive compatibility transaction blocked: phase=%s detail=%s\n' "${phase}" "$1" >&2
  exit 1
}

alias_target_from_inventory() {
  python3 - "$1" "$2" <<'PY'
import json,re,sys
rows=json.loads(sys.argv[1])
if not isinstance(rows,list): raise SystemExit(2)
matches=[]
for row in rows:
    if not isinstance(row,dict) or not isinstance(row.get("name"),str) or not isinstance(row.get("target"),str): raise SystemExit(2)
    if not re.fullmatch(r"[0-9a-f]{64}",row["target"]): raise SystemExit(2)
    if row["name"]==sys.argv[2]: matches.append(row["target"])
if len(matches)>1: raise SystemExit(2)
print(matches[0] if matches else "")
PY
}

fingerprint_state_from_inventory() {
  python3 - "$1" "$2" <<'PY'
import json,re,sys
rows=json.loads(sys.argv[1])
if not isinstance(rows,list): raise SystemExit(2)
fingerprints=[]
for row in rows:
    if not isinstance(row,dict) or not isinstance(row.get("fingerprint"),str): raise SystemExit(2)
    if not re.fullmatch(r"[0-9a-f]{64}",row["fingerprint"]): raise SystemExit(2)
    fingerprints.append(row["fingerprint"])
print("present" if sys.argv[2] in fingerprints else "absent")
PY
}

instance_state_from_inventory() {
  python3 - "$1" "$2" <<'PY'
import json,sys
rows=json.loads(sys.argv[1])
if not isinstance(rows,list): raise SystemExit(2)
names=[]
for row in rows:
    if not isinstance(row,dict) or not isinstance(row.get("name"),str): raise SystemExit(2)
    names.append(row["name"])
print("present" if sys.argv[2] in names else "absent")
PY
}

cleanup() {
  local status=$?
  local cleanup_failed=false
  local inventory='' aliases='' images='' state='' target=''
  trap - ERR EXIT
  set +e
  if [[ "${canary_instance_attempted}" == true ]]; then
    if inventory="$(incus list --project "${PROJECT}" --format json 2>/dev/null)" \
      && state="$(instance_state_from_inventory "${inventory}" "${canary_instance}" 2>/dev/null)"; then
      if [[ "${state}" == present ]]; then
        incus delete "${canary_instance}" --project "${PROJECT}" --force >/dev/null 2>&1 || cleanup_failed=true
      elif [[ "${state}" != absent ]]; then
        cleanup_failed=true
      fi
    else
      cleanup_failed=true
    fi
  fi
  if [[ "${canary_import_attempted}" == true ]]; then
    if aliases="$(incus image alias list --project "${PROJECT}" --format json 2>/dev/null)" \
      && target="$(alias_target_from_inventory "${aliases}" "${canary_image}" 2>/dev/null)"; then
      if [[ -n "${target}" && "${target}" != "${canary_image_fingerprint}" ]]; then
        cleanup_failed=true
      elif [[ -n "${target}" ]]; then
        incus image alias delete "${canary_image}" --project "${PROJECT}" >/dev/null 2>&1 || cleanup_failed=true
      fi
    else
      cleanup_failed=true
    fi
    if ! images="$(incus image list --project "${PROJECT}" --format json 2>/dev/null)"; then
      cleanup_failed=true
    fi
    if [[ "${canary_image_owned}" == true ]]; then
      if state="$(fingerprint_state_from_inventory "${images}" "${canary_image_fingerprint}" 2>/dev/null)"; then
        if [[ "${state}" == present ]]; then
          incus image delete "${canary_image_fingerprint}" --project "${PROJECT}" >/dev/null 2>&1 || cleanup_failed=true
        elif [[ "${state}" != absent ]]; then
          cleanup_failed=true
        fi
      else
        cleanup_failed=true
      fi
    fi
  fi
  if [[ -n "${dropin_staging}" && -e "${dropin_staging}" ]]; then
    rm -f -- "${dropin_staging}" || cleanup_failed=true
  fi
  if [[ -n "${workdir}" && -e "${workdir}" ]]; then
    rm -rf -- "${workdir}" || cleanup_failed=true
  fi
  if [[ "${canary_instance_attempted}" == true || "${canary_import_attempted}" == true ]]; then
    if inventory="$(incus list --all-projects --format csv 2>/dev/null)"; then
      [[ -z "${inventory}" ]] || cleanup_failed=true
    else
      cleanup_failed=true
    fi
    if aliases="$(incus image alias list --project "${PROJECT}" --format json 2>/dev/null)" \
      && target="$(alias_target_from_inventory "${aliases}" "${canary_image}" 2>/dev/null)"; then
      [[ -z "${target}" ]] || cleanup_failed=true
    else
      cleanup_failed=true
    fi
    if [[ "${canary_image_owned}" == true ]]; then
      if images="$(incus image list --project "${PROJECT}" --format json 2>/dev/null)" \
        && state="$(fingerprint_state_from_inventory "${images}" "${canary_image_fingerprint}" 2>/dev/null)"; then
        [[ "${state}" == absent ]] || cleanup_failed=true
      else
        cleanup_failed=true
      fi
    fi
    zero_runtime_state >/dev/null 2>&1 || cleanup_failed=true
  fi
  if [[ "${cleanup_failed}" == true ]]; then
    printf 'incus archive compatibility cleanup failed for exact canary resources\n' >&2
    exit 1
  fi
  exit "${status}"
}
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || fail 'apply requires WSL root'
[[ "${WSL_DISTRO_NAME:-}" == "${EXPECTED_DISTRO}" ]] || fail 'unexpected WSL distro'
[[ -d /run/systemd/system ]] || fail 'systemd is unavailable'
for command in incus dpkg-query systemctl install stat tar python3 cmp flock sha256sum mktemp runuser; do
  command -v "${command}" >/dev/null || fail "required command is absent: ${command}"
done
[[ -f "${TRANSACTION_LIB}" && ! -L "${TRANSACTION_LIB}" ]] \
  || fail 'GARM transaction library is absent or unsafe'
# shellcheck source=scripts/host/garm-jit-transaction-lib.sh
source "${TRANSACTION_LIB}"
acquire_transaction_lock
[[ "$(dpkg-query -W -f='${Version}' incus 2>/dev/null)" == "${EXPECTED_INCUS_PACKAGE}" ]] \
  || fail 'Incus package does not match the exact compatibility target'
for unit in self-hosted-ci-garm.service self-hosted-ci-allocation-broker.service self-hosted-ci-outbound-worker.service; do
  if active_state="$(systemctl is-active "${unit}" 2>&1)"; then
    fail "${unit} must be inactive"
  fi
  [[ "${active_state}" == 'inactive' ]] || fail "${unit} must be inactive"
done
zero_runtime_state || fail 'GARM scale sets or ci-jit instances remain'
if inventory="$(incus list --all-projects --format csv)"; then
  :
else
  fail 'Incus instance inventory is unobservable'
fi
[[ -z "${inventory}" ]] || fail 'Incus contains an instance'
canary_nonce="$(python3 -c 'import secrets; print(secrets.token_hex(8))')" \
  || fail 'canary nonce generation failed'
[[ "${canary_nonce}" =~ ^[0-9a-f]{16}$ ]] || fail 'canary nonce is invalid'
canary_image="ci-jit-archive-canary-image-${canary_nonce}"
canary_instance="ci-jit-archive-canary-instance-${canary_nonce}"
if alias_inventory="$(incus image alias list --project "${PROJECT}" --format json)"; then
  :
else
  fail 'Incus image alias inventory is unobservable'
fi
if alias_target="$(alias_target_from_inventory "${alias_inventory}" "${canary_image}")"; then
  :
else
  fail 'Incus image alias inventory is malformed'
fi
[[ -z "${alias_target}" ]] || fail 'reserved canary image alias already exists'
if preexisting_image_inventory="$(incus image list --project "${PROJECT}" --format json)"; then
  :
else
  fail 'Incus image fingerprint inventory is unobservable'
fi
# Validate the complete inventory schema before any image mutation.
fingerprint_state_from_inventory "${preexisting_image_inventory}" \
  '0000000000000000000000000000000000000000000000000000000000000000' >/dev/null \
  || fail 'Incus image fingerprint inventory is malformed'
incus profile show "${PROFILE}" --project "${PROJECT}" >/dev/null \
  || fail 'exact ci-jit profile is unavailable'
if [[ -e "${MARKER_PATH}" ]]; then
  [[ -f "${MARKER_PATH}" && ! -L "${MARKER_PATH}" ]] \
    || fail 'Incus archive compatibility marker is unsafe'
  [[ "$(stat -c '%u:%g:%a:%h' -- "${MARKER_PATH}")" == '0:0:600:1' ]] \
    || fail 'Incus archive compatibility marker metadata drift'
  [[ "$(<"${MARKER_PATH}")" == "${MARKER_CONTENT}" ]] \
    || fail 'Incus archive compatibility marker content drift'
fi

phase='install-dropin'
readonly dropin_content='[Service]
Environment=TAR_OPTIONS=--anchored'
install -d -o root -g root -m 0755 "${DROPIN_DIRECTORY}"
if [[ -e "${DROPIN_PATH}" ]]; then
  [[ -f "${DROPIN_PATH}" && ! -L "${DROPIN_PATH}" ]] || fail 'managed drop-in is not a regular file'
  [[ "$(stat -c '%u:%g:%a:%h' -- "${DROPIN_PATH}")" == '0:0:644:1' ]] \
    || fail 'managed drop-in metadata drift'
  [[ "$(cat -- "${DROPIN_PATH}")" == "${dropin_content}" ]] || fail 'managed drop-in content drift'
else
  dropin_staging="$(mktemp "${DROPIN_DIRECTORY}/.ci-jit-archive-excludes.XXXXXX")"
  chown root:root "${dropin_staging}"
  chmod 0644 "${dropin_staging}"
  printf '%s\n' "${dropin_content}" >"${dropin_staging}"
  [[ "$(sha256sum "${dropin_staging}" | cut -d' ' -f1)" == "${DROPIN_SHA256}" ]] \
    || fail 'managed drop-in staging digest drift'
  mv -T -- "${dropin_staging}" "${DROPIN_PATH}"
  dropin_staging=''
fi

phase='restart-incus'
systemctl daemon-reload
systemctl restart incus.service
[[ "$(systemctl is-active incus.service)" == 'active' ]] || fail 'Incus did not return active'
systemctl show incus.service --property=DropInPaths --value \
  | tr ' ' '\n' | grep -Fxq -- "${DROPIN_PATH}" \
  || fail 'managed drop-in is not loaded'
systemctl show incus.service --property=Environment --value \
  | tr ' ' '\n' | grep -Fxq 'TAR_OPTIONS=--anchored' \
  || fail 'Incus does not expose the anchored tar environment'

phase='nested-dev-canary'
workdir="$(mktemp -d /var/tmp/self-hosted-ci-incus-archive-canary.XXXXXX)"
chmod 0700 "${workdir}"
mkdir -p "${workdir}/image/rootfs/opt/self-hosted-ci/incus-unpack-probe/dev"
mkdir -p "${workdir}/image/rootfs/dev"
printf '%s' "${CANARY_VALUE}" >"${workdir}/image/rootfs/opt/self-hosted-ci/incus-unpack-probe/dev/sentinel"
printf '%s' 'must-remain-excluded' >"${workdir}/image/rootfs/dev/forbidden"
printf '%s\n' \
  'architecture: x86_64' \
  'creation_date: 1700000000' \
  'properties:' \
  '  description: self-hosted-ci nested dev extraction canary' \
  "  ci_jit_canary_nonce: ${canary_nonce}" \
  >"${workdir}/image/metadata.yaml"
tar --numeric-owner --owner=0 --group=0 -C "${workdir}/image" \
  -czf "${workdir}/nested-dev-canary.tar.gz" metadata.yaml rootfs
canary_image_fingerprint="$(sha256sum "${workdir}/nested-dev-canary.tar.gz" | cut -d' ' -f1)"
[[ "${canary_image_fingerprint}" =~ ^[0-9a-f]{64}$ ]] \
  || fail 'canary image fingerprint is unavailable or invalid before import'
if preexisting_fingerprint_state="$(fingerprint_state_from_inventory \
  "${preexisting_image_inventory}" "${canary_image_fingerprint}")"; then
  :
else
  fail 'Incus image fingerprint inventory is malformed before import'
fi
if [[ "${preexisting_fingerprint_state}" == absent ]]; then
  canary_image_owned=true
elif [[ "${preexisting_fingerprint_state}" != present ]]; then
  fail 'canary image fingerprint ownership is indeterminate'
fi
canary_import_attempted=true
incus image import "${workdir}/nested-dev-canary.tar.gz" \
  --project "${PROJECT}" --alias "${canary_image}"
if alias_inventory="$(incus image alias list --project "${PROJECT}" --format json)"; then
  :
else
  fail 'Incus image alias inventory is unobservable after import'
fi
if imported_fingerprint="$(alias_target_from_inventory "${alias_inventory}" "${canary_image}")"; then
  :
else
  fail 'Incus image alias inventory is malformed after import'
fi
[[ "${imported_fingerprint}" == "${canary_image_fingerprint}" ]] \
  || fail 'imported canary image fingerprint drifted'
canary_instance_attempted=true
incus init "${canary_image}" "${canary_instance}" \
  --project "${PROJECT}" --profile "${PROFILE}"
incus file pull \
  "${canary_instance}/opt/self-hosted-ci/incus-unpack-probe/dev/sentinel" - \
  --project "${PROJECT}" >"${workdir}/observed-sentinel"
printf '%s' "${CANARY_VALUE}" >"${workdir}/expected-sentinel"
cmp -- "${workdir}/expected-sentinel" "${workdir}/observed-sentinel" \
  || fail 'nested dev sentinel content drifted during image initialization'
if incus file pull "${canary_instance}/dev/forbidden" - \
  --project "${PROJECT}" >"${workdir}/forbidden-sentinel" 2>"${workdir}/forbidden-error"; then
  fail 'root dev content was not excluded during image initialization'
fi

phase='cleanup-canary'
incus delete "${canary_instance}" --project "${PROJECT}"
incus image alias delete "${canary_image}" --project "${PROJECT}"
if [[ "${canary_image_owned}" == true ]]; then
  incus image delete "${canary_image_fingerprint}" --project "${PROJECT}"
fi
if inventory="$(incus list --all-projects --format csv)"; then
  :
else
  fail 'Incus instance inventory is unobservable after canary cleanup'
fi
[[ -z "${inventory}" ]] || fail 'Incus instance residue remains'
if alias_inventory="$(incus image alias list --project "${PROJECT}" --format json)"; then
  :
else
  fail 'Incus image alias inventory is unobservable after canary cleanup'
fi
if alias_target="$(alias_target_from_inventory "${alias_inventory}" "${canary_image}")"; then
  :
else
  fail 'Incus image alias inventory is malformed after canary cleanup'
fi
[[ -z "${alias_target}" ]] || fail 'Incus canary image alias residue remains'
if image_inventory="$(incus image list --project "${PROJECT}" --format json)"; then
  :
else
  fail 'Incus image fingerprint inventory is unobservable after canary cleanup'
fi
if fingerprint_state="$(fingerprint_state_from_inventory "${image_inventory}" "${canary_image_fingerprint}")"; then
  :
else
  fail 'Incus image fingerprint inventory is malformed after canary cleanup'
fi
if [[ "${preexisting_fingerprint_state}" == absent ]]; then
  [[ "${fingerprint_state}" == absent ]] || fail 'Incus owned canary image residue remains'
else
  [[ "${fingerprint_state}" == present ]] || fail 'Incus preexisting image was not preserved'
fi
zero_runtime_state || fail 'runtime residue remains after canary cleanup'
canary_instance_attempted=false
canary_import_attempted=false
canary_image_owned=false

phase='attest'
install -d -o root -g root -m 0755 "${MARKER_DIRECTORY}"
durable_write "${MARKER_PATH}" "${MARKER_CONTENT}"
[[ -f "${MARKER_PATH}" && ! -L "${MARKER_PATH}" ]] \
  || fail 'Incus archive compatibility marker was not written safely'
[[ "$(stat -c '%u:%g:%a:%h' -- "${MARKER_PATH}")" == '0:0:600:1' ]] \
  || fail 'Incus archive compatibility marker metadata drift after write'
[[ "$(<"${MARKER_PATH}")" == "${MARKER_CONTENT}" ]] \
  || fail 'Incus archive compatibility marker content drift after write'

phase='complete'
printf '{"status":"installed","incus_package":"%s","dropin":"%s","marker":"%s","archive_excludes_anchored":true,"nested_dev_canary_passed":true,"root_dev_exclusion_preserved":true,"instances":0,"canary_image_absent":true}\n' \
  "${EXPECTED_INCUS_PACKAGE}" "${DROPIN_PATH}" "${MARKER_PATH}"
