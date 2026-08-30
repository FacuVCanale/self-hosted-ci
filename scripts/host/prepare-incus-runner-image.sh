#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT="ci-jit"
readonly TARGET_REMOTE="local"
readonly EXPECTED_ARCHITECTURE="x86_64"

die() { printf 'runner-image preparation blocked: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'usage: %s [--plan|--apply] --source-remote REMOTE --source-ref REF --expected-fingerprint SHA256 --local-alias ALIAS [--acknowledge-remote-image-fetch --acknowledge-local-image-alias-mutation]\n' "$0" >&2
  exit 2
}

mode=plan
source_remote=""
source_ref=""
expected_fingerprint=""
local_alias=""
ack_fetch=false
ack_alias=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) mode=plan; shift ;;
    --apply) mode=apply; shift ;;
    --source-remote) [[ $# -ge 2 ]] || usage; source_remote="$2"; shift 2 ;;
    --source-ref) [[ $# -ge 2 ]] || usage; source_ref="$2"; shift 2 ;;
    --expected-fingerprint) [[ $# -ge 2 ]] || usage; expected_fingerprint="$2"; shift 2 ;;
    --local-alias) [[ $# -ge 2 ]] || usage; local_alias="$2"; shift 2 ;;
    --acknowledge-remote-image-fetch) ack_fetch=true; shift ;;
    --acknowledge-local-image-alias-mutation) ack_alias=true; shift ;;
    *) usage ;;
  esac
done

[[ "${source_remote}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ && "${source_remote}" != "${TARGET_REMOTE}" ]] || \
  die 'source remote must be an explicit non-local Incus remote name'
[[ "${source_ref}" =~ ^[A-Za-z0-9][A-Za-z0-9._/+@:-]{0,255}$ && "${source_ref}" != *' '* ]] || \
  die 'source ref must be an explicit alias or fingerprint without whitespace'
[[ "${expected_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || \
  die 'expected fingerprint must be lowercase SHA-256'
[[ "${local_alias}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{2,127}$ && "${local_alias}" != *:* ]] || \
  die 'local alias must be an exact local name without a remote prefix'

if [[ "${mode}" == plan ]]; then
  python3 - "${source_remote}" "${source_ref}" "${expected_fingerprint}" "${local_alias}" <<'PY'
import json, sys
remote, ref, fingerprint, alias = sys.argv[1:]
print(json.dumps({
    "mode": "plan",
    "project": "ci-jit",
    "source_remote": remote,
    "source_ref": ref,
    "expected_fingerprint": fingerprint,
    "local_alias": alias,
    "expected_architecture": "x86_64",
    "host_changes": False,
    "remote_calls": "not_performed",
    "garm_enabled": False,
    "runner_registration": "not_performed",
    "sequence": [
        "verify explicit source ref resolves to the expected immutable fingerprint",
        "refetch by full fingerprint into project ci-jit if the image is absent",
        "create the exact local alias without reuse or alias overwrite",
        "verify exact local fingerprint, container type, architecture, and alias mapping",
    ],
}, sort_keys=True, separators=(",", ":")))
PY
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || die '--apply must run as root'
[[ "${WSL_DISTRO_NAME:-}" == Ubuntu-24.04-CI ]] || die 'WSL_DISTRO_NAME must be Ubuntu-24.04-CI'
grep -qi wsl2 /proc/sys/kernel/osrelease || die 'host must be WSL2'
[[ "${ack_fetch}" == true && "${ack_alias}" == true ]] || die '--apply requires both explicit acknowledgements'
command -v incus >/dev/null || die 'Incus CLI is absent'
command -v python3 >/dev/null || die 'Python 3 is absent'
command -v flock >/dev/null || die 'flock is absent'
command -v systemctl >/dev/null || die 'systemctl is absent'
systemctl is-active --quiet self-hosted-ci-garm.service && die 'GARM must be inactive while preparing its runner image'
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED ]] || die 'activation sentinel must be absent while preparing the runner image'

install -d -o root -g root -m 0750 /run/self-hosted-ci
exec 9>/run/self-hosted-ci/runner-image.lock
flock -n 9 || die 'another runner-image transaction is active'

workdir="$(mktemp -d /run/self-hosted-ci/runner-image.XXXXXX)"
chmod 0700 "${workdir}"
created_alias=false
transaction_succeeded=false
cleanup() {
  cleanup_status=$?
  if [[ "${transaction_succeeded}" != true && "${created_alias}" == true ]]; then
    incus image alias delete "${TARGET_REMOTE}:${local_alias}" --project "${PROJECT}" >/dev/null 2>&1 || \
      printf 'runner-image rollback warning: created alias could not be removed\n' >&2
  fi
  rm -rf --one-file-system "${workdir}" || printf 'runner-image cleanup warning: transaction directory could not be removed\n' >&2
  return "${cleanup_status}"
}
trap cleanup EXIT

incus remote list --format json >"${workdir}/remotes.json"
python3 - "${source_remote}" "${workdir}/remotes.json" <<'PY'
import json, pathlib, sys
remote, path = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
if isinstance(value, list):
    names = {item.get("name", item.get("Name")) for item in value if isinstance(item, dict)}
elif isinstance(value, dict):
    names = set(value)
else:
    names = set()
if remote not in names:
    raise SystemExit("explicit source remote is not configured")
PY

incus project show "${PROJECT}" --format json >"${workdir}/project.json" || die 'ci-jit project is absent'
python3 - "${workdir}/project.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("config", {}).get("features.images") != "false":
    raise SystemExit("ci-jit must inherit the dedicated local image store")
PY
incus list --project "${PROJECT}" --format json >"${workdir}/instances-before.json"
python3 - "${workdir}/instances-before.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value != []:
    raise SystemExit("ci-jit must contain zero instances while preparing the runner image")
PY

incus image list "${source_remote}:${source_ref}" --format json >"${workdir}/source.json" || \
  die 'explicit source image could not be resolved'
python3 - "${source_ref}" "${expected_fingerprint}" "${EXPECTED_ARCHITECTURE}" "${workdir}/source.json" <<'PY'
import json, pathlib, re, sys
source_ref, fingerprint, architecture, path = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
    raise SystemExit("source image inventory is invalid")
matches = [item for item in value if item.get("fingerprint") == fingerprint]
if len(matches) != 1:
    raise SystemExit("source ref fingerprint does not match the expected fingerprint")
image = matches[0]
aliases = [item.get("name") for item in image.get("aliases", []) if isinstance(item, dict)]
fingerprint_ref = bool(re.fullmatch(r"[0-9a-f]{12,64}", source_ref)) and fingerprint.startswith(source_ref)
if source_ref not in aliases and not fingerprint_ref:
    raise SystemExit("source inventory does not expose the exact source ref")
if image.get("type") != "container":
    raise SystemExit("source image is not a container image")
if image.get("architecture") != architecture:
    raise SystemExit("source image architecture is not x86_64")
PY

incus image alias list "${TARGET_REMOTE}:" --project "${PROJECT}" --format json >"${workdir}/aliases-before.json"
alias_state="$(python3 - "${local_alias}" "${expected_fingerprint}" "${workdir}/aliases-before.json" <<'PY'
import json, pathlib, sys
alias, fingerprint, path = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
matches = [item for item in value if item.get("name") == alias]
if len(matches) > 1:
    raise SystemExit("local alias inventory is ambiguous")
if not matches:
    print("absent")
elif matches[0].get("target") == fingerprint:
    print("exact")
else:
    raise SystemExit("local alias already points to a different fingerprint")
PY
)"

if [[ "${alias_state}" == absent ]]; then
  incus image list "${TARGET_REMOTE}:${expected_fingerprint}" --project "${PROJECT}" --format json \
    >"${workdir}/local-before.json" || die 'local image inventory could not be queried'
  local_image_state="$(python3 - "${expected_fingerprint}" "${workdir}/local-before.json" <<'PY'
import json, pathlib, sys
fingerprint, path = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
    raise SystemExit("local image inventory is invalid")
matches = [item for item in value if item.get("fingerprint") == fingerprint]
if len(matches) > 1:
    raise SystemExit("local fingerprint inventory is ambiguous")
print("present" if matches else "absent")
PY
)" || die 'local image inventory could not be validated'
  if [[ "${local_image_state}" == absent ]]; then
    # Resolve the mutable source ref once, then transfer by the verified full
    # fingerprint so a remote alias change cannot alter this transaction.
    incus image copy "${source_remote}:${expected_fingerprint}" "${TARGET_REMOTE}:" \
      --target-project "${PROJECT}" --quiet || die 'pinned image copy failed'
  fi
  incus image alias create "${TARGET_REMOTE}:${local_alias}" "${expected_fingerprint}" \
    --project "${PROJECT}" --description "self-hosted-ci pinned runner image ${expected_fingerprint}" || \
    die 'exact local alias creation failed'
  created_alias=true
fi

incus image list "${TARGET_REMOTE}:${local_alias}" --project "${PROJECT}" --format json >"${workdir}/local-after.json"
incus image alias list "${TARGET_REMOTE}:" --project "${PROJECT}" --format json >"${workdir}/aliases-after.json"
incus list --project "${PROJECT}" --format json >"${workdir}/instances-after.json"
python3 - "${local_alias}" "${expected_fingerprint}" "${EXPECTED_ARCHITECTURE}" \
  "${workdir}/local-after.json" "${workdir}/aliases-after.json" "${workdir}/instances-after.json" <<'PY'
import json, pathlib, sys
alias, fingerprint, architecture, image_path, aliases_path, instances_path = sys.argv[1:]
images = json.loads(pathlib.Path(image_path).read_text(encoding="utf-8"))
aliases = json.loads(pathlib.Path(aliases_path).read_text(encoding="utf-8"))
instances = json.loads(pathlib.Path(instances_path).read_text(encoding="utf-8"))
if not isinstance(images, list) or any(not isinstance(item, dict) for item in images):
    raise SystemExit("local image postcondition inventory is invalid")
image_matches = [
    item for item in images
    if item.get("fingerprint") == fingerprint
    and alias in [entry.get("name") for entry in item.get("aliases", []) if isinstance(entry, dict)]
]
if len(image_matches) != 1:
    raise SystemExit("local image postcondition failed")
image = image_matches[0]
if image.get("fingerprint") != fingerprint or image.get("type") != "container" or image.get("architecture") != architecture:
    raise SystemExit("local image postcondition failed")
matches = [item for item in aliases if item.get("name") == alias]
if len(matches) != 1 or matches[0].get("target") != fingerprint:
    raise SystemExit("exact local alias postcondition failed")
if instances != []:
    raise SystemExit("ci-jit instance inventory changed during runner-image preparation")
PY

transaction_succeeded=true
printf '{"status":"prepared","project":"%s","source_remote":"%s","source_ref":"%s","fingerprint":"%s","local_alias":"%s","architecture":"%s","alias_created":%s,"garm_enabled":false,"runner_registration_performed":false}\n' \
  "${PROJECT}" "${source_remote}" "${source_ref}" "${expected_fingerprint}" "${local_alias}" \
  "${EXPECTED_ARCHITECTURE}" "${created_alias}"
