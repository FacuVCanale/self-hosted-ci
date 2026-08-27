#!/usr/bin/env bash
set -euo pipefail

readonly GARM_CONFIG=/etc/self-hosted-ci/garm/config.toml
readonly PROVIDER_CONFIG=/etc/self-hosted-ci/garm/garm-provider-incus.toml
readonly HEALTH_STATE=/etc/self-hosted-ci/garm/health-state.json
readonly BROKER_CONFIG=/etc/self-hosted-ci/garm/allocation-broker.json
readonly BROKER_PUBLIC_KEY=/etc/self-hosted-ci/garm/allocation-authority-public-key.pem
readonly ADMIN_USERNAME=/etc/self-hosted-ci/garm/admin-username
readonly ADMIN_PASSWORD=/etc/self-hosted-ci/garm/admin-password
readonly JWT_SECRET=/etc/self-hosted-ci/garm/jwt-secret
readonly SESSION_HELPER=/usr/local/lib/self-hosted-ci/garm-cli-session.py
readonly RUNTIME_CLI_HOME=/run/self-hosted-ci/garm-cli
readonly TRANSIENT_UNIT=self-hosted-ci-garm-configure.service
readonly CALLBACK_URL=http://10.254.0.1:8080/api/v1/callbacks
readonly METADATA_URL=http://10.254.0.1:8080/api/v1/metadata

die() { printf 'garm-jit configuration blocked: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'usage: %s [--plan] | --apply --config-template FILE --jwt-secret-file FILE --database-passphrase-file FILE --garm-admin-username-file FILE --garm-admin-password-file FILE --garm-cli-home /run/self-hosted-ci/garm-cli --authority-kind personal-repository|organization-runner-group --repository-id ID --entity-id UUID --entity-name NAME --image-alias ALIAS --image-fingerprint SHA256 --allocation-authority-public-key FILE --live-job-verifier /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py [--runner-group NAME] --acknowledge-root-secret-installation --acknowledge-garm-database-mutation --acknowledge-external-github-configuration\n' "$0" >&2
  exit 2
}

mode=plan; template=""; jwt_file=""; passphrase_file=""; admin_username_file=""; admin_password_file=""; cli_home=""; authority_kind=""
repository_id=""; entity_id=""; entity_name=""; runner_group=""; image_alias=""; image_fingerprint=""; allocation_public_key=""; live_job_verifier=""
ack_secrets=false; ack_database=false; ack_github=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) mode=plan; shift ;;
    --apply) mode=apply; shift ;;
    --config-template) [[ $# -ge 2 ]] || usage; template="$2"; shift 2 ;;
    --jwt-secret-file) [[ $# -ge 2 ]] || usage; jwt_file="$2"; shift 2 ;;
    --database-passphrase-file) [[ $# -ge 2 ]] || usage; passphrase_file="$2"; shift 2 ;;
    --garm-admin-username-file) [[ $# -ge 2 ]] || usage; admin_username_file="$2"; shift 2 ;;
    --garm-admin-password-file) [[ $# -ge 2 ]] || usage; admin_password_file="$2"; shift 2 ;;
    --garm-cli-home) [[ $# -ge 2 ]] || usage; cli_home="$2"; shift 2 ;;
    --authority-kind) [[ $# -ge 2 ]] || usage; authority_kind="$2"; shift 2 ;;
    --repository-id) [[ $# -ge 2 ]] || usage; repository_id="$2"; shift 2 ;;
    --entity-id) [[ $# -ge 2 ]] || usage; entity_id="$2"; shift 2 ;;
    --entity-name) [[ $# -ge 2 ]] || usage; entity_name="$2"; shift 2 ;;
    --runner-group) [[ $# -ge 2 ]] || usage; runner_group="$2"; shift 2 ;;
    --image-alias) [[ $# -ge 2 ]] || usage; image_alias="$2"; shift 2 ;;
    --image-fingerprint) [[ $# -ge 2 ]] || usage; image_fingerprint="$2"; shift 2 ;;
    --allocation-authority-public-key) [[ $# -ge 2 ]] || usage; allocation_public_key="$2"; shift 2 ;;
    --live-job-verifier) [[ $# -ge 2 ]] || usage; live_job_verifier="$2"; shift 2 ;;
    --acknowledge-root-secret-installation) ack_secrets=true; shift ;;
    --acknowledge-garm-database-mutation) ack_database=true; shift ;;
    --acknowledge-external-github-configuration) ack_github=true; shift ;;
    *) usage ;;
  esac
done

if [[ "${mode}" == plan ]]; then
  printf '{"mode":"plan","host_changes":false,"external_calls":"not_performed","garm_enabled":false,"runner_registration":"not_performed","sequence":["render manager/provider config and install login credentials from root-only files","create a renewable root-only garm-cli session under /run","verify exact local Incus image fingerprint and selected target authority","temporarily start GARM without enabling its service","set runner-reachable callback and metadata URLs","require zero scale sets and zero runtime instances","install root-owned broker target/public-key/live-verifier contract","derive atomic manager health state","stop transient GARM"]}\n'
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || die '--apply must run as root'
[[ "${WSL_DISTRO_NAME:-}" == Ubuntu-24.04-CI ]] || die 'WSL_DISTRO_NAME must be Ubuntu-24.04-CI'
grep -qi wsl2 /proc/sys/kernel/osrelease || die 'host must be WSL2'
[[ "${ack_secrets}" == true && "${ack_database}" == true && "${ack_github}" == true ]] || die '--apply requires all three explicit acknowledgements'
[[ "${authority_kind}" == personal-repository || "${authority_kind}" == organization-runner-group ]] || die 'invalid authority kind'
[[ "${entity_id}" =~ ^[0-9a-fA-F-]{36}$ ]] || die 'entity ID must be an exact UUID'
[[ "${repository_id}" =~ ^[1-9][0-9]*$ ]] || die 'repository ID must be a canonical positive integer'
[[ "${entity_name}" =~ ^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$ ]] || die 'entity name is invalid'
[[ "${image_alias}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{2,127}$ && "${image_alias}" != *:* ]] || die 'image must be a local immutable alias without a remote prefix'
[[ "${image_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || die 'image fingerprint must be lowercase SHA-256'
[[ -f "${allocation_public_key}" && ! -L "${allocation_public_key}" ]] || die 'allocation authority public key must be a regular file'
[[ "${live_job_verifier}" == /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py ]] || die 'live workflow-job verifier path is not exact'
[[ -f "${live_job_verifier}" && ! -L "${live_job_verifier}" && -x "${live_job_verifier}" ]] || die 'live workflow-job verifier must be an executable regular file'
[[ "$(stat -c '%u:%h' "${live_job_verifier}")" == 0:1 ]] || die 'live workflow-job verifier must be root-owned with one link'
verifier_mode="$(stat -c '%a' "${live_job_verifier}")"
(( (8#${verifier_mode} & 8#022) == 0 )) || die 'live workflow-job verifier must not be writable by group or other'
if [[ "${authority_kind}" == personal-repository ]]; then
  [[ -z "${runner_group}" && "${entity_name}" == */* ]] || die 'personal repository authority requires owner/repo and forbids a runner group'
  entity_flag=--repo
else
  [[ "${entity_name}" != */* && "${runner_group}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$ && "${runner_group}" != *'*'* ]] || die 'organization authority requires an exact organization and runner group'
  entity_flag=--org
fi

require_root_secret() {
  local path="$1" mode_value
  [[ -f "${path}" && ! -L "${path}" ]] || die "${path} must be a regular non-symlink file"
  [[ "$(stat -c '%u:%h' "${path}")" == 0:1 ]] || die "${path} must be root-owned with one link"
  mode_value="$(stat -c '%a' "${path}")"
  (( (8#${mode_value} & 8#077) == 0 )) || die "${path} must not be accessible by group or other"
}
require_root_secret "${jwt_file}"; require_root_secret "${passphrase_file}"
require_root_secret "${admin_username_file}"; require_root_secret "${admin_password_file}"
[[ -f "${template}" && ! -L "${template}" ]] || die 'config template must be a regular file'
[[ "${cli_home}" == "${RUNTIME_CLI_HOME}" ]] || die 'garm-cli home must be exactly /run/self-hosted-ci/garm-cli'
[[ -x "${SESSION_HELPER}" && ! -L "${SESSION_HELPER}" ]] || die 'GARM CLI session helper is absent or unsafe'
[[ -f "${PROVIDER_CONFIG}" && ! -L "${PROVIDER_CONFIG}" ]] || die 'Incus provider config is absent'
[[ "$(stat -c '%U:%G:%a' "${PROVIDER_CONFIG}")" == root:garm-manager:640 ]] || die 'Incus provider config metadata drifted'
grep -Fqx '[image_remotes.images]' "${PROVIDER_CONFIG}" || die 'provider v0.1.5 requires an image remote map'
grep -Fqx 'skip_verify = false' "${PROVIDER_CONFIG}" || die 'provider image remote TLS verification is not strict'
! grep -Eq 'unix_socket|skip_verify = true|project_name = "default"' "${PROVIDER_CONFIG}" || die 'provider config contains a privilege or TLS bypass'
command -v python3 >/dev/null; command -v incus >/dev/null; command -v systemd-run >/dev/null
[[ -x /usr/local/bin/garm && -x /usr/local/bin/garm-cli && -x /usr/local/libexec/garm/garm-provider-incus ]] || die 'pinned GARM binaries are incomplete'
id garm-manager >/dev/null 2>&1 || die 'garm-manager is absent'
systemctl is-enabled --quiet self-hosted-ci-garm.service && die 'persistent GARM service must remain disabled during configuration'
systemctl is-active --quiet self-hosted-ci-garm.service && die 'persistent GARM service must be inactive during configuration'
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED ]] || die 'activation sentinel must be absent during configuration'

install -d -o root -g garm-manager -m 0750 /etc/self-hosted-ci/garm
install -d -o garm-manager -g garm-manager -m 0700 /var/lib/self-hosted-ci/garm
[[ ! -e "${GARM_CONFIG}" || ( -f "${GARM_CONFIG}" && ! -L "${GARM_CONFIG}" ) ]] || die 'existing GARM config is not a regular file'
[[ ! -e "${HEALTH_STATE}" || ( -f "${HEALTH_STATE}" && ! -L "${HEALTH_STATE}" ) ]] || die 'existing health state is not a regular file'
transaction_dir="$(mktemp -d /etc/self-hosted-ci/garm/.configure-rollback.XXXXXX)"
chmod 0700 "${transaction_dir}"
had_config=false; had_health=false; had_broker_config=false; had_broker_key=false; had_admin_username=false; had_admin_password=false; had_jwt_secret=false
if [[ -e "${GARM_CONFIG}" ]]; then
  cp -a "${GARM_CONFIG}" "${transaction_dir}/config.toml"; had_config=true
fi
if [[ -e "${HEALTH_STATE}" ]]; then
  cp -a "${HEALTH_STATE}" "${transaction_dir}/health-state.json"; had_health=true
fi
if [[ -e "${BROKER_CONFIG}" ]]; then cp -a "${BROKER_CONFIG}" "${transaction_dir}/allocation-broker.json"; had_broker_config=true; fi
if [[ -e "${BROKER_PUBLIC_KEY}" ]]; then cp -a "${BROKER_PUBLIC_KEY}" "${transaction_dir}/allocation-authority-public-key.pem"; had_broker_key=true; fi
for secret_name in admin-username admin-password jwt-secret; do
  secret_path="/etc/self-hosted-ci/garm/${secret_name}"
  if [[ -e "${secret_path}" ]]; then
    cp -a "${secret_path}" "${transaction_dir}/${secret_name}"
    case "${secret_name}" in
      admin-username) had_admin_username=true ;;
      admin-password) had_admin_password=true ;;
      jwt-secret) had_jwt_secret=true ;;
    esac
  fi
done
candidate="$(mktemp /etc/self-hosted-ci/garm/.config.toml.XXXXXX)"
transaction_succeeded=false
cleanup() {
  rm -f "${candidate:-}"
  systemctl stop "${TRANSIENT_UNIT}" >/dev/null 2>&1 || true
  systemctl reset-failed "${TRANSIENT_UNIT}" >/dev/null 2>&1 || true
  if [[ "${transaction_succeeded}" != true ]]; then
    if [[ "${had_config}" == true ]]; then cp -a "${transaction_dir}/config.toml" "${GARM_CONFIG}"; else rm -f "${GARM_CONFIG}"; fi
    if [[ "${had_health}" == true ]]; then cp -a "${transaction_dir}/health-state.json" "${HEALTH_STATE}"; else rm -f "${HEALTH_STATE}"; fi
    if [[ "${had_broker_config}" == true ]]; then cp -a "${transaction_dir}/allocation-broker.json" "${BROKER_CONFIG}"; else rm -f "${BROKER_CONFIG}"; fi
    if [[ "${had_broker_key}" == true ]]; then cp -a "${transaction_dir}/allocation-authority-public-key.pem" "${BROKER_PUBLIC_KEY}"; else rm -f "${BROKER_PUBLIC_KEY}"; fi
    if [[ "${had_admin_username}" == true ]]; then cp -a "${transaction_dir}/admin-username" "${ADMIN_USERNAME}"; else rm -f "${ADMIN_USERNAME}"; fi
    if [[ "${had_admin_password}" == true ]]; then cp -a "${transaction_dir}/admin-password" "${ADMIN_PASSWORD}"; else rm -f "${ADMIN_PASSWORD}"; fi
    if [[ "${had_jwt_secret}" == true ]]; then cp -a "${transaction_dir}/jwt-secret" "${JWT_SECRET}"; else rm -f "${JWT_SECRET}"; fi
  fi
  rm -rf --one-file-system "${transaction_dir}"
}
trap cleanup EXIT
python3 - "${template}" "${jwt_file}" "${passphrase_file}" "${candidate}" <<'PY'
import os, pathlib, sys, tomllib
template, jwt_path, pass_path, output = map(pathlib.Path, sys.argv[1:])
def secret(path, *, exact_32=False):
    value = path.read_text(encoding="utf-8").rstrip("\r\n")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~!@#$%^&*+=?-")
    if (len(value) != 32 if exact_32 else len(value) < 32) or not set(value) <= allowed:
        raise SystemExit("secret must contain at least 32 TOML-safe characters")
    return value
text = template.read_text(encoding="utf-8")
if text.count('REPLACE_ME_WITH_32_CHARS________') != 2:
    raise SystemExit("template placeholder count drifted")
text = text.replace('REPLACE_ME_WITH_32_CHARS________', secret(jwt_path), 1)
text = text.replace('REPLACE_ME_WITH_32_CHARS________', secret(pass_path, exact_32=True), 1)
value = tomllib.loads(text)
if value["apiserver"] != {"bind":"127.0.0.1","port":9997,"use_tls":False,"cors_origins":[],"webui":{"enable":False}}:
    raise SystemExit("API boundary drifted")
if value["database"]["backend"] != "sqlite3" or value["database"]["sqlite3"]["db_file"] != "/var/lib/self-hosted-ci/garm/garm.db":
    raise SystemExit("database boundary drifted")
providers = value.get("provider", [])
if len(providers) != 1 or providers[0].get("name") != "incus_ci_jit" or providers[0].get("disable_jit_config") is not False:
    raise SystemExit("provider boundary drifted")
fd = os.open(output, os.O_WRONLY | os.O_TRUNC)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write(text); handle.flush(); os.fsync(handle.fileno())
PY

chown root:garm-manager "${candidate}"; chmod 0640 "${candidate}"
mv -f "${candidate}" "${GARM_CONFIG}"; candidate=""
install -o root -g root -m 0600 "${admin_username_file}" "${ADMIN_USERNAME}"
install -o root -g root -m 0600 "${admin_password_file}" "${ADMIN_PASSWORD}"
install -o root -g root -m 0600 "${jwt_file}" "${JWT_SECRET}"
python3 - "${GARM_CONFIG}" "${ADMIN_USERNAME}" <<'PY'
import pathlib, re, sys
garm, username = map(pathlib.Path, sys.argv[1:])
if "REPLACE_ME_" in garm.read_text(encoding="utf-8"): raise SystemExit("unrendered config")
value=username.read_text(encoding="utf-8").rstrip("\r\n")
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value): raise SystemExit("GARM admin username is invalid")
PY

image_json="$(incus image info "${image_alias}" --project ci-jit --format json)" || die 'local runner image alias is absent'
python3 - "${image_alias}" "${image_fingerprint}" "${image_json}" <<'PY'
import json, sys
alias, fingerprint, raw = sys.argv[1:]
value = json.loads(raw)
if value.get("fingerprint") != fingerprint: raise SystemExit("image fingerprint drifted")
if value.get("type") != "container": raise SystemExit("runner image is not a container image")
if alias not in [item.get("name") for item in value.get("aliases", [])]: raise SystemExit("exact local image alias is absent")
PY

systemd-run --quiet --collect --unit "${TRANSIENT_UNIT%.service}" --uid garm-manager --gid garm-manager \
  --property=UMask=0077 --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
  --property=ProtectHome=yes --property=ProtectSystem=strict --property=ReadWritePaths=/var/lib/self-hosted-ci/garm \
  /usr/local/bin/garm --config "${GARM_CONFIG}"
for _ in $(seq 1 40); do
  if "${SESSION_HELPER}" run -- --format json controller show >/dev/null 2>&1; then break; fi
  sleep 0.25
done
"${SESSION_HELPER}" run -- --format json controller show >/dev/null || die 'renewable garm-cli live controller validation failed'
garm_cli() { "${SESSION_HELPER}" run -- --format json "$@"; }
providers="$(garm_cli provider list)" || die 'provider inventory failed'
python3 - "${providers}" <<'PY'
import json, sys
v=json.loads(sys.argv[1])
if len(v)!=1 or v[0].get("name")!="incus_ci_jit" or v[0].get("type")!="external": raise SystemExit("provider inventory drifted")
PY
garm_cli controller update --callback-url "${CALLBACK_URL}" --metadata-url "${METADATA_URL}" >/dev/null
controller="$(garm_cli controller show)"
python3 - "${controller}" "${CALLBACK_URL}" "${METADATA_URL}" <<'PY'
import json, sys
v=json.loads(sys.argv[1])
if v.get("callback_url") != sys.argv[2] or v.get("metadata_url") != sys.argv[3]: raise SystemExit("runner-reachable controller URLs drifted")
PY

inventory="$(garm_cli scaleset list "${entity_flag}" "${entity_id}")"
instances="$(incus list --project ci-jit --format json)"
python3 - "${inventory}" "${instances}" <<'PY'
import json,sys
if json.loads(sys.argv[1]) != []: raise SystemExit("configuration requires zero scale sets")
if json.loads(sys.argv[2]) != []: raise SystemExit("configuration requires zero Incus instances")
PY
install -o root -g root -m 0640 "${allocation_public_key}" "${BROKER_PUBLIC_KEY}"
python3 - "${HEALTH_STATE}" "${BROKER_CONFIG}" "${BROKER_PUBLIC_KEY}" "${cli_home}" "${repository_id}" "${authority_kind}" "${entity_id}" "${entity_name}" "${runner_group}" "${image_alias}" "${image_fingerprint}" "${live_job_verifier}" <<'PY'
import hashlib, json, os, pathlib, sys, tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
health_path, broker_path, key_path = map(pathlib.Path, sys.argv[1:4])
cli_home, repository_id, authority, entity_id, entity_name, runner_group, image, fingerprint, verifier = sys.argv[4:]
key=serialization.load_pem_public_key(key_path.read_bytes())
if not isinstance(key,ed25519.Ed25519PublicKey): raise SystemExit("allocation authority key must be Ed25519")
target={"authority_kind":authority,"entity_flag":"--repo" if authority=="personal-repository" else "--org","entity_id":entity_id,"entity_name":entity_name,"runner_group":runner_group or None}
der=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
broker={"allocation_signer_fingerprint":hashlib.sha256(der).hexdigest(),"garm_cli_home":cli_home,"provider_name":"incus_ci_jit","image_alias":image,"image_fingerprint":fingerprint,"live_job_verifier":verifier,"targets":{repository_id:target}}
state={"schema_version":3,"garm_cli_home":cli_home,"manager_configured":True,"provider_configured":True,"image_configured":True,"broker_configured":True,"zero_scale_sets":True,"image":{"alias":image,"fingerprint":fingerprint},"targets":{repository_id:target}}
for path,value,mode in ((broker_path,broker,0o640),(health_path,state,0o640)):
    path.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=f".{path.name}.",dir=path.parent)
    try:
        os.fchmod(fd,mode); os.fchown(fd,0,0)
        with os.fdopen(fd,"w",encoding="utf-8") as out:
            json.dump(value,out,sort_keys=True,separators=(",",":")); out.write("\n"); out.flush(); os.fsync(out.fileno())
        os.replace(tmp,path); dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
    except BaseException:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
        raise
PY
systemctl stop "${TRANSIENT_UNIT}" >/dev/null
systemctl is-active --quiet self-hosted-ci-garm.service && die 'persistent GARM became active'
systemctl is-enabled --quiet self-hosted-ci-garm.service && die 'persistent GARM became enabled'
transaction_succeeded=true
printf '{"status":"configured","broker_configured":true,"zero_scale_sets":true,"runner_registration_performed":false,"garm_enabled":false,"health_state_derived_from_live_api":true}\n'
