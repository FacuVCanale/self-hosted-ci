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
readonly GARM_DATABASE=/var/lib/self-hosted-ci/garm/garm.db
readonly GARM_BLOB_DATABASE=/var/lib/self-hosted-ci/garm/blob-garm.db
readonly LIVE_VERIFIER_CONFIG=/etc/self-hosted-ci/github-live-job-verifier.json
readonly SESSION_HELPER=/usr/local/lib/self-hosted-ci/garm-cli-session.py
readonly RUNTIME_CLI_HOME=/run/self-hosted-ci/garm-cli
readonly TRANSIENT_UNIT=self-hosted-ci-garm-configure.service
readonly CALLBACK_URL=http://10.254.0.1:8080/api/v1/callbacks
readonly METADATA_URL=http://10.254.0.1:8080/api/v1/metadata

die() { printf 'garm-jit configuration blocked: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'usage: %s [--plan] | --apply --config-template FILE --jwt-secret-file FILE --database-passphrase-file FILE --garm-admin-username-file FILE --garm-admin-password-file FILE --runner-manager-app-config-file FILE --dispatcher-app-config-file FILE --live-job-verifier-app-config-file FILE --garm-cli-home /run/self-hosted-ci/garm-cli --authority-kind personal-repository|organization-runner-group --repository OWNER/REPO --repository-id ID --default-branch BRANCH [--entity-id UUID] --entity-name OWNER/REPO|ORGANIZATION [--runner-group GROUP] --image-alias ALIAS --image-fingerprint SHA256 --allocation-authority-public-key FILE --live-job-verifier /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py --acknowledge-root-secret-installation --acknowledge-garm-database-mutation --acknowledge-external-github-configuration\n' "$0" >&2
  exit 2
}

mode=plan; template=""; jwt_file=""; passphrase_file=""; admin_username_file=""; admin_password_file=""; runner_manager_app_config_file=""; dispatcher_app_config_file=""; live_job_verifier_app_config_file=""; cli_home=""; authority_kind=""
repository=""; repository_id=""; default_branch=""; entity_id=""; entity_name=""; runner_group=""; image_alias=""; image_fingerprint=""; allocation_public_key=""; live_job_verifier=""
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
    --runner-manager-app-config-file) [[ $# -ge 2 ]] || usage; runner_manager_app_config_file="$2"; shift 2 ;;
    --dispatcher-app-config-file) [[ $# -ge 2 ]] || usage; dispatcher_app_config_file="$2"; shift 2 ;;
    --live-job-verifier-app-config-file) [[ $# -ge 2 ]] || usage; live_job_verifier_app_config_file="$2"; shift 2 ;;
    --garm-cli-home) [[ $# -ge 2 ]] || usage; cli_home="$2"; shift 2 ;;
    --authority-kind) [[ $# -ge 2 ]] || usage; authority_kind="$2"; shift 2 ;;
    --repository) [[ $# -ge 2 ]] || usage; repository="$2"; shift 2 ;;
    --repository-id) [[ $# -ge 2 ]] || usage; repository_id="$2"; shift 2 ;;
    --default-branch) [[ $# -ge 2 ]] || usage; default_branch="$2"; shift 2 ;;
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
  printf '{"mode":"plan","host_changes":false,"external_calls":"not_performed","garm_enabled":false,"runner_registration":"not_performed","sequence":["render manager/provider config and install login credentials from root-only files","initialize the controller through loopback without exposing the password","reconcile a repository-bound GitHub App credential and exact repo or organization entity","derive the entity UUID from live GARM state","verify exact local Incus image fingerprint and selected target authority","temporarily start GARM without enabling its service","set runner-reachable callback and metadata URLs","require zero scale sets and zero runtime instances","install root-owned broker target/public-key/live-verifier contract","derive atomic manager health state","stop transient GARM"]}\n'
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || die '--apply must run as root'
[[ "${WSL_DISTRO_NAME:-}" == Ubuntu-24.04-CI ]] || die 'WSL_DISTRO_NAME must be Ubuntu-24.04-CI'
grep -qi wsl2 /proc/sys/kernel/osrelease || die 'host must be WSL2'
[[ "${ack_secrets}" == true && "${ack_database}" == true && "${ack_github}" == true ]] || die '--apply requires all three explicit acknowledgements'
[[ "${authority_kind}" == personal-repository || "${authority_kind}" == organization-runner-group ]] || die 'authority kind must be personal-repository or organization-runner-group'
validate_uuid() {
  python3 - "$1" <<'PY'
import sys, uuid
try:
    value=uuid.UUID(sys.argv[1])
except (ValueError, AttributeError):
    raise SystemExit(1)
if str(value) != sys.argv[1].lower():
    raise SystemExit(1)
PY
}
[[ -z "${entity_id}" ]] || validate_uuid "${entity_id}" || die 'optional expected entity ID must be an exact UUID'
[[ "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'repository must be exact owner/repo'
[[ "${repository_id}" =~ ^[1-9][0-9]*$ ]] || die 'repository ID must be a canonical positive integer'
GITHUB_CREDENTIAL_NAME="self-hosted-ci-runner-manager-${repository_id}"
GITHUB_CREDENTIAL_DESCRIPTION="Self-hosted CI runner manager for repository ${repository_id}"
[[ "${default_branch}" =~ ^[A-Za-z0-9._/-]+$ && "${default_branch}" != /* && "${default_branch}" != */ && "${default_branch}" != *//* ]] || die 'default branch is invalid'
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
  [[ -z "${runner_group}" && "${entity_name}" == */* && "${entity_name}" == "${repository}" ]] || die 'personal repository authority requires the exact owner/repo entity and forbids a runner group'
  entity_flag=--repo
else
  [[ "${entity_name}" != */* && "${repository%%/*}" == "${entity_name}" ]] || die 'organization authority requires the repository owner as its exact organization entity'
  python3 - "${runner_group}" <<'PY' || die 'organization authority requires an exact selected runner group'
import sys
value=sys.argv[1]
if not value or value!=value.strip() or len(value)>100 or "*" in value or "\r" in value or "\n" in value:
    raise SystemExit(1)
PY
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
require_root_secret "${runner_manager_app_config_file}"
require_root_secret "${dispatcher_app_config_file}"
require_root_secret "${live_job_verifier_app_config_file}"
mapfile -t app_values < <(python3 - "${runner_manager_app_config_file}" "${dispatcher_app_config_file}" "${live_job_verifier_app_config_file}" "${repository}" "${repository_id}" "${default_branch}" "${authority_kind}" <<'PY'
import json, pathlib, re, sys
paths=map(pathlib.Path,sys.argv[1:4]); repository=sys.argv[4]; repository_id=sys.argv[5]; default_branch=sys.argv[6]; authority=sys.argv[7]
runner_permissions=(
 {"metadata":"read","actions":"read","administration":"write"}
 if authority=="personal-repository"
 else {"metadata":"read","organization_self_hosted_runners":"write"}
)
expected=(
 ("garm-runner-manager",runner_permissions),
 ("workflow-dispatch",{"metadata":"read","contents":"read","pull_requests":"read","actions":"write","administration":"read"}),
 ("live-job-read",{"metadata":"read","actions":"read"}),
)
values=[]; required={"schema_version","purpose","app_id","app_slug","installation_id","repository","repository_id","repository_selection","permissions","private_key_file"}
for path,(purpose,permissions) in zip(paths,expected,strict=True):
 v=json.loads(path.read_text(encoding="utf-8"))
 role_required=required | ({"default_branch","workflow_id","workflow_path"} if purpose=="workflow-dispatch" else set())
 if set(v)!=role_required or v.get("schema_version")!=1 or v.get("purpose")!=purpose: raise SystemExit(purpose+" App config fields drifted")
 if v.get("permissions")!=permissions: raise SystemExit(purpose+" App permissions drifted")
 if not isinstance(v.get("app_slug"),str) or not re.fullmatch(r"[A-Za-z0-9-]+",v["app_slug"]): raise SystemExit(purpose+" App slug is invalid")
 if v.get("repository")!=repository or str(v.get("repository_id"))!=repository_id or v.get("repository_selection")!="selected": raise SystemExit(purpose+" App repository binding drifted")
 if purpose=="workflow-dispatch" and (v.get("default_branch")!=default_branch or v.get("workflow_id")!="ci-jit-canary-child.yml" or v.get("workflow_path")!=".github/workflows/ci-jit-canary-child.yml"): raise SystemExit("workflow-dispatch App workflow binding drifted")
 if type(v.get("app_id")) is not int or v["app_id"]<1 or type(v.get("installation_id")) is not int or v["installation_id"]<1: raise SystemExit(purpose+" App IDs must be positive integers")
 key=v.get("private_key_file")
 if not isinstance(key,str) or not key.startswith("/etc/self-hosted-ci/secrets/"): raise SystemExit(purpose+" App key path is outside the protected secrets tree")
 values.append(v)
if len({v["app_id"] for v in values})!=3 or len({v["app_slug"] for v in values})!=3 or len({v["installation_id"] for v in values})!=3 or len({v["private_key_file"] for v in values})!=3: raise SystemExit("GitHub App identities and private keys must be pairwise distinct")
runner,dispatcher,verifier=values
for item in (runner["app_id"],runner["installation_id"],runner["private_key_file"],dispatcher["private_key_file"],verifier["app_id"],verifier["installation_id"],verifier["private_key_file"]): print(item)
PY
)
[[ ${#app_values[@]} -eq 7 ]] || die 'GitHub App configs could not be parsed'
github_app_id="${app_values[0]}"; github_installation_id="${app_values[1]}"; github_private_key="${app_values[2]}"
dispatcher_private_key="${app_values[3]}"; live_verifier_app_id="${app_values[4]}"; live_verifier_installation_id="${app_values[5]}"; live_verifier_private_key="${app_values[6]}"
require_root_secret "${github_private_key}"
require_root_secret "${dispatcher_private_key}"
require_root_secret "${live_verifier_private_key}"
python3 - "${github_private_key}" "${dispatcher_private_key}" "${live_verifier_private_key}" <<'PY'
import hashlib, pathlib, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
fingerprints=[]
for name in sys.argv[1:]:
 key=serialization.load_pem_private_key(pathlib.Path(name).read_bytes(),password=None)
 if not isinstance(key,rsa.RSAPrivateKey) or key.key_size<2048: raise SystemExit("GitHub App private keys must be RSA 2048-bit or stronger")
 der=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
 fingerprints.append(hashlib.sha256(der).digest())
if len(set(fingerprints))!=3: raise SystemExit("GitHub App public-key fingerprints must be pairwise distinct")
PY
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

install -d -o root -g garm-manager -m 0751 /etc/self-hosted-ci
install -d -o root -g garm-manager -m 0750 /etc/self-hosted-ci/garm
install -d -o root -g garm-manager -m 0710 /var/lib/self-hosted-ci
install -d -o garm-manager -g garm-manager -m 0700 /var/lib/self-hosted-ci/garm
[[ ! -e "${GARM_CONFIG}" || ( -f "${GARM_CONFIG}" && ! -L "${GARM_CONFIG}" ) ]] || die 'existing GARM config is not a regular file'
[[ ! -e "${HEALTH_STATE}" || ( -f "${HEALTH_STATE}" && ! -L "${HEALTH_STATE}" ) ]] || die 'existing health state is not a regular file'
transaction_dir="$(mktemp -d /etc/self-hosted-ci/garm/.configure-rollback.XXXXXX)"
chmod 0700 "${transaction_dir}"
had_config=false; had_health=false; had_broker_config=false; had_broker_key=false; had_admin_username=false; had_admin_password=false; had_jwt_secret=false; had_database=false; had_blob_database=false; had_live_verifier_config=false
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
if [[ -e "${GARM_DATABASE}" ]]; then cp -a "${GARM_DATABASE}" "${transaction_dir}/garm.db"; had_database=true; fi
if [[ -e "${GARM_BLOB_DATABASE}" ]]; then cp -a "${GARM_BLOB_DATABASE}" "${transaction_dir}/blob-garm.db"; had_blob_database=true; fi
if [[ -e "${LIVE_VERIFIER_CONFIG}" ]]; then cp -a "${LIVE_VERIFIER_CONFIG}" "${transaction_dir}/github-live-job-verifier.json"; had_live_verifier_config=true; fi
candidate="$(mktemp /etc/self-hosted-ci/garm/.config.toml.XXXXXX)"
transaction_succeeded=false
created_entity_id=""; created_entity_kind=""; created_credential_id=""
cleanup() {
  rm -f "${candidate:-}"
  if [[ "${transaction_succeeded}" != true ]]; then
    if [[ -n "${created_entity_id}" ]]; then garm_cli "${created_entity_kind}" delete "${created_entity_id}" --keep-webhook >/dev/null 2>&1 || true; fi
    if [[ -n "${created_credential_id}" ]]; then garm_cli github credentials delete "${created_credential_id}" >/dev/null 2>&1 || true; fi
  fi
  systemctl stop "${TRANSIENT_UNIT}" >/dev/null 2>&1 || true
  systemctl reset-failed "${TRANSIENT_UNIT}" >/dev/null 2>&1 || true
  if [[ "${transaction_succeeded}" != true ]]; then
    rm -f "${GARM_DATABASE}-wal" "${GARM_DATABASE}-shm" "${GARM_BLOB_DATABASE}-wal" "${GARM_BLOB_DATABASE}-shm"
    if [[ "${had_database}" == true ]]; then cp -a "${transaction_dir}/garm.db" "${GARM_DATABASE}"; else rm -f "${GARM_DATABASE}"; fi
    if [[ "${had_blob_database}" == true ]]; then cp -a "${transaction_dir}/blob-garm.db" "${GARM_BLOB_DATABASE}"; else rm -f "${GARM_BLOB_DATABASE}"; fi
    if [[ "${had_config}" == true ]]; then cp -a "${transaction_dir}/config.toml" "${GARM_CONFIG}"; else rm -f "${GARM_CONFIG}"; fi
    if [[ "${had_health}" == true ]]; then cp -a "${transaction_dir}/health-state.json" "${HEALTH_STATE}"; else rm -f "${HEALTH_STATE}"; fi
    if [[ "${had_broker_config}" == true ]]; then cp -a "${transaction_dir}/allocation-broker.json" "${BROKER_CONFIG}"; else rm -f "${BROKER_CONFIG}"; fi
    if [[ "${had_broker_key}" == true ]]; then cp -a "${transaction_dir}/allocation-authority-public-key.pem" "${BROKER_PUBLIC_KEY}"; else rm -f "${BROKER_PUBLIC_KEY}"; fi
    if [[ "${had_admin_username}" == true ]]; then cp -a "${transaction_dir}/admin-username" "${ADMIN_USERNAME}"; else rm -f "${ADMIN_USERNAME}"; fi
    if [[ "${had_admin_password}" == true ]]; then cp -a "${transaction_dir}/admin-password" "${ADMIN_PASSWORD}"; else rm -f "${ADMIN_PASSWORD}"; fi
    if [[ "${had_jwt_secret}" == true ]]; then cp -a "${transaction_dir}/jwt-secret" "${JWT_SECRET}"; else rm -f "${JWT_SECRET}"; fi
    if [[ "${had_live_verifier_config}" == true ]]; then cp -a "${transaction_dir}/github-live-job-verifier.json" "${LIVE_VERIFIER_CONFIG}"; else rm -f "${LIVE_VERIFIER_CONFIG}"; fi
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
python3 - "${LIVE_VERIFIER_CONFIG}" "${live_verifier_app_id}" "${live_verifier_installation_id}" "${live_verifier_private_key}" <<'PY'
import json, os, pathlib, sys, tempfile
path=pathlib.Path(sys.argv[1]); value={"app_id":int(sys.argv[2]),"installation_id":int(sys.argv[3]),"private_key_file":sys.argv[4]}
fd,tmp=tempfile.mkstemp(prefix=".github-live-job-verifier.",dir=path.parent)
try:
 os.fchmod(fd,0o600); os.fchown(fd,0,0)
 with os.fdopen(fd,"w",encoding="utf-8") as out:
  json.dump(value,out,sort_keys=True,separators=(",",":")); out.write("\n"); out.flush(); os.fsync(out.fileno())
 os.replace(tmp,path)
 dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
except BaseException:
 try: os.unlink(tmp)
 except FileNotFoundError: pass
 raise
PY
python3 - "${GARM_CONFIG}" "${ADMIN_USERNAME}" <<'PY'
import pathlib, re, sys
garm, username = map(pathlib.Path, sys.argv[1:])
if "REPLACE_ME_" in garm.read_text(encoding="utf-8"): raise SystemExit("unrendered config")
value=username.read_text(encoding="utf-8").rstrip("\r\n")
if not re.fullmatch(r"[A-Za-z0-9]{1,64}", value): raise SystemExit("GARM admin username is invalid")
PY

image_info="$(incus image info "${image_alias}" --project ci-jit)" || die 'local runner image alias is absent'
python3 - "${image_alias}" "${image_fingerprint}" "${image_info}" <<'PY'
import re, sys
alias, fingerprint, raw = sys.argv[1:]
observed = dict(re.findall(r"(?m)^(Fingerprint|Type):[ \t]*([^\r\n]+)$", raw))
aliases = set(re.findall(r"(?m)^    -[ \t]+([^\r\n]+)$", raw))
if observed.get("Fingerprint") != fingerprint: raise SystemExit("image fingerprint drifted")
if observed.get("Type") != "container": raise SystemExit("runner image is not a container image")
if alias not in aliases: raise SystemExit("exact local image alias is absent")
PY

systemd-run --quiet --collect --unit "${TRANSIENT_UNIT%.service}" --uid garm-manager --gid garm-manager \
  --property=UMask=0077 --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
  --property=ProtectHome=yes --property=ProtectSystem=strict --property=ReadWritePaths=/var/lib/self-hosted-ci/garm \
  /usr/local/bin/garm --config "${GARM_CONFIG}"
for _ in $(seq 1 40); do
  if python3 - <<'PY' >/dev/null 2>&1
import socket
with socket.create_connection(("127.0.0.1",9997),timeout=.25): pass
PY
  then break; fi
  sleep 0.25
done
python3 - "${admin_username_file}" "${admin_password_file}" <<'PY'
import json, pathlib, urllib.error, urllib.request, sys
username=pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").rstrip("\r\n")
password=pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").rstrip("\r\n")
body=json.dumps({"username":username,"password":password,"email":username+"@localhost.invalid","full_name":"Self Hosted CI Administrator"},separators=(",",":")).encode()
request=urllib.request.Request("http://127.0.0.1:9997/api/v1/first-run",data=body,headers={"Content-Type":"application/json"},method="POST")
try:
    with urllib.request.urlopen(request,timeout=5) as response:
        if response.status != 200: raise SystemExit("unexpected first-run response")
except urllib.error.HTTPError as exc:
    if exc.code != 409: raise SystemExit("controller first-run failed") from None
PY
garm_cli() { "${SESSION_HELPER}" run -- --format json "$@"; }
garm_cli controller update --callback-url "${CALLBACK_URL}" --metadata-url "${METADATA_URL}" >/dev/null || die 'controller URL initialization failed'
for _ in $(seq 1 20); do
  if garm_cli controller show >/dev/null 2>&1; then break; fi
  sleep 0.25
done
"${SESSION_HELPER}" run -- --format json controller show >/dev/null || die 'renewable garm-cli live controller validation failed'
providers="$(garm_cli provider list)" || die 'provider inventory failed'
python3 - "${providers}" <<'PY'
import json, sys
v=json.loads(sys.argv[1])
if len(v)!=1 or v[0].get("name")!="incus_ci_jit" or v[0].get("type")!="external": raise SystemExit("provider inventory drifted")
PY
controller="$(garm_cli controller show)"
python3 - "${controller}" "${CALLBACK_URL}" "${METADATA_URL}" <<'PY'
import json, sys
v=json.loads(sys.argv[1])
if v.get("callback_url") != sys.argv[2] or v.get("metadata_url") != sys.argv[3]: raise SystemExit("runner-reachable controller URLs drifted")
PY

credentials="$(garm_cli github credentials list)" || die 'GitHub credential inventory failed'
credential_id="$(python3 - "${credentials}" "${GITHUB_CREDENTIAL_NAME}" <<'PY'
import json,sys
inventory=json.loads(sys.argv[1])
if inventory is None: inventory=[]
if not isinstance(inventory,list): raise SystemExit("GitHub credential inventory is not an array")
matches=[v for v in inventory if v.get("name")==sys.argv[2]]
if len(matches)>1: raise SystemExit("duplicate repository-bound GitHub credentials")
if matches:
    v=matches[0]
    if v.get("auth-type")!="app" or v.get("endpoint",{}).get("name")!="github.com": raise SystemExit("repository-bound GitHub credential type/endpoint drifted")
    print(v["id"])
PY
)"
if [[ -n "${credential_id}" ]]; then
  garm_cli github credentials update "${credential_id}" --name "${GITHUB_CREDENTIAL_NAME}" --description "${GITHUB_CREDENTIAL_DESCRIPTION}" --app-id "${github_app_id}" --app-installation-id "${github_installation_id}" --private-key-path "${github_private_key}" >/dev/null
else
  credential="$(garm_cli github credentials add --name "${GITHUB_CREDENTIAL_NAME}" --description "${GITHUB_CREDENTIAL_DESCRIPTION}" --endpoint github.com --auth-type app --app-id "${github_app_id}" --app-installation-id "${github_installation_id}" --private-key-path "${github_private_key}")"
  created_credential_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "${credential}")"
fi
if [[ "${authority_kind}" == personal-repository ]]; then
  repo_owner="${entity_name%%/*}"; repo_name="${entity_name#*/}"
  entities="$(garm_cli repo list --owner "${repo_owner}" --name "${repo_name}" --endpoint github.com)" || die 'repository inventory failed'
  derived_entity_id="$(python3 - "${entities}" "${repo_owner}" "${repo_name}" <<'PY'
import json,sys
inventory=json.loads(sys.argv[1])
if inventory is None: inventory=[]
if not isinstance(inventory,list): raise SystemExit("repository inventory is not an array")
matches=[v for v in inventory if v.get("owner")==sys.argv[2] and v.get("name")==sys.argv[3]]
if len(matches)>1: raise SystemExit("duplicate repository")
if matches:
    v=matches[0]
    if v.get("agent_mode") is not False: raise SystemExit("repository agent mode must remain disabled")
    print(v["id"])
PY
)"
  if [[ -n "${derived_entity_id}" ]]; then
    garm_cli repo update "${derived_entity_id}" --credentials "${GITHUB_CREDENTIAL_NAME}" --pool-balancer-type roundrobin --agent-mode=false >/dev/null
  else
    entity="$(garm_cli repo add --owner "${repo_owner}" --name "${repo_name}" --forge-type github --credentials "${GITHUB_CREDENTIAL_NAME}" --random-webhook-secret --pool-balancer-type roundrobin --agent-mode=false)"
    derived_entity_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "${entity}")"
    created_entity_id="${derived_entity_id}"; created_entity_kind=repo
  fi
  entity="$(garm_cli repo show "${derived_entity_id}" --endpoint github.com)" || die 'reconciled repository cannot be read'
  python3 - "${entity}" "${repo_owner}" "${repo_name}" "${GITHUB_CREDENTIAL_NAME}" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
credential=v.get("credentials",{})
if v.get("owner")!=sys.argv[2] or v.get("name")!=sys.argv[3] or v.get("agent_mode") is not False: raise SystemExit("repository identity drifted")
if credential.get("name")!=sys.argv[4] or credential.get("auth-type")!="app" or v.get("pool_balancing_type")!="roundrobin": raise SystemExit("repository credential/balancer drifted")
PY
else
  entities="$(garm_cli org list --name "${entity_name}" --endpoint github.com)" || die 'organization inventory failed'
  derived_entity_id="$(python3 - "${entities}" "${entity_name}" <<'PY'
import json,sys
inventory=json.loads(sys.argv[1])
if inventory is None: inventory=[]
if not isinstance(inventory,list): raise SystemExit("organization inventory is not an array")
matches=[v for v in inventory if v.get("name")==sys.argv[2]]
if len(matches)>1: raise SystemExit("duplicate organization")
if matches:
    v=matches[0]
    if v.get("agent_mode") is not False: raise SystemExit("organization agent mode must remain disabled")
    print(v["id"])
PY
)"
  if [[ -n "${derived_entity_id}" ]]; then
    garm_cli org update "${derived_entity_id}" --credentials "${GITHUB_CREDENTIAL_NAME}" --pool-balancer-type roundrobin --agent-mode=false >/dev/null
  else
    entity="$(garm_cli org add --name "${entity_name}" --forge-type github --credentials "${GITHUB_CREDENTIAL_NAME}" --random-webhook-secret --pool-balancer-type roundrobin --agent-mode=false)"
    derived_entity_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "${entity}")"
    created_entity_id="${derived_entity_id}"; created_entity_kind=org
  fi
  entity="$(garm_cli org show "${derived_entity_id}" --endpoint github.com)" || die 'reconciled organization cannot be read'
  python3 - "${entity}" "${entity_name}" "${GITHUB_CREDENTIAL_NAME}" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
credential=v.get("credentials",{})
if v.get("name")!=sys.argv[2] or v.get("agent_mode") is not False: raise SystemExit("organization identity drifted")
if credential.get("name")!=sys.argv[3] or credential.get("auth-type")!="app" or v.get("pool_balancing_type")!="roundrobin": raise SystemExit("organization credential/balancer drifted")
PY
fi
validate_uuid "${derived_entity_id}" || die 'GARM returned an invalid entity UUID'
[[ -z "${entity_id}" || "${entity_id,,}" == "${derived_entity_id,,}" ]] || die 'expected entity ID does not match the reconciled entity'
entity_id="${derived_entity_id}"

inventory="$(garm_cli scaleset list "${entity_flag}" "${entity_id}")"
instances="$(incus list --project ci-jit --format json)"
python3 - "${inventory}" "${instances}" <<'PY'
import json,sys
scale_sets=json.loads(sys.argv[1]); instances=json.loads(sys.argv[2])
if scale_sets is None: scale_sets=[]
if instances is None: instances=[]
if not isinstance(scale_sets,list) or scale_sets: raise SystemExit("configuration requires zero scale sets")
if not isinstance(instances,list) or instances: raise SystemExit("configuration requires zero Incus instances")
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
for path,value,mode in ((broker_path,broker,0o600),(health_path,state,0o600)):
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
