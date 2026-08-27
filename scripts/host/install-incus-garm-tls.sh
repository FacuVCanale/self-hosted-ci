#!/usr/bin/env bash
set -euo pipefail

readonly project='ci-jit'
readonly trust_name='garm-manager-ci-jit'
readonly endpoint='https://127.0.0.1:8443'
readonly target_root='/etc/self-hosted-ci/garm'
readonly client_cert="${target_root}/incus-client.crt"
readonly client_key="${target_root}/incus-client.key"
readonly server_cert="${target_root}/incus-server.crt"
readonly provider_config="${target_root}/garm-provider-incus.toml"
readonly canary='self-hosted-ci-tls-privileged-canary'

die() { printf 'Incus GARM TLS boundary blocked: %s\n' "$*" >&2; exit 1; }

usage() {
  printf 'usage: %s [--plan] | --apply --provider-template FILE --acknowledge-loopback-tls-boundary\n' "$0" >&2
  exit 2
}

mode='plan'
acknowledged=false
template='/usr/local/share/self-hosted-ci/garm-provider-incus.toml'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) mode='plan'; shift ;;
    --apply) mode='apply'; shift ;;
    --provider-template) [[ $# -ge 2 ]] || usage; template="$2"; shift 2 ;;
    --acknowledge-loopback-tls-boundary) acknowledged=true; shift ;;
    *) usage ;;
  esac
done

if [[ "${mode}" == 'plan' ]]; then
  printf '{"mode":"plan","endpoint":"%s","project":"%s","trust_name":"%s","garm_enabled":false,"runner_registration":"not_performed"}\n' \
    "${endpoint}" "${project}" "${trust_name}"
  exit 0
fi

[[ "${acknowledged}" == true ]] || die '--apply requires --acknowledge-loopback-tls-boundary'
[[ "${EUID}" -eq 0 ]] || die '--apply must run as root'
[[ -f "${template}" && ! -L "${template}" ]] || die 'provider configuration template is missing or unsafe'
for command in incus openssl curl python3 install sha256sum stat getent cmp systemctl sed; do
  command -v "${command}" >/dev/null || die "required command is absent: ${command}"
done
id garm-manager >/dev/null 2>&1 || die 'garm-manager account is absent'
getent group garm-manager >/dev/null || die 'garm-manager group is absent'
if id -nG garm-manager | tr ' ' '\n' | grep -Eq '^(incus|incus-admin|sudo|admin|wheel)$'; then
  die 'garm-manager belongs to a forbidden privileged group'
fi
[[ "$(incus project get "${project}" restricted)" == 'true' ]] || die 'ci-jit project is not restricted'
[[ -f /var/lib/incus/server.crt && ! -L /var/lib/incus/server.crt ]] || die 'Incus server certificate is absent or unsafe'
[[ -z "$(incus list --all-projects --format csv)" ]] || die 'Incus contains an instance before TLS boundary installation'
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED ]] || die 'activation sentinel must be absent during TLS boundary installation'
systemctl is-enabled --quiet self-hosted-ci-garm.service && die 'GARM must be disabled during TLS boundary installation'

install -d -o root -g garm-manager -m 0750 "${target_root}"
tx="$(mktemp -d /run/self-hosted-ci-incus-tls.XXXXXX)"
chmod 0700 "${tx}"
cleanup() {
  incus delete "${canary}" --project "${project}" --force >/dev/null 2>&1 || true
  rm -rf -- "${tx}"
}
trap cleanup EXIT

if [[ -e "${client_cert}" || -e "${client_key}" ]]; then
  [[ -f "${client_cert}" && ! -L "${client_cert}" && -f "${client_key}" && ! -L "${client_key}" ]] || \
    die 'existing client TLS material is incomplete or unsafe'
  openssl x509 -in "${client_cert}" -noout -checkend 2592000 >/dev/null || die 'client certificate expires within 30 days'
  openssl pkey -in "${client_key}" -pubout -out "${tx}/key.pub" >/dev/null
  openssl x509 -in "${client_cert}" -pubkey -noout >"${tx}/cert.pub"
  cmp -s "${tx}/key.pub" "${tx}/cert.pub" || die 'client certificate and key do not match'
  chown root:garm-manager "${client_cert}" "${client_key}"
  chmod 0640 "${client_cert}" "${client_key}"
else
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -sha384 -nodes \
    -days 3650 -subj '/CN=garm-manager-ci-jit' \
    -keyout "${tx}/client.key" -out "${tx}/client.crt" >/dev/null 2>&1
  install -o root -g garm-manager -m 0640 "${tx}/client.key" "${client_key}"
  install -o root -g garm-manager -m 0640 "${tx}/client.crt" "${client_cert}"
fi
install -o root -g garm-manager -m 0640 /var/lib/incus/server.crt "${server_cert}"
install -o root -g garm-manager -m 0640 "${template}" "${provider_config}"
server_name="$(openssl x509 -in "${server_cert}" -noout -subject -nameopt RFC2253 | sed -n 's/^subject=.*CN=\([^,]*\).*$/\1/p')"
[[ "${server_name}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die 'Incus server certificate has no safe DNS common name'
readonly api_endpoint="https://${server_name}:8443"

incus config set core.https_address=127.0.0.1:8443
[[ "$(incus config get core.https_address)" == '127.0.0.1:8443' ]] || die 'Incus HTTPS endpoint drifted from loopback'

client_fingerprint="$(openssl x509 -in "${client_cert}" -outform DER | sha256sum | cut -d' ' -f1)"
mapfile -t trust_fingerprints < <(incus query '/1.0/certificates?recursion=1' | python3 -c '
import json, sys
for item in json.load(sys.stdin):
    if item.get("name") == "garm-manager-ci-jit":
        print(item["fingerprint"])
')
for fingerprint in "${trust_fingerprints[@]}"; do
  [[ "${fingerprint}" == "${client_fingerprint}" ]] || incus config trust remove "${fingerprint}"
done
if ! printf '%s\n' "${trust_fingerprints[@]}" | grep -Fxq "${client_fingerprint}"; then
  incus config trust add-certificate "${client_cert}" --name "${trust_name}" --restricted --projects "${project}"
fi

incus query '/1.0/certificates?recursion=1' | python3 -c '
import json, sys
fp, name, project = sys.argv[1:]
matches = [x for x in json.load(sys.stdin) if x.get("name") == name]
if len(matches) != 1:
    raise SystemExit("restricted trust identity is not unique")
item = matches[0]
if item.get("fingerprint") != fp or item.get("type") != "client" or item.get("restricted") is not True or item.get("projects") != [project]:
    raise SystemExit("restricted trust identity drift")
' "${client_fingerprint}" "${trust_name}" "${project}"

for path in "${client_cert}" "${client_key}" "${server_cert}" "${provider_config}"; do
  [[ "$(stat -c '%U:%G:%a' "${path}")" == 'root:garm-manager:640' ]] || die "unsafe ownership or mode: ${path}"
done
cmp -s "${template}" "${provider_config}" || die 'provider configuration differs from reviewed template'
grep -Fqx 'project_name = "ci-jit"' "${provider_config}" || die 'provider project drift'
grep -Fqx 'url = "https://127.0.0.1:8443"' "${provider_config}" || die 'provider endpoint drift'
grep -Fqx 'include_default_profile = false' "${provider_config}" || die 'provider default-profile drift'
! grep -Eq 'unix_socket|skip_verify[[:space:]]*=[[:space:]]*true|project_name = "default"' "${provider_config}" || die 'provider configuration contains a privilege bypass'

api_request() {
  local method="$1" path="$2" body="${3:-}" output="${tx}/response.json" status
  if [[ -n "${body}" ]]; then
    status="$(curl --silent --show-error --noproxy '*' --cacert "${server_cert}" --resolve "${server_name}:8443:127.0.0.1" --cert "${client_cert}" --key "${client_key}" \
      --request "${method}" --header 'Content-Type: application/json' --data "${body}" \
      --output "${output}" --write-out '%{http_code}' "${api_endpoint}${path}")"
  else
    status="$(curl --silent --show-error --noproxy '*' --cacert "${server_cert}" --resolve "${server_name}:8443:127.0.0.1" --cert "${client_cert}" --key "${client_key}" \
      --request "${method}" --output "${output}" --write-out '%{http_code}' "${api_endpoint}${path}")"
  fi
  printf '%s' "${status}"
}

[[ "$(api_request GET '/1.0/projects/ci-jit')" == '200' ]] || die 'restricted client cannot read ci-jit project'
default_status="$(api_request GET '/1.0/projects/default')"
[[ "${default_status}" == '403' || "${default_status}" == '404' ]] || die 'restricted client can observe the default project'
privileged_body="$(python3 -c 'import json; print(json.dumps({"name": "self-hosted-ci-tls-privileged-canary", "source": {"type": "none"}, "config": {"security.privileged": "true"}, "profiles": ["ci-jit"]}))')"
privileged_status="$(api_request POST '/1.0/instances?project=ci-jit' "${privileged_body}")"
[[ ! "${privileged_status}" =~ ^2 ]] || die 'restricted client created a privileged instance'
grep -Eiq 'privileg|restricted|not allowed' "${tx}/response.json" || die 'privileged canary was rejected for an unrelated reason'
! incus info "${canary}" --project "${project}" >/dev/null 2>&1 || die 'privileged canary left an instance'
[[ -z "$(incus list --all-projects --format csv)" ]] || die 'TLS canaries left an Incus instance'
[[ ! -e /etc/self-hosted-ci/ACTIVATION_APPROVED ]] || die 'TLS installation unexpectedly crossed the activation gate'
systemctl is-enabled --quiet self-hosted-ci-garm.service && die 'TLS installation unexpectedly enabled GARM'

printf '{"status":"installed","endpoint":"%s","project":"%s","trust_name":"%s","trust_restricted":true,"default_project_denied":true,"privileged_instance_denied":true,"tls_files_mode":"0640","tls_files_group":"garm-manager","garm_enabled":false,"runner_registration_performed":false}\n' \
  "${endpoint}" "${project}" "${trust_name}"
