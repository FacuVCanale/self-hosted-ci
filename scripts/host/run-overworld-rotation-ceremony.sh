#!/bin/bash
# Versioned live-contract and image-rotation ceremony. Usage: ceremony.sh <full-sha>
set -euo pipefail
[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40,64}$ ]] || { echo "usage: $0 <full-sha>" >&2; exit 2; }
SHA=$1; C=~/.local/share/self-hosted-ci/live-contract-ceremony-$SHA; PY=~/code/self-hosted-ci/.venv/bin/python; REPO=~/code/self-hosted-ci; SCR=$(cd "$(dirname "$0")" && pwd)
CONFIG=~/.config/self-hosted-ci/config.json
CONNECTION=$(python3 - "$CONFIG" <<'PY'
import json,pathlib,re,sys
p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text(encoding="utf-8"))
if set(v)!={"distro","public_repository","public_sha","ssh_key","ssh_target"}: raise SystemExit("canonical config fields are not exact")
if not re.fullmatch(r"[A-Za-z0-9_.@-]+",v["ssh_target"]): raise SystemExit("service SSH target is invalid")
if not re.fullmatch(r"[A-Za-z0-9_.-]+",v["distro"]): raise SystemExit("distro is invalid")
print("\t".join((v["ssh_key"],v["ssh_target"],v["distro"])))
PY
)
IFS=$'\t' read -r KEY SVC DISTRO <<<"$CONNECTION"
FP=$(openssl pkey -pubin -in ~/.local/share/self-hosted-ci/reviewer/reviewer-public-key.pem -outform DER | shasum -a 256 | awk '{print $1}')
RECEIPT=${ROTATION_RECEIPT:-$C/build-receipt.json}
PROFILE=$REPO/repository_profiles/overworld/profile.json
MANIFEST=$REPO/images/overworld-pr-v1/manifest.json
IMAGE_OBSERVATION=${ROTATION_IMAGE_OBSERVATION:-$C/image-observation.json}
BASE=~/.local/share/self-hosted-ci/live-contract-ceremony-7c0e603/base/b6c9ff10/contract
SUPERVISOR_SHA=$(git -C "$REPO" show "${SHA}:scripts/host/run-health-supervisor.ps1" | shasum -a 256 | awk '{print $1}')
[[ "$SUPERVISOR_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid supervisor SHA-256" >&2; exit 1; }
log(){ echo "$(date -u +%H:%M:%SZ) [ceremony] $*"; }
mkop() { STEP=$1; INNER=$2; cat > $SCR/op-$STEP.ps1 <<PS
\$ProgressPreference='SilentlyContinue'
\$diag = 'C:\ProgramData\self-hosted-ci\diagnostics'
\$wrapper = Join-Path \$diag 'op-$STEP.ps1'
\$log = Join-Path \$diag 'op-$STEP.log'
\$sid = (Get-LocalUser selfhosted-ci-svc).SID.Value
\$reader = "\$env:COMPUTERNAME\selfhosted-ci-health"
\$body = @"
\`\$ErrorActionPreference = 'Continue'
Start-Transcript -Path '\$log' -Force | Out-Null
try {
  Set-Location 'C:\ProgramData\self-hosted-ci\package\scripts\host'
  $INNER
  Write-Output "OP_EXIT=\`\$LASTEXITCODE"
} catch { Write-Output "OP_ERROR=\`\$(\`\$_.Exception.Message)" }
Write-Output 'OP_DONE'
Stop-Transcript | Out-Null
"@
Set-Content -LiteralPath \$wrapper -Value \$body -Encoding UTF8
if (Test-Path \$log) { Remove-Item \$log -Force }
\$action = New-ScheduledTaskAction -Execute "\$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \`"\$wrapper\`""
\$principal = New-ScheduledTaskPrincipal -UserId "\$env:COMPUTERNAME\facun" -LogonType Interactive -RunLevel Highest
\$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 25) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Unregister-ScheduledTask -TaskName 'SelfHostedCI-Operator-Step' -Confirm:\$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'SelfHostedCI-Operator-Step' -Action \$action -Principal \$principal -Settings \$settings | Out-Null
Start-ScheduledTask -TaskName 'SelfHostedCI-Operator-Step'
"started $STEP"
PS
}
runop() { STEP=$1; MAXI=${2:-30}; ENC=$(iconv -f UTF-8 -t UTF-16LE $SCR/op-$STEP.ps1 | base64 | tr -d '\n'); ssh -o BatchMode=yes -o ConnectTimeout=10 desktop "powershell -NoProfile -EncodedCommand $ENC" 2>&1 | LC_ALL=C tr -d '\0' | LC_ALL=C sed 's/[^[:print:]\t]//g' | grep -E '^started' >/dev/null; DONE=false; for i in $(seq 1 $MAXI); do sleep 10; OUT=$(ssh -o BatchMode=yes -o ConnectTimeout=8 desktop "powershell -NoProfile -Command \"Get-Content C:\ProgramData\self-hosted-ci\diagnostics\op-$STEP.log -ErrorAction SilentlyContinue | Select-Object -Last 20\"" 2>&1 | LC_ALL=C tr -d '\0' | LC_ALL=C sed 's/[^[:print:]\t]//g'); if echo "$OUT" | grep -q 'OP_DONE'; then DONE=true; break; fi; done; echo "$OUT" | grep -E 'OP_|^\{' | cut -c1-1200; $DONE || { echo "OP_TIMEOUT=$STEP"; return 124; }; }
DISTRO_SAFE=$(printf '%q' "$DISTRO")
distro(){ local B; B=$(printf '%s' "$1" | base64 | tr -d '\n'); ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 "$SVC" "wsl -d $DISTRO_SAFE -u root --exec bash -c \"echo $B | base64 -d | bash\"" 2>&1 | LC_ALL=C tr -d '\0'; }
review_sources(){
  "$PY" "$REPO/scripts/host/review-overworld-image-rotation.py" \
    --ceremony-directory "$1" --repository "$REPO" --sha "$2" \
    --receipt "$RECEIPT" --profile "$PROFILE" --manifest "$MANIFEST" \
    --image-observation "$IMAGE_OBSERVATION" \
    --live-previous-fingerprint "$LIVE_PREVIOUS_IMAGE_FINGERPRINT"
}
derive_candidate(){ python3 - "$RECEIPT" "$PROFILE" "$MANIFEST" <<'PY'
import hashlib,json,pathlib,re,sys
receipt_path,profile_path,manifest_path=map(pathlib.Path,sys.argv[1:])
r=json.loads(receipt_path.read_text(encoding="utf-8")); m=json.loads(manifest_path.read_text(encoding="utf-8"))
fields={"status","project","profile","base_fingerprint","manifest_sha256","candidate_alias","fingerprint","builder_privileged","builder_nesting","credentials_persisted","alias_moved"}
profile_digest=hashlib.sha256(profile_path.read_bytes()).hexdigest(); manifest_digest=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
expected=f'{m.get("profile")}-{profile_digest[:12]}'
if set(r)!=fields or r.get("status")!="built" or r.get("project")!="ci-jit" or r.get("profile")!=m.get("profile") or r.get("manifest_sha256")!=manifest_digest or r.get("candidate_alias")!=expected: raise SystemExit(1)
if not all(isinstance(r.get(k),str) and re.fullmatch(r"[0-9a-f]{64}",r[k]) for k in ("base_fingerprint","fingerprint")): raise SystemExit(1)
if any(r.get(k) is not False for k in ("builder_privileged","builder_nesting","credentials_persisted","alias_moved")): raise SystemExit(1)
print("\t".join((r["candidate_alias"],r["fingerprint"])))
PY
}
collect_image_observation(){
  local alias=$1 fingerprint=$2
  distro "set -euo pipefail; work=\$(mktemp -d /var/tmp/rotation-observation.XXXXXX); cleanup(){ rm -rf -- \"\$work\"; }; trap cleanup EXIT; aliases=\$(incus image alias list --project ci-jit --format json); python3 - '$alias' '$fingerprint' \"\$aliases\" <<'PY'
import json,sys
alias,fingerprint,raw=sys.argv[1:]
rows=[row for row in json.loads(raw) if row.get('name')==alias]
if len(rows)!=1 or rows[0].get('target')!=fingerprint: raise SystemExit(1)
PY
incus image export '$fingerprint' \"\$work/image\" --project ci-jit >/dev/null
python3 - \"\$work\" '$alias' '$fingerprint' <<'PY'
import json,pathlib,sys,tarfile
root,alias,fingerprint=pathlib.Path(sys.argv[1]),sys.argv[2],sys.argv[3]
archives=[p for p in root.iterdir() if p.is_file() and not p.is_symlink()]
if len(archives)!=1: raise SystemExit(1)
marker_name='rootfs/etc/self-hosted-ci/repository-profile-image-v1.json'; marker=None
with tarfile.open(archives[0],mode='r|*') as archive:
 for member in archive:
  if member.name==marker_name:
   if marker is not None or not member.isfile(): raise SystemExit(1)
   stream=archive.extractfile(member)
   if stream is None: raise SystemExit(1)
   marker=json.load(stream)
if marker is None: raise SystemExit(1)
print(json.dumps({'alias':alias,'fingerprint':fingerprint,'marker':marker},sort_keys=True,separators=(',',':')))
PY"
}
if [ "${REVIEW_ONLY:-false}" = true ]; then
  LIVE_PREVIOUS_IMAGE_FINGERPRINT=${ROTATION_LIVE_PREVIOUS_IMAGE_FINGERPRINT:?required for isolated review}
  review_sources "${REVIEW_C:-$C}" "${REVIEW_SHA:-$SHA}"
  exit
fi
mkdir -p $C/measured
START=${START:-1}
BACKUP_DIR=$C/backup; BACKUP_FILE=$BACKUP_DIR/run-health-supervisor.before-$SHA.ps1; BACKUP_HASH=$BACKUP_FILE.sha256
if [ "$START" -le 1 ]; then
  mkdir -p "$BACKUP_DIR"
  REMOTE_SUPERVISOR_SHA=$(ssh -o BatchMode=yes desktop 'powershell -NoProfile -NonInteractive -Command "(Get-FileHash -LiteralPath '\''C:\ProgramData\self-hosted-ci\control\run-health-supervisor.ps1'\'' -Algorithm SHA256).Hash.ToLowerInvariant()"' 2>&1 | LC_ALL=C tr -d '\0\r' | tail -n 1)
  [[ "$REMOTE_SUPERVISOR_SHA" =~ ^[0-9a-f]{64}$ ]] || { log "active supervisor backup hash unavailable"; exit 1; }
  scp -q 'desktop:C:/ProgramData/self-hosted-ci/control/run-health-supervisor.ps1' "$BACKUP_FILE"
  [ "$(shasum -a 256 "$BACKUP_FILE" | awk '{print $1}')" = "$REMOTE_SUPERVISOR_SHA" ] || { log "active supervisor backup hash mismatch"; exit 1; }
  printf '%s  %s\n' "$REMOTE_SUPERVISOR_SHA" "$(basename "$BACKUP_FILE")" > "$BACKUP_HASH"
else
  [ -f "$BACKUP_FILE" ] && [ -f "$BACKUP_HASH" ] || { log "verified supervisor backup is missing on resume"; exit 1; }
  (cd "$BACKUP_DIR" && shasum -a 256 -c "$(basename "$BACKUP_HASH")") >/dev/null || { log "supervisor backup verification failed on resume"; exit 1; }
fi
[ "$START" -le 5 ] || U=$(ls $C/unsigned-*.tar | head -1 | sed -E "s/.*unsigned-([0-9a-f]+)\.tar/\1/")
if [ "$START" -le 5 ]; then
log "1 deploy package $SHA"; cd $REPO && git rev-parse --verify -q "$SHA" >/dev/null && $PY scripts/host/deploy-host-package.py --ssh-target desktop --ref $SHA --apply | tail -c 200; echo
ssh -o BatchMode=yes desktop 'powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path C:\ProgramData\self-hosted-ci\package\artifacts\live-contract | Out-Null"' >/dev/null 2>&1
log "2 source tar"; $PY scripts/host/build-wsl-jit-live-contract-tar.py source --contract-dir $BASE --output $C/source.tar >/dev/null; SSHA=$(shasum -a 256 $C/source.tar | awk '{print $1}'); SBYTES=$(stat -f %z $C/source.tar); scp -q $C/source.tar 'desktop:C:/ProgramData/self-hosted-ci/package/artifacts/live-contract/unsigned-live-contract-source.tar'
log "3 uninstall supervisor"; mkop uninstall '& .\uninstall-health-supervisor.ps1 -ExpectedServiceAccountSid '"'"'$sid'"'"' -Apply -AcknowledgeTaskRemoval -AcknowledgeFinalPasswordRotation -AcknowledgeHealthArtifactRemoval'; runop uninstall 20 | grep -q '"status":"uninstalled"' || { log "uninstall failed"; exit 1; }
log "4 collect unsigned"; mkop collect '& .\install-wsl-jit-live-contract.ps1 -ExpectedServiceAccountSid '"'"'$sid'"'"' -UnsignedSourceRelativePath '"'"'artifacts/live-contract/unsigned-live-contract-source.tar'"'"' -CollectUnsigned -Apply -ExpectedInputSha256 '"'"''"$SSHA"''"'"' -ExpectedInputBytes '"$SBYTES"' -AcknowledgeUnsignedCollection -AcknowledgeOneTimePasswordRotation'; OUT=$(runop collect 80); U=$(echo "$OUT" | grep -o '"unsigned_bundle_sha256":"[0-9a-f]*"' | cut -d'"' -f4); [ -n "$U" ] || { log "collect failed: $OUT"; exit 1; }
log "5 fetch+review $U"; scp -q "desktop:C:/ProgramData/self-hosted-ci/unsigned-live-contract/unsigned-live-contract-$U.tar" $C/unsigned-$U.tar; [ "$(shasum -a 256 $C/unsigned-$U.tar | cut -c1-64)" = "$U" ] || { log "hash mismatch"; exit 1; }; rm -rf $C/measured && mkdir -p $C/measured && tar -xf $C/unsigned-$U.tar -C $C/measured
fi
if [ "$START" -gt 5 ]; then
  [ "$(shasum -a 256 "$C/unsigned-$U.tar" | cut -c1-64)" = "$U" ] || { log "resume hash mismatch"; exit 1; }
  rm -rf "$C/measured" && mkdir -p "$C/measured" && tar -xf "$C/unsigned-$U.tar" -C "$C/measured"
fi
LIVE_PREVIOUS_IMAGE_FINGERPRINT=$(distro "set -euo pipefail; /usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py --verify >/dev/null; python3 - <<'PY'
import json,re
v=json.load(open('/etc/self-hosted-ci/outbound-worker.json',encoding='utf-8'))
f=v.get('image_fingerprint')
if not isinstance(f,str) or not re.fullmatch(r'[0-9a-f]{64}',f): raise SystemExit(1)
print(f)
PY")
[[ "$LIVE_PREVIOUS_IMAGE_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || { log "verified live previous fingerprint is invalid"; exit 1; }
CANDIDATE=$(derive_candidate) || { echo "REVIEW_FAIL build receipt does not match versioned profile"; exit 1; }
IFS=$'\t' read -r CANDIDATE_ALIAS CANDIDATE_FINGERPRINT <<<"$CANDIDATE"
collect_image_observation "$CANDIDATE_ALIAS" "$CANDIDATE_FINGERPRINT" >"$IMAGE_OBSERVATION" \
  || { echo "REVIEW_FAIL published image observation failed"; exit 1; }
review_sources "$C" "$SHA"
ROTATION=$(python3 - "$RECEIPT" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding="utf-8"))
print("\t".join((v["candidate_alias"],v["fingerprint"])))
PY
)
IFS=$'\t' read -r IMAGE_ALIAS IMAGE_FINGERPRINT <<<"$ROTATION"
PREVIOUS_IMAGE_FINGERPRINT=$LIVE_PREVIOUS_IMAGE_FINGERPRINT
cd $REPO
log "6 sign+bundle"; $PY scripts/host/sign-wsl-jit-boundary.py --input $C/measured/contract/runner-boundary-measured-v2.json --output $C/runner-boundary-v2.json --reviewer-private-key ~/.local/share/self-hosted-ci/reviewer/reviewer-private-key.pem >/dev/null; $PY scripts/host/build-wsl-jit-live-contract-tar.py signed --unsigned-tar $C/unsigned-$U.tar --signed-boundary $C/runner-boundary-v2.json --reviewer-public-key ~/.local/share/self-hosted-ci/reviewer/reviewer-public-key.pem --reviewer-key-fingerprint $FP --output $C/bundle.tar >/dev/null; BSHA=$(shasum -a 256 $C/bundle.tar | awk '{print $1}'); BBYTES=$(stat -f %z $C/bundle.tar); scp -q $C/bundle.tar 'desktop:C:/ProgramData/self-hosted-ci/package/artifacts/live-contract/live-contract-bundle.tar'
log "7 signed apply $BSHA"; mkop apply '& .\install-wsl-jit-live-contract.ps1 -ExpectedServiceAccountSid '"'"'$sid'"'"' -BundleRelativePath '"'"'artifacts/live-contract/live-contract-bundle.tar'"'"' -ExpectedInputSha256 '"'"''"$BSHA"''"'"' -ExpectedInputBytes '"$BBYTES"' -ExpectedReviewerFingerprint '"'"''"$FP"''"'"' -Apply -AcknowledgeLiveContractMutation -AcknowledgeExternalGitHubMutation -AcknowledgeLocalCiDeactivation -AcknowledgeOneTimePasswordRotation'; runop apply 90 | grep -q '"status":"installed"' || { log "apply failed"; exit 1; }
log "8 verify + configure + activate"; distro "set -euo pipefail; /usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py --evidence /etc/self-hosted-ci/runner-boundary-v2.json --measurement-root /etc/self-hosted-ci/host-evidence --reviewer-public-key /etc/self-hosted-ci/boundary-reviewer-public-key.pem --pinned-fingerprint '$FP'; python3 -c 'import json; v=json.load(open(\"/etc/self-hosted-ci/outbound-worker.json\")); claim=v.get(\"claim_deadline_seconds\",720); approval=v[\"approval_ttl_seconds\"]; assert claim==720 and approval==240 and claim>approval; print(json.dumps({\"approval_ttl_seconds\":approval,\"claim_deadline_seconds_effective\":claim},sort_keys=True,separators=(\",\",\":\")))'; bash /usr/local/lib/self-hosted-ci/configure-garm-jit.sh --apply --config-template /etc/self-hosted-ci/garm/config.toml.example --jwt-secret-file /root/self-hosted-ci-secrets/jwt --database-passphrase-file /root/self-hosted-ci-secrets/db-passphrase --garm-admin-username-file /root/self-hosted-ci-secrets/admin-username --garm-admin-password-file /root/self-hosted-ci-secrets/admin-password --runner-manager-app-config-file /etc/self-hosted-ci/overworld-runner-manager-app.json --dispatcher-app-config-file /etc/self-hosted-ci/overworld-dispatcher-app.json --live-job-verifier-app-config-file /etc/self-hosted-ci/overworld-live-job-verifier-app.json --garm-cli-home /run/self-hosted-ci-broker/garm-cli --authority-kind organization-runner-group --repository alethia-earth/Overworld --repository-id 1172953958 --default-branch master --entity-name alethia-earth --runner-group overworld-ci-jit --image-alias '$IMAGE_ALIAS' --image-fingerprint '$IMAGE_FINGERPRINT' --expected-previous-image-fingerprint '$PREVIOUS_IMAGE_FINGERPRINT' --allocation-authority-public-key /root/self-hosted-ci-secrets/allocation-public-key.pem --live-job-verifier /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py --acknowledge-root-secret-installation --acknowledge-garm-database-mutation --acknowledge-external-github-configuration; python3 /usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py --verify; bash /usr/local/lib/self-hosted-ci/activate-garm-jit.sh --apply --incus-project ci-jit --garm-cli-home /run/self-hosted-ci-broker/garm-cli --acknowledge-external-github-mutation --acknowledge-local-ci-activation; sleep 5; systemctl is-active self-hosted-ci-garm.service self-hosted-ci-allocation-broker.service self-hosted-ci-outbound-worker.service self-hosted-ci-egress-proxy.service self-hosted-ci-network-policy.service self-hosted-ci-boundary-verify.service self-hosted-ci-health-heartbeat.timer | tr '\n' ' '; echo"
log "9 reinstall supervisor"; mkop install "& .\install-health-supervisor.ps1 -ExpectedServiceAccountSid '\$sid' -ReaderAccount '\$reader' -ExpectedSupervisorSha256 '$SUPERVISOR_SHA' -Apply -AcknowledgePersistentPasswordTask -AcknowledgeServiceAccountPasswordRotation -AcknowledgeProtectedHealthAcls"; OUT=$(runop install 40); printf '%s\n' "$OUT" | python3 -c 'import json,sys; expected=sys.argv[1]; values=[]
for line in sys.stdin:
    try: values.append(json.loads(line))
    except json.JSONDecodeError: pass
if not values: raise SystemExit("supervisor install emitted no JSON")
value=values[-1]
if value.get("status")!="installed" or value.get("task_restarted") is not True or value.get("supervisor_process_count")!=1 or value.get("supervisor_script_sha256")!=expected: raise SystemExit("supervisor install proof mismatch")' "$SUPERVISOR_SHA" || { log "supervisor install/restart proof failed: $OUT"; exit 1; }
ssh -o BatchMode=yes desktop 'powershell -NoProfile -Command "Unregister-ScheduledTask -TaskName SelfHostedCI-Operator-Step -Confirm:$false -ErrorAction SilentlyContinue; Get-ChildItem C:\ProgramData\self-hosted-ci\diagnostics\op-*.ps1 -ErrorAction SilentlyContinue | Remove-Item -Force"' >/dev/null 2>&1
log "done: $(self-hosted-ci doctor alethia-earth/Overworld | python3 -c "import sys,json;d=json.load(sys.stdin);print('doctor',d['doctor'])")"
