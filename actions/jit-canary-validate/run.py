#!/usr/bin/env python3
"""Dependency-free hosted validation for a signed JIT canary dispatch."""
from __future__ import annotations

import base64, hashlib, json, os, re, subprocess, sys, tempfile, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

class CanaryPackageError(ValueError): pass

SHA=re.compile(r"[0-9a-f]{40}"); HEX=re.compile(r"[0-9a-f]{64}")
LABEL=re.compile(r"wsl-jit-[0-9a-f]{32}")
SCENARIOS=("success","failure","cancel","timeout","force-cancel","reboot")
PACKAGE_FIELDS={"canary_package_version","scenario","runner_label","authorization"}
WORKFLOW=".github/workflows/ci-jit-canary-child.yml"
DOMAIN=b"self-hosted-ci/jit-canary-authorization/v1\x00"
AUTH_FIELDS={"schema_version","purpose","production_activation_authorized","outbound_worker_authorized","required_check_authorized","github_contact_authorized","runner_registration_authorized","repository","repository_id","pull_request","base_sha","head_sha","tested_merge_sha","workflow_ref","dispatch_sha","garm_entity","image_alias","image_fingerprint","allocation_signer_fingerprint","github_app_config_digest","live_job_verifier_digest","network_policy_digest","bootstrap_install_receipt_digest","scenarios","max_allocations","max_concurrency","max_jobs_per_allocation","issued_at","expires_at","nonce"}

def parse(raw: bytes)->Any:
    def pairs(items):
        out={}
        for key,value in items:
            if key in out: raise CanaryPackageError("duplicate JSON key")
            out[key]=value
        return out
    try: return json.loads(raw.decode(),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(CanaryPackageError("non-finite JSON")))
    except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise CanaryPackageError("invalid I-JSON") from exc

def canonical(value:Any)->bytes:
    if isinstance(value,float): raise CanaryPackageError("floats forbidden")
    if isinstance(value,dict): return b"{"+b",".join(json.dumps(k,separators=(",",":")).encode()+b":"+canonical(value[k]) for k in sorted(value))+b"}"
    if isinstance(value,list): return b"["+b",".join(canonical(v) for v in value)+b"]"
    if type(value) is int and abs(value)>2**53-1: raise CanaryPackageError("unsafe integer")
    return json.dumps(value,separators=(",",":"),ensure_ascii=False).encode()

def verify_auth(value:Any,key_pem:bytes,pin:str,now:datetime)->Mapping[str,Any]:
    if not isinstance(value,dict) or set(value)!=AUTH_FIELDS|{"attestation"}: raise CanaryPackageError("authorization fields not exact")
    att=value["attestation"]
    if not isinstance(att,dict) or set(att)!={"attestation_version","signer_fingerprint","signature"} or att.get("attestation_version")!=1 or not HEX.fullmatch(pin) or att.get("signer_fingerprint")!=pin: raise CanaryPackageError("attestation or pin not exact")
    payload={k:v for k,v in value.items() if k!="attestation"}
    safety=(payload.get("schema_version")==1 and payload.get("purpose")=="runner-lifecycle-proof-only" and payload.get("production_activation_authorized") is False and payload.get("outbound_worker_authorized") is False and payload.get("required_check_authorized") is False and payload.get("github_contact_authorized") is True and payload.get("runner_registration_authorized") is True and payload.get("scenarios")==list(SCENARIOS) and payload.get("max_allocations")==6 and payload.get("max_concurrency")==1 and payload.get("max_jobs_per_allocation")==1 and isinstance(payload.get("nonce"),str) and re.fullmatch(r"[0-9a-f]{32}",payload["nonce"]))
    if not safety: raise CanaryPackageError("authorization safety boundary invalid")
    repository=payload.get("repository"); workflow=payload.get("workflow_ref"); entity=payload.get("garm_entity")
    if not isinstance(repository,str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository) or type(payload.get("repository_id")) is not int or payload["repository_id"]<1 or type(payload.get("pull_request")) is not int or payload["pull_request"]<1: raise CanaryPackageError("authorization repository identity invalid")
    if not isinstance(workflow,str) or not workflow.startswith(repository+"/"+WORKFLOW+"@refs/heads/") or not re.fullmatch(r"[A-Za-z0-9._/-]+",workflow.rsplit("@refs/heads/",1)[-1]): raise CanaryPackageError("authorization workflow invalid")
    if not isinstance(entity,dict) or set(entity)!={"authority_kind","entity_id","entity_name","runner_group"} or entity.get("authority_kind") not in {"personal-repository","organization-runner-group"} or not isinstance(entity.get("entity_id"),str) or not re.fullmatch(r"[0-9a-f-]{36}",entity["entity_id"]) or not isinstance(entity.get("entity_name"),str) or not entity["entity_name"]: raise CanaryPackageError("authorization GARM entity invalid")
    if (entity["authority_kind"]=="personal-repository" and entity.get("runner_group") is not None) or (entity["authority_kind"]=="organization-runner-group" and (not isinstance(entity.get("runner_group"),str) or not entity["runner_group"])): raise CanaryPackageError("authorization runner group invalid")
    if not isinstance(payload.get("image_alias"),str) or not payload["image_alias"]: raise CanaryPackageError("authorization image alias invalid")
    if any(not isinstance(payload.get(f),str) or not SHA.fullmatch(payload[f]) for f in ("base_sha","head_sha","tested_merge_sha","dispatch_sha")): raise CanaryPackageError("authorization SHA invalid")
    if any(not isinstance(payload.get(f),str) or not HEX.fullmatch(payload[f]) for f in ("image_fingerprint","allocation_signer_fingerprint","github_app_config_digest","live_job_verifier_digest","network_policy_digest","bootstrap_install_receipt_digest")): raise CanaryPackageError("authorization digest invalid")
    try:
        issued=datetime.fromisoformat(payload["issued_at"].removesuffix("Z")+"+00:00"); expires=datetime.fromisoformat(payload["expires_at"].removesuffix("Z")+"+00:00")
    except (KeyError,TypeError,ValueError) as exc: raise CanaryPackageError("timestamps invalid") from exc
    if not payload["issued_at"].endswith("Z") or not payload["expires_at"].endswith("Z") or expires<=issued or (expires-issued).total_seconds()>7200 or now<issued or now>=expires: raise CanaryPackageError("authorization expired or not yet valid")
    encoded=att.get("signature")
    if not isinstance(encoded,str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}",encoded): raise CanaryPackageError("signature encoding invalid")
    signature=base64.b64decode(encoded+"==",altchars=b"-_",validate=True)
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory); key=root/"key.pem"; der=root/"key.der"; msg=root/"message"; sig=root/"signature"
        key.write_bytes(key_pem); msg.write_bytes(DOMAIN+canonical(payload)); sig.write_bytes(signature)
        converted=subprocess.run(["openssl","pkey","-pubin","-in",str(key),"-outform","DER","-out",str(der)],capture_output=True)
        if converted.returncode or hashlib.sha256(der.read_bytes()).hexdigest()!=pin: raise CanaryPackageError("public key fingerprint mismatch")
        verified=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(key),"-rawin","-in",str(msg),"-sigfile",str(sig)],capture_output=True)
        if verified.returncode: raise CanaryPackageError("authorization signature invalid")
    return payload

def github_api(path:str,token:str)->Mapping[str,Any]:
    request=urllib.request.Request("https://api.github.com"+path,headers={"Accept":"application/vnd.github+json","Authorization":f"Bearer {token}","X-GitHub-Api-Version":"2022-11-28","User-Agent":"self-hosted-ci-jit-canary-validator/1"})
    try:
        with urllib.request.urlopen(request,timeout=20) as response: value=json.load(response)
    except (OSError,urllib.error.HTTPError,json.JSONDecodeError) as exc: raise CanaryPackageError("GitHub live revalidation failed") from exc
    if not isinstance(value,dict): raise CanaryPackageError("GitHub response invalid")
    return value

def validate_package(raw:bytes,*,public_key_pem:bytes,pinned_fingerprint:str,environment:Mapping[str,str],api=github_api,now=lambda:datetime.now(timezone.utc))->dict[str,str]:
    value=parse(raw)
    if not isinstance(value,dict) or set(value)!=PACKAGE_FIELDS or value.get("canary_package_version")!=1: raise CanaryPackageError("package fields/version not exact")
    scenario,label=value.get("scenario"),value.get("runner_label")
    if scenario not in SCENARIOS or not isinstance(label,str) or not LABEL.fullmatch(label): raise CanaryPackageError("scenario/label invalid")
    auth=verify_auth(value.get("authorization"),public_key_pem,pinned_fingerprint,now())
    repo,rid,sha,wref,token=(environment.get(k,"") for k in ("GITHUB_REPOSITORY","GITHUB_REPOSITORY_ID","GITHUB_SHA","GITHUB_WORKFLOW_REF","GITHUB_TOKEN"))
    if auth.get("repository")!=repo or str(auth.get("repository_id"))!=rid or auth.get("dispatch_sha")!=sha or auth.get("workflow_ref")!=wref or not SHA.fullmatch(sha) or not token: raise CanaryPackageError("dispatch identity crossed signed authorization")
    live_repo=api(f"/repos/{repo}",token); pull=api(f"/repos/{repo}/pulls/{auth['pull_request']}",token); workflow=api(f"/repos/{repo}/actions/workflows/{WORKFLOW}",token)
    if live_repo.get("id")!=auth["repository_id"] or live_repo.get("full_name")!=repo or pull.get("number")!=auth["pull_request"] or pull.get("state")!="open" or not isinstance(pull.get("base"),dict) or not isinstance(pull.get("head"),dict) or pull["base"].get("sha")!=auth["base_sha"] or pull["head"].get("sha")!=auth["head_sha"] or pull.get("merge_commit_sha")!=auth["tested_merge_sha"] or workflow.get("path")!=WORKFLOW or workflow.get("state")!="active": raise CanaryPackageError("live repository PR merge or workflow drifted")
    return {"scenario":scenario,"repository":repo,"pr_number":str(auth["pull_request"]),"base_sha":auth["base_sha"],"head_sha":auth["head_sha"],"tested_merge_sha":auth["tested_merge_sha"],"runner_label":label}

def main(environment:Mapping[str,str]|None=None)->int:
    env=os.environ if environment is None else environment
    try:
        outputs=validate_package(env.get("JIT_CANARY_PACKAGE","").encode(),public_key_pem=base64.b64decode(env.get("JIT_CANARY_REVIEWER_PUBLIC_KEY_B64",""),validate=True),pinned_fingerprint=env.get("JIT_CANARY_REVIEWER_FINGERPRINT",""),environment=env)
        with Path(env["GITHUB_OUTPUT"]).open("a",encoding="utf-8",newline="\n") as stream:
            for key in ("scenario","repository","pr_number","base_sha","head_sha","tested_merge_sha","runner_label"): stream.write(f"{key}={outputs[key]}\n")
    except (OSError,KeyError,TypeError,ValueError) as exc:
        print(f"JIT canary package rejected: {exc}",file=sys.stderr); return 2
    return 0

if __name__=="__main__": raise SystemExit(main())
