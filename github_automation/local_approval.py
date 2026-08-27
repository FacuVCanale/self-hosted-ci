"""Durable, operator-scoped WorkSource for explicitly approved PR heads."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import subprocess
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from .github import ProtocolPackage
from .gatestore import GateStore
from .runner_jit import validate_allocation_reservation
from .runner_jit import allocation_scale_set_name
from .jit_pilot import JitPilotPackageV1
from .worker_authority import WorkerAppAuthorityV1, WorkerAuthorityError, WorkerGitHubClient


class LocalApprovalError(RuntimeError): pass


@dataclass(frozen=True)
class ResolvedApprovalTarget:
    repository_id: str
    repository: str
    pr_number: int
    head_sha: str
    default_branch: str
    workflow_ref: str
    base_sha: str
    tested_merge_sha: str


class ApprovalResolver(Protocol):
    def resolve(self, repository: str, pr_number: int) -> ResolvedApprovalTarget: ...


class WorkRequestBuilder(Protocol):
    def build(self, target: ResolvedApprovalTarget, *, head_generation: int, request_id: str, nonce: str, now: datetime, ttl: timedelta) -> Mapping[str, Any]: ...


class WorkerAuthorityResolver:
    def __init__(self, client: WorkerGitHubClient): self.client=client
    def resolve(self, repository: str, pr_number: int) -> ResolvedApprovalTarget:
        authority=self.client.authority
        if repository != authority.repository: raise LocalApprovalError("repository is not the exact selected GitHub App repository")
        token=self.client.authenticate(); self.client.repository(token)
        pr=self.client.pull_request(pr_number,token); self.client.workflow(token)
        base=pr.get("base",{}).get("sha"); merge=pr.get("merge_commit_sha")
        if not isinstance(base,str) or not re.fullmatch(r"[0-9a-f]{40}",base) or not isinstance(merge,str) or not re.fullmatch(r"[0-9a-f]{40}",merge):
            raise LocalApprovalError("pull request lacks exact base or tested merge SHA")
        return ResolvedApprovalTarget(
            str(authority.repository_id),authority.repository,pr_number,pr["head"]["sha"],
            authority.default_branch,f"{authority.repository}/{authority.workflow_path}@refs/heads/{authority.default_branch}",
            base,merge,
        )


def _root_file(path:Path, *, executable:bool=False, maximum:int=1_048_576)->None:
    try: info=os.lstat(path)
    except OSError as exc: raise LocalApprovalError(f"required authority file is missing: {path}") from exc
    mode=stat.S_IMODE(info.st_mode)
    expected=0o700 if executable else 0o600
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or mode!=expected or not 1<=info.st_size<=maximum:
        raise LocalApprovalError(f"authority file must be root-owned regular {expected:04o}: {path}")


class ExternalAuthorityBuilder:
    """Invoke the real authority-v1 signer; never manufactures substitute proof."""
    def __init__(self, helper:Path, manifest:Path, signer_key:Path):
        self.helper=helper; self.manifest=manifest; self.signer_key=signer_key
    def build(self,target,*,head_generation,request_id,nonce,now,ttl):
        for path,executable in ((self.helper,True),(self.manifest,False),(self.signer_key,False)):
            _root_file(path,executable=executable)
        bounded={
            "repository_id":target.repository_id,"repository":target.repository,"pr_number":target.pr_number,
            "head_sha":target.head_sha,"head_generation":head_generation,"default_branch":target.default_branch,
            "workflow_ref":target.workflow_ref,"request_id":request_id,"nonce":nonce,
            "issued_at":now.isoformat(timespec="seconds").replace("+00:00","Z"),
            "expires_at":(now+ttl).isoformat(timespec="seconds").replace("+00:00","Z"),
        }
        try:
            result=subprocess.run(
                [str(self.helper),"--manifest",str(self.manifest),"--signer-key",str(self.signer_key)],
                input=json.dumps(bounded,sort_keys=True,separators=(",",":")),text=True,capture_output=True,
                timeout=30,check=False,env={"PATH":"/usr/bin:/bin"},
            )
        except (OSError,subprocess.TimeoutExpired) as exc: raise LocalApprovalError("authority-v1 helper could not run") from exc
        if result.returncode: raise LocalApprovalError("authority-v1 helper rejected the exact approval; provision manifest and signer with the documented install command")
        try: value=json.loads(result.stdout)
        except json.JSONDecodeError as exc: raise LocalApprovalError("authority-v1 helper returned invalid JSON") from exc
        if not isinstance(value,dict): raise LocalApprovalError("authority-v1 helper response is not an object")
        return value


class PilotWorkRequestBuilder:
    """Build a non-gating pilot request from live GitHub facts, without offline authority."""
    def __init__(self,image_fingerprint:str):
        if not re.fullmatch(r"[0-9a-f]{64}",image_fingerprint): raise LocalApprovalError("pilot image fingerprint must be lowercase SHA-256")
        self.image_fingerprint=image_fingerprint
    def build(self,target,*,head_generation,request_id,nonce,now,ttl):
        allocation_id=str(uuid4())
        reservation={
            "allocation_reservation_version":1,"allocation_id":allocation_id,"repository_id":target.repository_id,
            "repository":target.repository,"head_sha":target.head_sha,"workflow_ref":target.workflow_ref,
            "job_name":"local-quality","authority_kind":"personal-repository","runner_group":None,
            "scale_set_name":"","labels":[],"image_fingerprint":self.image_fingerprint,"nonce":nonce,
            "issued_at":LocalApprovalStore._stamp(now),"expires_at":LocalApprovalStore._stamp(now+ttl),
            "max_jobs":1,"ephemeral":True,
        }
        reservation["scale_set_name"]=allocation_scale_set_name(reservation);reservation["labels"]=[reservation["scale_set_name"]]
        package={
            "jit_pilot_package_version":1,"repository":target.repository,"repository_id":int(target.repository_id),
            "pr_number":target.pr_number,"base_branch":target.default_branch,"base_sha":target.base_sha,
            "head_sha":target.head_sha,"tested_merge_sha":target.tested_merge_sha,"workflow_ref":target.workflow_ref,
            "backend":"local","allocation_id":allocation_id,"runner_label":reservation["scale_set_name"],
            "issued_at":reservation["issued_at"],"expires_at":reservation["expires_at"],
        }
        JitPilotPackageV1.from_mapping(package,now=now)
        return {"request_id":request_id,"pilot_package":package,"reservation":reservation}


class LocalApprovalStore:
    def __init__(self,path:Path,gatestore:GateStore,resolver:ApprovalResolver,builder:WorkRequestBuilder,*,clock:Callable[[],datetime]=lambda:datetime.now(timezone.utc),ttl:timedelta=timedelta(minutes=4)):
        if ttl<=timedelta(0) or ttl>timedelta(minutes=5): raise ValueError("approval TTL must be in (0, 5 minutes]")
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700); self.path=path; self.gatestore=gatestore; self.resolver=resolver; self.builder=builder; self.clock=clock; self.ttl=ttl; self.current_request:Mapping[str,Any]|None=None
        with self._connect() as db: db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS approvals(
          request_id TEXT PRIMARY KEY, repository TEXT NOT NULL, pr_number INTEGER NOT NULL,
          head_sha TEXT NOT NULL, head_generation INTEGER NOT NULL, state TEXT NOT NULL,
          request_json TEXT NOT NULL, result_json TEXT, reason TEXT, created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL, claim_until TEXT, active_key TEXT UNIQUE
        );
        """)
        with self._connect() as db:
            columns={row[1] for row in db.execute("PRAGMA table_info(approvals)")}
            if "durable" not in columns:db.execute("ALTER TABLE approvals ADD COLUMN durable INTEGER NOT NULL DEFAULT 0")
    @contextmanager
    def _connect(self):
        db=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        try:
            db.row_factory=sqlite3.Row; db.execute("PRAGMA busy_timeout=10000")
            yield db
        except Exception:
            if db.in_transaction: db.execute("ROLLBACK")
            raise
        finally:
            db.close()
    @staticmethod
    def _stamp(value:datetime)->str:return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    @staticmethod
    def _parse(value:str)->datetime:return datetime.fromisoformat(value.replace("Z","+00:00"))
    def approve(self,repository:str,pr_number:int)->Mapping[str,Any]:
        if not isinstance(repository,str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository): raise LocalApprovalError("repository must be one exact owner/repo")
        if isinstance(pr_number,bool) or not isinstance(pr_number,int) or pr_number<1: raise LocalApprovalError("PR number must be positive")
        now=self.clock(); target=self.resolver.resolve(repository,pr_number)
        head_generation=self.gatestore.observe_head(target.repository_id,pr_number,target.head_sha)
        with self._connect() as db:
            row=db.execute("SELECT request_id,state,expires_at FROM approvals WHERE repository=? AND pr_number=? AND head_sha=?",(repository,pr_number,target.head_sha)).fetchone()
            if row and row["state"] in {"pending","claimed"} and now<self._parse(row["expires_at"]): return {"request_id":row["request_id"],"state":row["state"],"idempotent":True}
        request_id=str(uuid4()); nonce=secrets.token_urlsafe(32)
        if len(nonce)!=43: raise LocalApprovalError("internal nonce generation failed")
        raw=self.builder.build(target,head_generation=head_generation,request_id=request_id,nonce=nonce,now=now,ttl=self.ttl)
        request=self._validate_request(raw,target,head_generation,request_id,nonce,now)
        encoded=json.dumps(request,sort_keys=True,separators=(",",":")); expires=self._stamp(now+self.ttl)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                active_key=f"{repository}:{pr_number}:{target.head_sha}"
                db.execute("INSERT INTO approvals(request_id,repository,pr_number,head_sha,head_generation,state,request_json,result_json,reason,created_at,expires_at,claim_until,active_key,durable) VALUES(?,?,?,?,?,'pending',?,NULL,NULL,?,?,NULL,?,0)",(request_id,repository,pr_number,target.head_sha,head_generation,encoded,self._stamp(now),expires,active_key)); db.execute("COMMIT")
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK"); row=db.execute("SELECT request_id,state FROM approvals WHERE repository=? AND pr_number=? AND head_sha=? AND state IN ('pending','claimed') ORDER BY created_at DESC LIMIT 1",(repository,pr_number,target.head_sha)).fetchone()
                if row:return {"request_id":row["request_id"],"state":row["state"],"idempotent":True}
                raise
        return {"request_id":request_id,"state":"pending","idempotent":False,"head_sha":target.head_sha,"expires_at":expires}
    def _validate_request(self,raw,target,generation,request_id,nonce,now):
        if not isinstance(raw,Mapping) or set(raw) not in ({"request_id","protocol_package","reservation"},{"request_id","pilot_package","reservation"}): raise LocalApprovalError("request builder must return one exact work request")
        if raw["request_id"]!=request_id: raise LocalApprovalError("authority helper crossed request identity")
        reservation=raw["reservation"]
        validate_allocation_reservation(reservation,now=now)
        expected={"repository_id":target.repository_id,"repository":target.repository,"head_sha":target.head_sha,"workflow_ref":target.workflow_ref,"nonce":nonce}
        if any(reservation.get(key)!=value for key,value in expected.items()): raise LocalApprovalError("reservation crossed resolved GitHub authority")
        if "pilot_package" in raw:
            package=JitPilotPackageV1.from_mapping(raw["pilot_package"],now=now)
            if package.repository_id!=int(target.repository_id) or package.repository!=target.repository or package.pr_number!=target.pr_number or package.head_sha!=target.head_sha or package.base_sha!=target.base_sha or package.tested_merge_sha!=target.tested_merge_sha: raise LocalApprovalError("pilot package crossed resolved GitHub target")
            if package.allocation_id!=reservation["allocation_id"] or package.runner_label!=reservation["scale_set_name"]: raise LocalApprovalError("pilot package crossed reservation identity")
            return {"request_id":request_id,"pilot_package":dict(raw["pilot_package"]),"reservation":dict(reservation)}
        package=ProtocolPackage.from_mapping(raw["protocol_package"])
        if package.values["repository_id"]!=int(target.repository_id) or package.values["repository"]!=target.repository or package.values["pr_number"]!=target.pr_number or package.values["head_sha"]!=target.head_sha or package.values["generation"]!=generation: raise LocalApprovalError("protocol package crossed resolved GateStore target")
        if package.values["allocation_id"]!=reservation["allocation_id"] or package.values["allocation_nonce"]!=nonce or package.values["runner_label"]!=reservation["scale_set_name"]: raise LocalApprovalError("protocol package crossed reservation identity")
        return {"request_id":request_id,"protocol_package":dict(package.values),"reservation":dict(reservation)}
    def poll(self)->Mapping[str,Any]|None:
        now=self.clock(); self.current_request=None
        while True:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row=db.execute("SELECT * FROM approvals WHERE state='pending' ORDER BY created_at,request_id LIMIT 1").fetchone()
                if row is None: db.execute("COMMIT"); return None
                if now>=self._parse(row["expires_at"]): db.execute("UPDATE approvals SET state='expired',reason='ttl-expired',active_key=NULL WHERE request_id=?",(row["request_id"],)); db.execute("COMMIT"); continue
                claim_until=min(now+timedelta(minutes=1),self._parse(row["expires_at"]))
                db.execute("UPDATE approvals SET state='claimed',claim_until=? WHERE request_id=?",(self._stamp(claim_until),row["request_id"])); db.execute("COMMIT")
            request=json.loads(row["request_json"])
            try: current=self.resolver.resolve(row["repository"],row["pr_number"])
            except Exception:
                self.fail(row["request_id"],"authority-reresolution-failed"); continue
            if current.head_sha!=row["head_sha"] or self.gatestore.observe_head(current.repository_id,current.pr_number,current.head_sha)!=row["head_generation"]:
                self._set(row["request_id"],"expired","head-or-generation-changed"); continue
            self.current_request=request; return request
    def claim(self,request_id,request,*,lease_seconds):
        if isinstance(lease_seconds,bool) or not isinstance(lease_seconds,int) or not 1<=lease_seconds<=7200:raise LocalApprovalError("work-source lease is invalid")
        encoded=json.dumps(request,sort_keys=True,separators=(",",":"));until=self._stamp(self.clock()+timedelta(seconds=lease_seconds))
        with self._connect() as db:
            changed=db.execute("UPDATE approvals SET durable=1,claim_until=?,reason=NULL WHERE request_id=? AND state='claimed' AND request_json=?",(until,request_id,encoded)).rowcount
        if changed!=1:raise LocalApprovalError("approval claim identity is not durable")
        self.current_request=request
    def resume(self,request_id,request,*,lease_seconds):
        encoded=json.dumps(request,sort_keys=True,separators=(",",":"))
        with self._connect() as db:
            row=db.execute("SELECT request_json,state,durable FROM approvals WHERE request_id=?",(request_id,)).fetchone()
        if row is None or row["request_json"]!=encoded or row["state"]!="claimed" or row["durable"]!=1:
            raise LocalApprovalError("durable approval cannot be resumed")
        self.claim(request_id,request,lease_seconds=lease_seconds)
        return request
    def retry(self,request_id,reason):
        if not isinstance(reason,str) or not reason:raise LocalApprovalError("retry reason is invalid")
        with self._connect() as db:
            changed=db.execute("UPDATE approvals SET reason=?,claim_until=? WHERE request_id=? AND state='claimed' AND durable=1",(reason,self._stamp(self.clock()),request_id)).rowcount
        if changed!=1:raise LocalApprovalError("durable approval cannot be retried")
    def complete(self,request_id,result):
        encoded=json.dumps(result,sort_keys=True,separators=(",",":"))
        with self._connect() as db:
            row=db.execute("SELECT state,result_json FROM approvals WHERE request_id=?",(request_id,)).fetchone()
        if row is not None and row["state"]=="completed":
            if row["result_json"]!=encoded:raise LocalApprovalError("completed approval result identity crossed")
            return
        self._set(request_id,"completed",None,result)
    def fail(self,request_id,reason): self._set(request_id,"failed",reason)
    def revoke(self,repository,pr_number):
        with self._connect() as db:
            changed=db.execute("UPDATE approvals SET state='revoked',reason='operator-revoked',claim_until=NULL,active_key=NULL WHERE repository=? AND pr_number=? AND state IN ('pending','claimed')",(repository,pr_number)).rowcount
        return {"repository":repository,"pr_number":pr_number,"revoked":changed}
    def status(self,repository=None,pr_number=None):
        query="SELECT request_id,repository,pr_number,head_sha,head_generation,state,created_at,expires_at,reason FROM approvals"; args=[]
        if repository is not None: query+=" WHERE repository=?"; args.append(repository)
        if pr_number is not None: query+=(" AND" if args else " WHERE")+" pr_number=?"; args.append(pr_number)
        with self._connect() as db:return [dict(row) for row in db.execute(query+" ORDER BY created_at DESC",args)]
    def recover_claims(self):
        now=self._stamp(self.clock())
        with self._connect() as db:
            db.execute("UPDATE approvals SET state='expired',reason='ttl-expired',claim_until=NULL,active_key=NULL WHERE state='claimed' AND durable=0 AND expires_at<=?",(now,))
            return db.execute("UPDATE approvals SET state='pending',claim_until=NULL WHERE state='claimed' AND durable=0 AND claim_until<=? AND expires_at>?",(now,now)).rowcount
    def _set(self,request_id,state,reason=None,result=None):
        encoded=None if result is None else json.dumps(result,sort_keys=True,separators=(",",":"))
        with self._connect() as db:
            changed=db.execute("UPDATE approvals SET state=?,reason=?,result_json=?,claim_until=NULL,active_key=NULL WHERE request_id=? AND state IN ('pending','claimed')",(state,reason,encoded,request_id)).rowcount
        if changed!=1: raise LocalApprovalError("approval is no longer claimable")
