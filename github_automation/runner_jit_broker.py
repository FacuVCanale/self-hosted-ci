"""Transactional allocation-to-GARM broker for one-job runner scale sets.

The broker owns scale-set lifecycle, but deliberately does not own GARM
authentication or GitHub App setup.  A driver receives an already authenticated
GARM session and must implement the narrow operations below.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import ed25519

from .coordinator import ReservePartialFailure
from .runner_jit import RunnerJitError, SqliteAllocationLedger

RUNNER_INSTALL_TEMPLATE = Path(
    "/usr/local/share/self-hosted-ci/runner-install-offline.sh.tmpl"
)


@dataclass(frozen=True)
class JobStartedContext:
    repository_id: str
    repository: str
    dispatch_sha: str
    tested_sha: str
    workflow_ref: str
    run_id: str
    run_attempt: int
    job_name: str
    runner_name: str
    scale_set_name: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> JobStartedContext:
        required = {
            "repository_id",
            "repository",
            "dispatch_sha",
            "tested_sha",
            "workflow_ref",
            "run_id",
            "run_attempt",
            "job_name",
            "runner_name",
            "scale_set_name",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise RunnerJitError("job-started context requires exact fields")
        if not isinstance(value["run_attempt"], int) or isinstance(
            value["run_attempt"], bool
        ):
            raise RunnerJitError("job-started run_attempt must be an integer")
        if any(
            not isinstance(value[field], str) or not value[field]
            for field in required - {"run_attempt"}
        ):
            raise RunnerJitError("job-started string fields must be non-empty")
        return cls(**value)


class GarmAllocationDriver(Protocol):
    """Narrow, testable GARM surface; no credential acquisition is allowed."""

    def assert_no_persistent_scale_set(self) -> None: ...

    def ensure_disabled_scale_set(self, reservation: Mapping[str, Any]) -> str: ...

    def bind_signed_allocation(
        self,
        scale_set_id: str,
        reservation: Mapping[str, Any],
        envelope: Mapping[str, Any],
    ) -> None: ...

    def find_scale_set(self, scale_set_name: str) -> str | None: ...

    def enable_scale_set(self, scale_set_id: str, scale_set_name: str) -> None: ...

    def assert_runner_claim(
        self,
        scale_set_id: str,
        scale_set_name: str,
        runner_name: str,
        payload: Mapping[str, Any],
    ) -> None: ...

    def disable_scale_set(self, scale_set_id: str, scale_set_name: str) -> None: ...

    def drain_scale_set(self, scale_set_id: str, scale_set_name: str) -> None: ...

    def delete_scale_set(self, scale_set_id: str, scale_set_name: str) -> None: ...

    def assert_scale_set_absent(self, scale_set_name: str) -> None: ...

    def measure_cleanup(
        self, allocation_id: str, scale_set_name: str
    ) -> Mapping[str, Any]: ...

    def assert_runtime_empty(self) -> None: ...


class LiveWorkflowJobVerifier(Protocol):
    def verify(
        self, payload: Mapping[str, Any], context: JobStartedContext
    ) -> None: ...


class AllocationBroker:
    """Fail-closed create→bind→enable→claim→disable→drain→delete lifecycle."""

    def __init__(
        self,
        ledger: SqliteAllocationLedger,
        driver: GarmAllocationDriver,
        public_key: ed25519.Ed25519PublicKey,
        pinned_fingerprint: str,
        live_job_verifier: LiveWorkflowJobVerifier,
    ) -> None:
        self.ledger = ledger
        self.driver = driver
        self.public_key = public_key
        self.pinned_fingerprint = pinned_fingerprint
        self.live_job_verifier = live_job_verifier

    def reserve(
        self, reservation: Mapping[str, Any], *, now: datetime
    ) -> Mapping[str, str]:
        """Create a disabled scale set before dispatch, without job authority."""

        self.driver.assert_no_persistent_scale_set()
        allocation_id = reservation["allocation_id"]
        scale_set_name = reservation["scale_set_name"]
        self.ledger.reserve(reservation, now=now)
        try:
            scale_set_id = self.driver.ensure_disabled_scale_set(reservation)
            self.ledger.bind_scale_set(allocation_id, scale_set_id, scale_set_name)
        except Exception as exc:
            raise ReservePartialFailure(allocation_id) from exc
        return {
            "allocation_id": allocation_id,
            "scale_set_id": scale_set_id,
            "runner_label": scale_set_name,
            "state": "reserved-disabled",
        }

    def finalize(
        self, envelope: Mapping[str, Any], *, now: datetime
    ) -> Mapping[str, str]:
        """Bind observed run/job authority, inject hook binding, then enable."""

        self.ledger.finalize(
            envelope,
            self.public_key,
            pinned_fingerprint=self.pinned_fingerprint,
            now=now,
        )
        payload = envelope["payload"]
        scale_set_name, scale_set_id = self.ledger.scale_set_binding(
            payload["allocation_id"]
        )
        self.driver.bind_signed_allocation(scale_set_id, payload, envelope)
        self.driver.enable_scale_set(scale_set_id, scale_set_name)
        return {
            "allocation_id": payload["allocation_id"],
            "scale_set_id": scale_set_id,
            "runner_label": scale_set_name,
            "state": "enabled-awaiting-claim",
        }

    def job_started(
        self,
        allocation_id: str,
        context: JobStartedContext | Mapping[str, Any],
        *,
        now: datetime,
    ) -> None:
        """Called by ACTIONS_RUNNER_HOOK_JOB_STARTED before any workflow step."""

        if isinstance(context, Mapping):
            context = JobStartedContext.from_mapping(context)
        payload = self.ledger.payload(allocation_id)
        expected = {
            "repository_id": payload["repository_id"],
            "repository": payload["repository"],
            "dispatch_sha": payload["dispatch_sha"],
            "tested_sha": payload["tested_sha"],
            "workflow_ref": payload["workflow_ref"],
            "run_id": payload["run_id"],
            "run_attempt": payload["run_attempt"],
            "job_name": payload["job_name"],
            "scale_set_name": payload["scale_set_name"],
        }
        observed = {field: getattr(context, field) for field in expected}
        if observed != expected:
            raise RunnerJitError(
                "job-started context crossed the signed allocation binding"
            )
        scale_set_name, scale_set_id = self.ledger.scale_set_binding(allocation_id)
        self.driver.assert_runner_claim(
            scale_set_id, scale_set_name, context.runner_name, payload
        )
        self.live_job_verifier.verify(payload, context)
        self.ledger.transition(allocation_id, "claim", now=now)
        # Disabling immediately after the unique runner claims the job prevents
        # a second registration/job while allowing the claimed job to proceed.
        self.driver.disable_scale_set(scale_set_id, scale_set_name)
        self.ledger.transition(allocation_id, "start", now=now)

    def finish(
        self,
        allocation_id: str,
        *,
        outcome: str,
        normal_cancel_attempted: bool = False,
    ) -> Mapping[str, str]:
        record = self.ledger.get(allocation_id)
        if record.state != "running" or record.jobs_started != 1:
            # A workflow can become terminal before the fail-closed job-started
            # hook reaches `running` (for example validation failure or expiry).
            # There is no executed job outcome to attest in that case, but the
            # exact allocation still has to be destroyed and proven absent.
            try:
                binding = self.ledger.payload(allocation_id)
            except RunnerJitError:
                binding = self.ledger.reservation(allocation_id)
            scale_set_name = binding["scale_set_name"]
            self.recover(allocation_id)
            return {
                "allocation_id": allocation_id,
                "runner_label": scale_set_name,
                "state": "cleaned",
            }
        self.ledger.transition(
            allocation_id,
            "finish",
            outcome=outcome,
            normal_cancel_attempted=normal_cancel_attempted,
        )
        scale_set_name, scale_set_id = self.ledger.scale_set_binding(allocation_id)
        self._delete_exact(scale_set_id, scale_set_name)
        self._wait_for_cleanup(allocation_id, scale_set_name)
        self.ledger.transition(allocation_id, "cleanup")
        return {
            "allocation_id": allocation_id,
            "runner_label": scale_set_name,
            "state": "cleaned",
        }

    def prove_clean(self, allocation_id: str, runner_label: str) -> Mapping[str, Any]:
        """Re-measure exact allocation and global runtime emptiness."""

        scale_set_name, _ = self.ledger.scale_set_binding(allocation_id)
        if scale_set_name != runner_label:
            raise RunnerJitError(
                "cleanup proof runner label crossed allocation binding"
            )
        record = self.ledger.get(allocation_id)
        if record.state != "cleaned" or not record.cleanup_complete:
            raise RunnerJitError(
                "cleanup proof requires a cleaned allocation ledger record"
            )
        self.driver.assert_scale_set_absent(scale_set_name)
        self.driver.assert_runtime_empty()
        return {
            "allocation_id": allocation_id,
            "runner_label": runner_label,
            "state": "cleaned",
            "scale_set_absent": True,
            "runtime_empty": True,
        }

    def recover_all(self) -> list[str]:
        """Converge after broker/WSL reboot without preserving live runners."""

        recovered: list[str] = []
        self.driver.assert_no_persistent_scale_set()
        for allocation_id in self.ledger.recoverable_allocation_ids():
            self.recover(allocation_id)
            recovered.append(allocation_id)
        self.driver.assert_runtime_empty()
        return recovered

    def recover(self, allocation_id: str) -> Mapping[str, str]:
        """Recover one allocation and prove its exact scale set is absent."""

        record = self.ledger.get(allocation_id)
        try:
            binding = self.ledger.payload(allocation_id)
        except RunnerJitError:
            binding = self.ledger.reservation(allocation_id)
        scale_set_name = binding["scale_set_name"]
        try:
            _, scale_set_id = self.ledger.scale_set_binding(allocation_id)
        except RunnerJitError:
            scale_set_id = self.driver.find_scale_set(scale_set_name)
            if scale_set_id is not None:
                self.ledger.bind_scale_set(allocation_id, scale_set_id, scale_set_name)
        if scale_set_id is not None:
            self._delete_exact(scale_set_id, scale_set_name)
        else:
            self.driver.assert_scale_set_absent(scale_set_name)

        if record.state == "terminal":
            self.ledger.transition(allocation_id, "cleanup")
        elif record.state != "cleaned":
            pending = self.ledger.transition(allocation_id, "recover")
            measured = self.driver.measure_cleanup(allocation_id, scale_set_name)
            required_measurements = {
                "registration_removed",
                "workspace_removed",
                "token_removed",
                "container_removed",
                "allocation_removed",
                "orphan_registrations",
            }
            if set(measured) != required_measurements:
                raise RunnerJitError("driver cleanup measurements are not exact")
            evidence = {
                "allocation_id": allocation_id,
                "cleanup_idempotency_key": pending.cleanup_idempotency_key,
                "jobs_started": pending.jobs_started,
                **measured,
            }
            self.ledger.transition(
                allocation_id,
                "ack-recovery-cleanup",
                cleanup_idempotency_key=pending.cleanup_idempotency_key,
                cleanup_evidence=evidence,
            )
        self.driver.assert_scale_set_absent(scale_set_name)
        return {"allocation_id": allocation_id, "state": "absent"}

    def _delete_exact(self, scale_set_id: str, scale_set_name: str) -> None:
        # A prior cleanup may have removed the scale set before the durable
        # ledger recorded completion.  Measure by the authorization-bound name
        # first so recovery is idempotent without ever acting on a stale ID
        # that GARM may later reuse for a different scale set.
        if self.driver.find_scale_set(scale_set_name) is None:
            self.driver.assert_scale_set_absent(scale_set_name)
            return
        self.driver.disable_scale_set(scale_set_id, scale_set_name)
        self.driver.drain_scale_set(scale_set_id, scale_set_name)
        self.driver.delete_scale_set(scale_set_id, scale_set_name)
        self.driver.assert_scale_set_absent(scale_set_name)

    def _wait_for_cleanup(self, allocation_id: str, scale_set_name: str) -> None:
        """Wait for the provider's eventually consistent instance teardown.

        GARM can remove a scale set before Incus has finished deleting its
        runner.  Keep the ledger recoverable until every allocation-scoped
        cleanup surface is measured absent.
        """

        deadline = time.monotonic() + GARM_CLEANUP_CONVERGENCE_SECONDS
        while True:
            try:
                self.driver.measure_cleanup(allocation_id, scale_set_name)
                return
            except RunnerJitError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


GARM_CLEANUP_CONVERGENCE_SECONDS = 600


class GarmCliAllocationDriver:
    """Exact GARM 0.2.1 CLI adapter using an existing authenticated profile."""

    def __init__(self, config: Mapping[str, Any], hook_source: Path) -> None:
        required = {
            "garm_cli_home",
            "provider_name",
            "image_alias",
            "image_fingerprint",
            "targets",
        }
        if not isinstance(config, Mapping) or set(config) != required:
            raise RunnerJitError("allocation broker config requires exact fields")
        self.config = config
        self.hook_source = hook_source
        self._target: Mapping[str, Any] | None = None
        # GARM observes runner deregistration, GitHub inventory removal, and
        # provider teardown on separate reconciliation loops.  A healthy JIT
        # job can therefore need several minutes to disappear from the GARM
        # scale-set runner inventory even after GitHub and Incus are empty.
        self._timeout = GARM_CLEANUP_CONVERGENCE_SECONDS

    def _run(self, *args: str) -> Any:
        result = subprocess.run(
            [
                "/usr/local/lib/self-hosted-ci/garm-cli-session.py",
                "run",
                "--",
                "--format",
                "json",
                *args,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return json.loads(result.stdout) if result.stdout.strip() else None

    def _resolve_target(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        target = self.config["targets"].get(payload["repository_id"])
        required = {
            "authority_kind",
            "entity_flag",
            "entity_id",
            "entity_name",
            "runner_group",
        }
        if not isinstance(target, Mapping) or set(target) != required:
            raise RunnerJitError("repository is not in the broker target allowlist")
        expected_flag = (
            "--repo" if payload["authority_kind"] == "personal-repository" else "--org"
        )
        if (
            target["authority_kind"] != payload["authority_kind"]
            or target["entity_flag"] != expected_flag
            or target["runner_group"] != payload["runner_group"]
        ):
            raise RunnerJitError("GARM target authority crossed the signed allocation")
        self._target = target
        return target

    def _list_for(self, target: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        value = self._run(
            "scaleset", "list", target["entity_flag"], str(target["entity_id"])
        )
        if not isinstance(value, list):
            raise RunnerJitError("GARM scale-set inventory is invalid")
        return value

    def assert_no_persistent_scale_set(self) -> None:
        for target in self.config["targets"].values():
            for scale_set in self._list_for(target):
                name = scale_set.get("name")
                if name == "wsl-jit":
                    raise RunnerJitError(
                        "persistent shared wsl-jit scale set exists in selected authority"
                    )

    def _bootstrap(self, envelope: Mapping[str, Any]) -> bytes:
        hook = self.hook_source.read_bytes()
        if self.hook_source.is_symlink() or not hook.startswith(
            b"#!/usr/bin/env python3\n"
        ):
            raise RunnerJitError("runner hook source is unsafe")
        payload = envelope["payload"]
        hook_b64 = base64.b64encode(hook).decode("ascii")
        envelope_b64 = base64.b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        script = f"""#!/usr/bin/env bash
set -euo pipefail
umask 077
install -d -o root -g root -m 0755 /opt/self-hosted-ci/bin /etc/self-hosted-ci /etc/systemd/system.conf.d
printf '%s\n' \
  'export HTTPS_PROXY=http://10.254.0.1:3128' \
  'export HTTP_PROXY=http://10.254.0.1:3128' \
  'export NO_PROXY=10.254.0.1,127.0.0.1,localhost' \
  'export https_proxy=http://10.254.0.1:3128' \
  'export http_proxy=http://10.254.0.1:3128' \
  'export no_proxy=10.254.0.1,127.0.0.1,localhost' \
  > /etc/profile.d/self-hosted-ci-runner-proxy.sh
chown root:root /etc/profile.d/self-hosted-ci-runner-proxy.sh
chmod 0644 /etc/profile.d/self-hosted-ci-runner-proxy.sh
printf '%s' '{hook_b64}' | base64 -d > /opt/self-hosted-ci/bin/runner-job-started-hook.py
chown root:root /opt/self-hosted-ci/bin/runner-job-started-hook.py
chmod 0755 /opt/self-hosted-ci/bin/runner-job-started-hook.py
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'exec /usr/bin/python3 /opt/self-hosted-ci/bin/runner-job-started-hook.py "$@"' \
  > /opt/self-hosted-ci/bin/runner-job-started-hook.sh
chown root:root /opt/self-hosted-ci/bin/runner-job-started-hook.sh
chmod 0755 /opt/self-hosted-ci/bin/runner-job-started-hook.sh
printf '%s' '{envelope_b64}' | base64 -d > /etc/self-hosted-ci/allocation.json
printf '%s\n' '{payload["allocation_id"]}' > /etc/self-hosted-ci/allocation-id
printf '%s\n' '{payload["scale_set_name"]}' > /etc/self-hosted-ci/scale-set-name
chown root:root /etc/self-hosted-ci/allocation.json /etc/self-hosted-ci/allocation-id /etc/self-hosted-ci/scale-set-name
chmod 0444 /etc/self-hosted-ci/allocation.json /etc/self-hosted-ci/allocation-id /etc/self-hosted-ci/scale-set-name
printf '%s\n' \
  '[Manager]' \
  'DefaultEnvironment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/self-hosted-ci/bin/runner-job-started-hook.sh HTTPS_PROXY=http://10.254.0.1:3128 HTTP_PROXY=http://10.254.0.1:3128 NO_PROXY=10.254.0.1,127.0.0.1,localhost https_proxy=http://10.254.0.1:3128 http_proxy=http://10.254.0.1:3128 no_proxy=10.254.0.1,127.0.0.1,localhost' \
  > /etc/systemd/system.conf.d/self-hosted-ci-runner-hook.conf
chown root:root /etc/systemd/system.conf.d/self-hosted-ci-runner-hook.conf
chmod 0644 /etc/systemd/system.conf.d/self-hosted-ci-runner-hook.conf
systemctl daemon-reexec
"""
        return script.encode("utf-8")

    def ensure_disabled_scale_set(self, payload: Mapping[str, Any]) -> str:
        if payload["image_fingerprint"] != self.config["image_fingerprint"]:
            raise RunnerJitError(
                "allocation image fingerprint crossed broker configuration"
            )
        target = self._resolve_target(payload)
        matches = [
            item
            for item in self._list_for(target)
            if item.get("name") == payload["scale_set_name"]
        ]
        if len(matches) > 1:
            raise RunnerJitError("duplicate allocation scale sets exist")
        if matches:
            scale_id = str(matches[0].get("id"))
            self.disable_scale_set(scale_id, payload["scale_set_name"])
            return scale_id
        extra_specs = {"disable_updates": True}
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            json.dump(extra_specs, handle, sort_keys=True, separators=(",", ":"))
            specs_path = handle.name
        try:
            args = [
                "scaleset",
                "add",
                target["entity_flag"],
                str(target["entity_id"]),
                "--provider-name",
                str(self.config["provider_name"]),
                "--name",
                payload["scale_set_name"],
                "--image",
                str(self.config["image_alias"]),
                "--flavor",
                "ci-jit",
                "--os-type",
                "linux",
                "--os-arch",
                "amd64",
                "--runner-prefix",
                payload["scale_set_name"],
                "--labels",
                payload["scale_set_name"],
                "--max-runners",
                "1",
                "--min-idle-runners",
                "0",
                "--enabled=false",
                "--enable-shell=false",
                "--extra-specs-file",
                specs_path,
            ]
            if payload["runner_group"] is not None:
                args.extend(("--runner-group", payload["runner_group"]))
            created = self._run(*args)
        finally:
            Path(specs_path).unlink(missing_ok=True)
        scale_id = str(created.get("id"))
        if not scale_id.isdigit() or scale_id == "0":
            raise RunnerJitError("GARM did not return a scale-set ID")
        return scale_id

    def bind_signed_allocation(
        self, scale_set_id: str, payload: Mapping[str, Any], envelope: Mapping[str, Any]
    ) -> None:
        self._show_exact(scale_set_id, payload["scale_set_name"], False)
        try:
            runner_install_template = RUNNER_INSTALL_TEMPLATE.read_bytes()
        except OSError as exc:
            raise RunnerJitError("offline runner install template is unavailable") from exc
        if not runner_install_template.startswith(b"#!/bin/bash\n"):
            raise RunnerJitError("offline runner install template is invalid")
        extra_specs = {
            "disable_updates": True,
            "runner_install_template": base64.b64encode(
                runner_install_template
            ).decode("ascii"),
            "pre_install_scripts": {
                "20-self-hosted-ci-allocation.sh": base64.b64encode(
                    self._bootstrap(envelope)
                ).decode("ascii")
            },
        }
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            json.dump(extra_specs, handle, sort_keys=True, separators=(",", ":"))
            path = handle.name
        try:
            self._run("scaleset", "update", scale_set_id, "--extra-specs-file", path)
        finally:
            Path(path).unlink(missing_ok=True)
        observed = self._show_exact(scale_set_id, payload["scale_set_name"], False)
        if observed.get("extra_specs") != extra_specs:
            raise RunnerJitError(
                "signed allocation bootstrap did not bind to disabled scale set"
            )

    def find_scale_set(self, scale_set_name: str) -> str | None:
        for target in self.config["targets"].values():
            matches = [
                item
                for item in self._list_for(target)
                if item.get("name") == scale_set_name
            ]
            if len(matches) > 1:
                raise RunnerJitError("duplicate allocation scale sets exist")
            if matches:
                return str(matches[0]["id"])
        return None

    def _show_exact(
        self, scale_set_id: str, scale_set_name: str, enabled: bool | None = None
    ) -> Mapping[str, Any]:
        value = self._run("scaleset", "show", scale_set_id)
        if (
            not isinstance(value, Mapping)
            or str(value.get("id")) != scale_set_id
            or value.get("name") != scale_set_name
        ):
            raise RunnerJitError("GARM scale-set identity drifted")
        observed_enabled = value.get("enabled", False)
        if type(observed_enabled) is not bool:
            raise RunnerJitError("GARM scale-set enabled state drifted")
        if enabled is not None and observed_enabled is not enabled:
            raise RunnerJitError("GARM scale-set enabled state drifted")
        observed_min_idle = value.get("min_idle_runners", 0)
        if (
            value.get("max_runners") != 1
            or type(observed_min_idle) is not int
            or observed_min_idle != 0
        ):
            raise RunnerJitError("GARM scale set is not one-job/JIT")
        return value

    def enable_scale_set(self, scale_set_id: str, scale_set_name: str) -> None:
        self._show_exact(scale_set_id, scale_set_name, False)
        self._run("scaleset", "update", scale_set_id, "--enabled=true")
        self._show_exact(scale_set_id, scale_set_name, True)

    def assert_runner_claim(
        self,
        scale_set_id: str,
        scale_set_name: str,
        runner_name: str,
        payload: Mapping[str, Any],
    ) -> None:
        self._show_exact(scale_set_id, scale_set_name, True)
        runners = self._run("scaleset", "runner", "list", scale_set_id)
        if (
            not isinstance(runners, list)
            or len(runners) != 1
            or runners[0].get("name") != runner_name
        ):
            raise RunnerJitError(
                "job-started runner is not the sole allocation registration"
            )

    def disable_scale_set(self, scale_set_id: str, scale_set_name: str) -> None:
        self._show_exact(scale_set_id, scale_set_name)
        self._run("scaleset", "update", scale_set_id, "--enabled=false")
        self._show_exact(scale_set_id, scale_set_name, False)

    def drain_scale_set(self, scale_set_id: str, scale_set_name: str) -> None:
        deadline = time.monotonic() + self._timeout
        while True:
            self._show_exact(scale_set_id, scale_set_name, False)
            runners = self._run("scaleset", "runner", "list", scale_set_id)
            if runners == []:
                return
            if time.monotonic() >= deadline:
                raise RunnerJitError("GARM scale-set drain timed out")
            time.sleep(2)

    def delete_scale_set(self, scale_set_id: str, scale_set_name: str) -> None:
        self._show_exact(scale_set_id, scale_set_name, False)
        self._run("scaleset", "delete", scale_set_id)

    def assert_scale_set_absent(self, scale_set_name: str) -> None:
        if self.find_scale_set(scale_set_name) is not None:
            raise RunnerJitError("transient GARM scale set survived deletion")

    def _incus_instances(self) -> list[Mapping[str, Any]]:
        incus_config = Path("/run/self-hosted-ci/incus-client")
        incus_config.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(incus_config, 0o700)
        result = subprocess.run(
            ["/usr/bin/incus", "--project", "ci-jit", "list", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "INCUS_CONF": str(incus_config)},
        )
        value = json.loads(result.stdout)
        if not isinstance(value, list) or any(
            not isinstance(item, Mapping) for item in value
        ):
            raise RunnerJitError("Incus project inventory is invalid")
        return value

    def measure_cleanup(
        self, allocation_id: str, scale_set_name: str
    ) -> Mapping[str, Any]:
        self.assert_scale_set_absent(scale_set_name)
        matching_instances = [
            item
            for item in self._incus_instances()
            if item.get("name") == scale_set_name
            or str(item.get("name", "")).startswith(scale_set_name + "-")
        ]
        if matching_instances:
            raise RunnerJitError("allocation Incus instance survived cleanup")
        # The workspace and ephemeral registration token live only inside the
        # measured-absent disposable instance; the GARM allocation is also
        # measured absent above.
        return {
            "registration_removed": True,
            "workspace_removed": True,
            "token_removed": True,
            "container_removed": True,
            "allocation_removed": True,
            "orphan_registrations": 0,
        }

    def assert_runtime_empty(self) -> None:
        for target in self.config["targets"].values():
            if self._list_for(target) != []:
                raise RunnerJitError(
                    "GARM target contains scale sets after startup recovery"
                )
        if self._incus_instances() != []:
            raise RunnerJitError(
                "Incus ci-jit project contains instances after startup recovery"
            )


class ExternalLiveWorkflowJobVerifier:
    """Fail-closed adapter to the separately authenticated GitHub authority lane."""

    MAX_ATTEMPTS = 10
    RETRY_DELAY_SECONDS = 1

    def __init__(self, executable: Path) -> None:
        self.executable = executable

    def verify(self, payload: Mapping[str, Any], context: JobStartedContext) -> None:
        info = os.lstat(self.executable)
        if (
            not self.executable.is_file()
            or self.executable.is_symlink()
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise RunnerJitError("live workflow-job verifier executable is unsafe")
        request = {
            "workflow_job_id": payload["job_id"],
            "run_id": payload["run_id"],
            "run_attempt": payload["run_attempt"],
            "repository_id": payload["repository_id"],
            "repository": payload["repository"],
            "dispatch_sha": payload["dispatch_sha"],
            "workflow_ref": payload["workflow_ref"],
            "job_name": payload["job_name"],
            "runner_name": context.runner_name,
            "runner_group": payload["runner_group"],
            "labels": payload["labels"],
            "required_status": "in_progress",
        }
        result = None
        for attempt in range(self.MAX_ATTEMPTS):
            result = subprocess.run(
                [str(self.executable)],
                input=json.dumps(request, sort_keys=True, separators=(",", ":")),
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            if result.returncode == 0:
                break
            if attempt + 1 == self.MAX_ATTEMPTS:
                raise RunnerJitError(
                    "GitHub live workflow-job verification did not converge"
                )
            time.sleep(self.RETRY_DELAY_SECONDS)
        assert result is not None
        try:
            observed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RunnerJitError(
                "live workflow-job verifier output is invalid"
            ) from exc
        expected = {**request, "verified": True}
        expected.pop("required_status")
        expected["status"] = "in_progress"
        if observed != expected:
            raise RunnerJitError(
                "GitHub live workflow job crossed the signed allocation"
            )
