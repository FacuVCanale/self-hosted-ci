#!/usr/bin/env python3
"""Stage public runtime files and bind them into an unsigned boundary template."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_REF = "live/live-artifacts-v1.json"

# source path, installed target, mode, kind, component
PUBLIC_ARTIFACTS = (
    ("scripts/host/verify-wsl-jit-readiness.py", "/usr/local/lib/self-hosted-ci/verify-wsl-jit-readiness.py", "0755", "script", "garm"),
    ("scripts/host/verify-live-artifact-contract.py", "/usr/local/lib/self-hosted-ci/verify-live-artifact-contract.py", "0755", "script", "garm"),
    ("scripts/host/collect-wsl-jit-measurements.py", "/usr/local/lib/self-hosted-ci/collect-wsl-jit-measurements.py", "0755", "script", "garm"),
    ("scripts/host/collect-health-snapshot.py", "/usr/local/lib/self-hosted-ci/collect-health-snapshot.py", "0755", "script", "garm"),
    ("scripts/host/garm-cli-session.py", "/usr/local/lib/self-hosted-ci/garm-cli-session.py", "0755", "script", "garm"),
    ("scripts/host/update-health-heartbeat.py", "/usr/local/lib/self-hosted-ci/update-health-heartbeat.py", "0755", "script", "garm"),
    ("scripts/host/install-wsl-jit-evidence.py", "/usr/local/lib/self-hosted-ci/install-wsl-jit-evidence.py", "0755", "script", "garm"),
    ("scripts/host/prepare-incus-runner-image.sh", "/usr/local/lib/self-hosted-ci/prepare-incus-runner-image.sh", "0755", "script", "incus"),
    ("scripts/host/configure-garm-jit.sh", "/usr/local/lib/self-hosted-ci/configure-garm-jit.sh", "0755", "script", "garm"),
    ("scripts/host/activate-garm-jit.sh", "/usr/local/lib/self-hosted-ci/activate-garm-jit.sh", "0755", "script", "garm"),
    ("scripts/host/deactivate-garm-jit.sh", "/usr/local/lib/self-hosted-ci/deactivate-garm-jit.sh", "0755", "script", "garm"),
    ("scripts/host/garm-jit-transaction-lib.sh", "/usr/local/lib/self-hosted-ci/garm-jit-transaction-lib.sh", "0755", "script", "garm"),
    ("scripts/host/install-incus-garm-tls.sh", "/usr/local/lib/self-hosted-ci/install-incus-garm-tls.sh", "0755", "script", "garm"),
    ("scripts/host/install-runner-network-runtime.sh", "/usr/local/lib/self-hosted-ci/install-runner-network-runtime.sh", "0755", "script", "network-policy"),
    ("scripts/host/apply-runner-network-policy.sh", "/usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh", "0755", "script", "network-policy"),
    ("scripts/host/run-egress-proxies.sh", "/usr/local/lib/self-hosted-ci/run-egress-proxies.sh", "0755", "script", "network-policy"),
    ("scripts/host/garm-callback-proxy.py", "/usr/local/lib/self-hosted-ci/garm-callback-proxy.py", "0755", "script", "network-policy"),
    ("scripts/host/garm-allocation-broker.py", "/usr/local/lib/self-hosted-ci/garm-allocation-broker.py", "0755", "script", "garm"),
    ("scripts/host/github-live-job-verifier.py", "/usr/local/libexec/self-hosted-ci/github-live-job-verifier.py", "0755", "script", "garm"),
    ("scripts/host/runner-job-started-hook.py", "/usr/local/lib/self-hosted-ci/runner-job-started-hook.py", "0755", "script", "garm"),
    ("scripts/host/outbound-coordinator-worker.py", "/usr/local/lib/self-hosted-ci/outbound-coordinator-worker.py", "0755", "script", "garm"),
    ("scripts/host/install-outbound-worker-runtime.py", "/usr/local/lib/self-hosted-ci/install-outbound-worker-runtime.py", "0755", "script", "garm"),
    ("scripts/host/jit-pilot-terminal-monitor.py", "/usr/local/lib/self-hosted-ci/jit-pilot-terminal-monitor.py", "0755", "script", "garm"),
    ("github_automation/__init__.py", "/usr/local/lib/self-hosted-ci/github_automation/__init__.py", "0644", "python-module", "garm"),
    ("github_automation/crypto.py", "/usr/local/lib/self-hosted-ci/github_automation/crypto.py", "0644", "python-module", "garm"),
    ("github_automation/host_security.py", "/usr/local/lib/self-hosted-ci/github_automation/host_security.py", "0644", "python-module", "garm"),
    ("github_automation/runner_boundary.py", "/usr/local/lib/self-hosted-ci/github_automation/runner_boundary.py", "0644", "python-module", "garm"),
    ("github_automation/runner_jit.py", "/usr/local/lib/self-hosted-ci/github_automation/runner_jit.py", "0644", "python-module", "garm"),
    ("github_automation/runner_jit_broker.py", "/usr/local/lib/self-hosted-ci/github_automation/runner_jit_broker.py", "0644", "python-module", "garm"),
    ("github_automation/github.py", "/usr/local/lib/self-hosted-ci/github_automation/github.py", "0644", "python-module", "garm"),
    ("github_automation/github_adapter.py", "/usr/local/lib/self-hosted-ci/github_automation/github_adapter.py", "0644", "python-module", "garm"),
    ("github_automation/check_delivery.py", "/usr/local/lib/self-hosted-ci/github_automation/check_delivery.py", "0644", "python-module", "garm"),
    ("github_automation/inventory.py", "/usr/local/lib/self-hosted-ci/github_automation/inventory.py", "0644", "python-module", "garm"),
    ("github_automation/policy.py", "/usr/local/lib/self-hosted-ci/github_automation/policy.py", "0644", "python-module", "garm"),
    ("github_automation/registry.py", "/usr/local/lib/self-hosted-ci/github_automation/registry.py", "0644", "python-module", "garm"),
    ("github_automation/coordinator.py", "/usr/local/lib/self-hosted-ci/github_automation/coordinator.py", "0644", "python-module", "garm"),
    ("github_automation/outbound_worker.py", "/usr/local/lib/self-hosted-ci/github_automation/outbound_worker.py", "0644", "python-module", "garm"),
    ("github_automation/worker_authority.py", "/usr/local/lib/self-hosted-ci/github_automation/worker_authority.py", "0644", "python-module", "garm"),
    ("github_automation/gatestore.py", "/usr/local/lib/self-hosted-ci/github_automation/gatestore.py", "0644", "python-module", "garm"),
    ("github_automation/jit_pilot.py", "/usr/local/lib/self-hosted-ci/github_automation/jit_pilot.py", "0644", "python-module", "garm"),
    ("github_automation/local_approval.py", "/usr/local/lib/self-hosted-ci/github_automation/local_approval.py", "0644", "python-module", "garm"),
    ("templates/garm/config.toml.example", "/etc/self-hosted-ci/garm/config.toml.example", "0640", "public-config", "garm"),
    ("templates/incus/runner-profile.yaml", "/etc/self-hosted-ci/incus/runner-profile.yaml", "0640", "public-config", "incus"),
    ("templates/garm/garm-provider-incus.toml", "/usr/local/share/self-hosted-ci/garm-provider-incus.toml", "0644", "public-config", "garm"),
    ("templates/garm/outbound-worker.json.example", "/usr/local/share/self-hosted-ci/outbound-worker.json.example", "0644", "public-config", "garm"),
    ("templates/garm/worker-app-authority.json.example", "/usr/local/share/self-hosted-ci/worker-app-authority.json.example", "0644", "public-config", "garm"),
    ("templates/garm/garm-provider-incus.toml", "/etc/self-hosted-ci/garm/garm-provider-incus.toml", "0640", "public-config", "garm"),
    ("packaging/network/squid.conf", "/etc/self-hosted-ci/network/squid.conf", "0640", "public-config", "network-policy"),
    ("packaging/systemd/self-hosted-ci-boundary-verify.service", "/etc/systemd/system/self-hosted-ci-boundary-verify.service", "0644", "unit", "garm"),
    ("packaging/systemd/self-hosted-ci-garm.service", "/etc/systemd/system/self-hosted-ci-garm.service", "0644", "unit", "garm"),
    ("packaging/systemd/self-hosted-ci-network-policy.service", "/etc/systemd/system/self-hosted-ci-network-policy.service", "0644", "unit", "network-policy"),
    ("packaging/systemd/self-hosted-ci-egress-proxy.service", "/etc/systemd/system/self-hosted-ci-egress-proxy.service", "0644", "unit", "network-policy"),
    ("packaging/systemd/self-hosted-ci-allocation-broker.service", "/etc/systemd/system/self-hosted-ci-allocation-broker.service", "0644", "unit", "garm"),
    ("packaging/systemd/self-hosted-ci-outbound-worker.service", "/etc/systemd/system/self-hosted-ci-outbound-worker.service", "0644", "unit", "garm"),
    ("packaging/systemd/self-hosted-ci-health-heartbeat.service", "/etc/systemd/system/self-hosted-ci-health-heartbeat.service", "0644", "unit", "garm"),
    ("packaging/systemd/self-hosted-ci-health-heartbeat.timer", "/etc/systemd/system/self-hosted-ci-health-heartbeat.timer", "0644", "unit", "garm"),
)
PINNED_BINARIES = (
    ("/usr/local/bin/garm", "garm"),
    ("/usr/local/bin/garm-cli", "garm"),
    ("/usr/local/libexec/garm/garm-provider-incus", "garm"),
)
TARGET_GROUPS = {
    "/etc/self-hosted-ci/network/squid.conf": "proxy",
    "/etc/self-hosted-ci/garm/garm-provider-incus.toml": "garm-manager",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-boundary", required=True, type=Path)
    parser.add_argument("--output-boundary", required=True, type=Path)
    parser.add_argument("--measurement-root", required=True, type=Path)
    parser.add_argument("--installed-root", default=Path("/"), type=Path)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("live contract staging must run as root", file=sys.stderr)
        return 2
    try:
        boundary = json.loads(args.input_boundary.read_text(encoding="utf-8"))
        boundary.pop("attestation", None)
        refs_by_component: dict[str, list[str]] = {}
        records: list[dict] = []
        for index, (relative, target, mode, kind, component) in enumerate(PUBLIC_ARTIFACTS):
            source = ROOT / relative
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"public source is unsafe: {relative}")
            data = source.read_bytes()
            ref = f"live/source/{index:02d}-{Path(relative).name}"
            destination = args.measurement_root / ref
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            # Evidence copies are inert data. Their signed mode is deliberately
            # non-executable; the contract separately binds the destination mode.
            os.chown(destination, 0, 0); os.chmod(destination, 0o640)
            group_name = TARGET_GROUPS.get(target, "root")
            target_gid = grp.getgrnam(group_name).gr_gid
            records.append({"target": target, "source_ref": ref, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mode": mode, "uid": 0, "gid": target_gid, "kind": kind})
            refs_by_component.setdefault(component, []).append(ref)
        for target, component in PINNED_BINARIES:
            installed = args.installed_root / target.lstrip("/")
            if installed.is_symlink() or not installed.is_file():
                raise ValueError(f"pinned binary is unsafe or absent: {target}")
            info, data = os.stat(installed, follow_symlinks=False), installed.read_bytes()
            if info.st_uid != 0 or info.st_nlink != 1:
                raise ValueError(f"pinned binary metadata is unsafe: {target}")
            records.append({"target": target, "source_ref": None, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mode": f"{info.st_mode & 0o7777:04o}", "uid": 0, "gid": info.st_gid, "kind": "pinned-binary"})
            refs_by_component.setdefault(component, [])
        records.sort(key=lambda item: item["target"])
        contract = {"live_artifact_contract_version": 1, "artifacts": records}
        contract_path = args.measurement_root / CONTRACT_REF
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chown(contract_path, 0, 0); os.chmod(contract_path, 0o640)
        refs_by_component.setdefault("garm", []).append(CONTRACT_REF)
        for component in boundary["components"]:
            for ref in refs_by_component.get(component["id"], []):
                if ref not in component["evidence_refs"]:
                    component["evidence_refs"].append(ref)
            component["evidence_refs"].sort()
        args.output_boundary.write_text(json.dumps(boundary, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"live contract staging failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
