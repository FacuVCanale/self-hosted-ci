#!/usr/bin/env python3
"""Collect sanitized, read-only observations from the dedicated WSL JIT host.

This program deliberately makes no readiness decision.  It emits observations
and exits non-zero when any mandatory probe cannot be completed.  In
particular, it has no operator override or ``--pass`` escape hatch.
"""

from __future__ import annotations

import configparser
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXPECTED_DISTRO = "Ubuntu-24.04-CI"
EXPECTED_IDENTITIES = ("garm-manager",)
PACKAGES = (
    "dnsmasq-base",
    "e2fsprogs",
    "incus",
    "nftables",
    "squid",
    "util-linux",
)
BINARIES = {
    "garm": "/usr/local/bin/garm",
    "garm-cli": "/usr/local/bin/garm-cli",
    "garm-provider-incus": "/usr/local/libexec/garm/garm-provider-incus",
    "incus": "/usr/bin/incus",
    "nft": "/usr/sbin/nft",
    "squid": "/usr/sbin/squid",
}
EXPECTED_SOFTWARE = {
    "incus": {"version": "6.0.0-1ubuntu0.3"},
    "garm": {
        "version": "0.2.1",
        "artifact_sha256": "11176acb8a725f914b9b947891b4837d374fb616195562cc0ad45a7be8b6c746",
        "binary_sha256": "b04fda186bfa0c98a902a3bb7525987217565681ec33b553921945dbb574b87e",
    },
    "garm-cli": {
        "version": "0.2.1",
        "artifact_sha256": "983fa54557f3f5ce3aa1eeb2387499f5f823d14512a0559ba888667bc3b3e88e",
        "binary_sha256": "a973c9061cf7962b4f90c8220ed6f6cc8abeeed20780ea8b9e31ce6dfc99bd9b",
    },
    "garm-provider-incus": {
        "version": "0.1.5",
        "artifact_sha256": "1489b5f9b3f01528e338c604c13dabe8321ed6f1bc6de77c7344119d7731c43f",
        "binary_sha256": "0fe2c592cece494ad5fc6a6fe05ef2e621fb5d47fb03cc472c2b1d6739428891",
    },
}
EXPECTED_ENDPOINTS = (
    ("10.254.0.1", 53, "dns"),
    ("10.254.0.1", 3128, "egress-proxy"),
    ("10.254.0.1", 8080, "garm-proxy"),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str | None:
    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def any_matching_file(
    roots: tuple[Path, ...], patterns: tuple[str, ...]
) -> bool | None:
    try:
        return any(
            next(root.glob(pattern), None) is not None
            for root in roots
            if root.is_dir()
            for pattern in patterns
        )
    except OSError:
        return None


def recursive_credential_candidates(
    roots: tuple[Path, ...], *, maximum_entries: int = 50_000
) -> bool | None:
    """Classify nested credential-like material without emitting any path."""
    entries = 0
    key_names = {
        ".credentials",
        ".credentials_rsaparams",
        ".runner",
        "authorized_keys",
        "config",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
    key_suffixes = (".key", ".p12", ".pfx", ".pkcs12")

    def fail_walk(error: OSError) -> None:
        raise error

    try:
        for root in roots:
            try:
                details = root.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(details.st_mode):
                return None
            if not stat.S_ISDIR(details.st_mode):
                continue
            for current, directories, files in os.walk(
                root, followlinks=False, onerror=fail_walk
            ):
                current_path = Path(current)
                entries += len(directories) + len(files)
                if entries > maximum_entries:
                    return None
                safe_directories: list[str] = []
                for name in directories:
                    candidate = current_path / name
                    if candidate.is_symlink():
                        return True
                    safe_directories.append(name)
                directories[:] = safe_directories
                inside_ssh = ".ssh" in current_path.parts
                for name in files:
                    if (current_path / name).is_symlink():
                        return True
                    lowered = name.lower()
                    if (
                        inside_ssh
                        or lowered in key_names
                        or lowered.endswith(key_suffixes)
                        or (lowered.endswith(".pem") and "public" not in lowered)
                    ):
                        return True
        return False
    except OSError:
        return None


def credential_scan_roots() -> tuple[Path, ...]:
    """Return sanitized credential roots, including GARM's configured home."""
    roots = [Path("/root"), Path("/var/lib/garm"), Path("/etc/self-hosted-ci")]
    try:
        roots.append(Path(pwd.getpwnam("garm-manager").pw_dir))
    except KeyError:
        pass
    return tuple(dict.fromkeys(roots))


class Collector:
    def __init__(
        self,
        *,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        environ: dict[str, str] | os._Environ[str] = os.environ,
    ) -> None:
        self.run = run
        self.environ = environ
        self.errors: list[dict[str, str]] = []

    def command(
        self, probe: str, argv: list[str], *, accepted_codes: tuple[int, ...] = (0,)
    ) -> str | None:
        executable = shutil.which(argv[0])
        if executable is None:
            self.errors.append({"probe": probe, "reason": "command-missing"})
            return None
        try:
            result = self.run(
                [executable, *argv[1:]],
                text=True,
                capture_output=True,
                check=False,
                timeout=15,
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                },
            )
        except (OSError, subprocess.TimeoutExpired):
            self.errors.append({"probe": probe, "reason": "command-unavailable"})
            return None
        if result.returncode not in accepted_codes:
            self.errors.append({"probe": probe, "reason": "command-failed"})
            return None
        return result.stdout

    def json_command(self, probe: str, argv: list[str]) -> Any | None:
        output = self.command(probe, argv)
        if output is None:
            return None
        try:
            return json.loads(output)
        except (TypeError, json.JSONDecodeError):
            self.errors.append({"probe": probe, "reason": "invalid-json"})
            return None

    def wsl_boundary(self) -> dict[str, object]:
        config_path = Path("/etc/wsl.conf")
        result: dict[str, object] = {
            "distro_environment_matches": self.environ.get("WSL_DISTRO_NAME")
            == EXPECTED_DISTRO,
            "wsl_conf": {"readable": False, "sha256": None, "settings": {}},
        }
        try:
            raw = config_path.read_text(encoding="utf-8")
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw)
            settings = {
                "automount.enabled": parser.get("automount", "enabled", fallback=None),
                "automount.mountfstab": parser.get(
                    "automount", "mountfstab", fallback=None
                ),
                "interop.enabled": parser.get("interop", "enabled", fallback=None),
                "interop.appendwindowspath": parser.get(
                    "interop", "appendwindowspath", fallback=None
                ),
            }
            result["wsl_conf"] = {
                "readable": True,
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "settings": settings,
            }
        except (OSError, UnicodeDecodeError, configparser.Error):
            self.errors.append({"probe": "wsl-conf", "reason": "unreadable-or-invalid"})
        return result

    def mounts_and_interop(self) -> dict[str, object]:
        classifications = {
            "drvfs": 0,
            "windows_drive_target": 0,
            "docker_desktop": 0,
            "wsl_shared": 0,
        }
        try:
            lines = (
                Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
            )
            for line in lines:
                fields = line.split()
                separator = fields.index("-")
                target, fs_type, source = (
                    fields[4],
                    fields[separator + 1],
                    fields[separator + 2],
                )
                classifications["drvfs"] += int(fs_type == "drvfs")
                classifications["windows_drive_target"] += int(
                    target.startswith("/mnt/") and len(target.split("/", 3)[2]) == 1
                )
                classifications["docker_desktop"] += int(
                    "docker-desktop" in target or "docker-desktop" in source
                )
                classifications["wsl_shared"] += int(target.startswith("/mnt/wsl/"))
        except (OSError, UnicodeDecodeError, ValueError, IndexError):
            self.errors.append({"probe": "mounts", "reason": "unreadable-or-invalid"})

        interop_path = Path("/proc/sys/fs/binfmt_misc/WSLInterop")
        try:
            interop_text = interop_path.read_text(encoding="ascii")
            interop = {
                "present": True,
                "enabled": "enabled" in interop_text.splitlines(),
            }
        except OSError:
            interop = {"present": False, "enabled": False}
        path_entries = self.environ.get("PATH", "").split(":")
        windows_path_entries = sum(
            1
            for entry in path_entries
            if "\\" in entry or (len(entry) >= 2 and entry[1] == ":")
        )
        return {
            "mount_class_counts": classifications,
            "wsl_interop": interop,
            "windows_path_entry_count": windows_path_entries,
        }

    def credential_surfaces(self) -> dict[str, object]:
        exact = {
            "docker_socket": (Path("/var/run/docker.sock"), Path("/run/docker.sock")),
            "docker_desktop_socket": (
                Path("/run/guest-services/docker.sock"),
                Path("/mnt/wsl/shared-docker/docker.sock"),
            ),
            "persistent_actions_runner": (
                Path("/opt/self-hosted-ci/actions-runner/.runner"),
                Path("/opt/self-hosted-ci/actions-runner/.credentials"),
                Path("/opt/self-hosted-ci/actions-runner/.credentials_rsaparams"),
                Path("/var/lib/garm/.runner"),
                Path("/var/lib/garm/.credentials"),
                Path("/var/lib/garm/.credentials_rsaparams"),
            ),
            "garm_control_credentials": (
                Path("/etc/self-hosted-ci/garm/admin-username"),
                Path("/etc/self-hosted-ci/garm/admin-password"),
                Path("/etc/self-hosted-ci/garm/jwt-secret"),
            ),
            "github_or_authority_private_keys": (
                Path("/etc/self-hosted-ci/secrets/github-app.pem"),
                Path("/etc/self-hosted-ci/secrets/worker-github-app.pem"),
                Path("/etc/self-hosted-ci/secrets/authority-v1-ed25519.pem"),
                Path("/etc/self-hosted-ci/secrets/allocation-ed25519.pem"),
            ),
        }
        classes = {
            name: any(path.exists() for path in paths) for name, paths in exact.items()
        }
        ssh_agent = self.environ.get("SSH_AUTH_SOCK")
        classes["ssh_agent_socket"] = bool(ssh_agent and Path(ssh_agent).exists())
        secret_roots = credential_scan_roots()
        private_patterns = (
            "id_rsa",
            "id_ed25519",
            "*.p12",
            "*.pfx",
            "*private*.pem",
            "*deploy*key*",
        )
        classes["private_or_deploy_key_candidates"] = any_matching_file(
            secret_roots, private_patterns
        )
        unit_roots = (
            Path("/etc/systemd/system"),
            Path("/usr/lib/systemd/system"),
            Path("/lib/systemd/system"),
        )
        service_units = any_matching_file(unit_roots, ("actions.runner.*.service",))
        classes["persistent_actions_runner_service_unit"] = service_units
        recursive = recursive_credential_candidates(secret_roots)
        classes["recursive_credential_candidates"] = recursive
        if recursive is None:
            self.errors.append(
                {"probe": "recursive-credential-scan", "reason": "unobservable"}
            )
        return classes

    def identities(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in EXPECTED_IDENTITIES:
            try:
                account = pwd.getpwnam(name)
                groups = sorted(
                    group.gr_name for group in grp.getgrall() if name in group.gr_mem
                )
                primary = grp.getgrgid(account.pw_gid).gr_name
                result[name] = {
                    "present": True,
                    "uid": account.pw_uid,
                    "gid": account.pw_gid,
                    "primary_group": primary,
                    "supplementary_groups": groups,
                    "home": account.pw_dir,
                    "shell": account.pw_shell,
                }
            except KeyError:
                result[name] = {"present": False}
                self.errors.append({"probe": f"identity:{name}", "reason": "absent"})
        return result

    def packages_and_binaries(self) -> dict[str, object]:
        packages: dict[str, object] = {}
        for name in PACKAGES:
            output = self.command(
                f"package:{name}",
                ["dpkg-query", "-W", "-f=${db:Status-Status}|${Version}\n", name],
            )
            if output is None:
                packages[name] = {"installed": None, "version": None}
                continue
            status, separator, version = output.strip().partition("|")
            if separator != "|":
                self.errors.append(
                    {"probe": f"package:{name}", "reason": "invalid-output"}
                )
                packages[name] = {"installed": None, "version": None}
            else:
                packages[name] = {
                    "installed": status == "installed",
                    "version": version,
                }
        binaries = {
            name: {
                "path": path,
                "present": Path(path).is_file() and not Path(path).is_symlink(),
                "sha256": sha256_file(Path(path)),
            }
            for name, path in BINARIES.items()
        }
        return {
            "expected_pins": EXPECTED_SOFTWARE,
            "packages": packages,
            "binaries": binaries,
        }

    @staticmethod
    def sanitize_incus(name: str, payload: dict[str, object]) -> dict[str, object]:
        config_keys = {
            "project": {
                "features.images",
                "features.profiles",
                "features.storage.volumes",
                "restricted",
                "restricted.containers.privilege",
                "restricted.containers.nesting",
                "restricted.containers.lowlevel",
                "restricted.devices.disk",
                "restricted.devices.nic",
                "restricted.networks.access",
                "limits.instances",
                "limits.containers",
                "limits.virtual-machines",
                "limits.cpu",
                "limits.memory",
                "limits.processes",
                "limits.disk",
            },
            "profile": {
                "security.privileged",
                "security.nesting",
                "security.idmap.isolated",
                "limits.cpu",
                "limits.memory",
                "limits.processes",
            },
            "storage": {"source"},
            "bridge": {
                "ipv4.address",
                "ipv4.dhcp",
                "ipv4.dhcp.ranges",
                "ipv4.dhcp.gateway",
                "ipv4.nat",
                "ipv4.firewall",
                "ipv6.address",
                "ipv6.nat",
                "ipv6.firewall",
                "dns.mode",
                "bridge.external_interfaces",
            },
        }[name]
        config = payload.get("config")
        safe_config = (
            {key: config[key] for key in sorted(config_keys) if key in config}
            if isinstance(config, dict)
            else {}
        )
        result: dict[str, object] = {
            "present": True,
            "config": safe_config,
        }
        if name == "storage":
            result["driver"] = payload.get("driver")
        elif name == "bridge":
            result["type"] = payload.get("type")
        elif name == "profile":
            devices = payload.get("devices")
            safe_devices: dict[str, object] = {}
            if isinstance(devices, dict):
                for device_name in ("eth0", "root"):
                    device = devices.get(device_name)
                    if not isinstance(device, dict):
                        continue
                    allowed = (
                        {"type", "path", "pool", "size"}
                        if device_name == "root"
                        else {
                            "type",
                            "network",
                            "name",
                            "security.mac_filtering",
                            "security.ipv4_filtering",
                            "security.ipv6_filtering",
                        }
                    )
                    safe_devices[device_name] = {
                        key: device[key] for key in sorted(allowed) if key in device
                    }
            result["devices"] = safe_devices
        return result

    def incus(self) -> dict[str, object]:
        endpoints = {
            "project": "/1.0/projects/ci-jit",
            "profile": "/1.0/profiles/ci-jit?project=ci-jit",
            "storage": "/1.0/storage-pools/ci-jit-dedicated",
            "bridge": "/1.0/networks/ci-jit-isolated",
        }
        observations: dict[str, object] = {}
        for name, endpoint in endpoints.items():
            payload = self.json_command(f"incus:{name}", ["incus", "query", endpoint])
            if isinstance(payload, dict):
                observations[name] = self.sanitize_incus(name, payload)
            else:
                observations[name] = {"present": False}
        instances = self.json_command(
            "incus:instances",
            ["incus", "list", "--project", "ci-jit", "--format", "json"],
        )
        observations["instances"] = {
            "observable": isinstance(instances, list),
            "count": len(instances) if isinstance(instances, list) else None,
            "names_sha256": hashlib.sha256(
                json.dumps(
                    sorted(
                        item.get("name", "")
                        for item in instances
                        if isinstance(item, dict)
                    ),
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            if isinstance(instances, list)
            else None,
        }
        return observations

    def network(self) -> dict[str, object]:
        nft = self.json_command("nftables", ["nft", "--json", "list", "ruleset"])
        if isinstance(nft, dict) and isinstance(nft.get("nftables"), list):
            records = nft["nftables"]
            tables = sorted(
                str(record["table"].get("name"))
                for record in records
                if isinstance(record, dict) and isinstance(record.get("table"), dict)
            )
            nft_observation = {
                "observable": True,
                "table_names": tables,
                "rule_count": sum(
                    isinstance(record, dict) and "rule" in record for record in records
                ),
                "canonical_sha256": hashlib.sha256(
                    json.dumps(nft, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            }
        else:
            nft_observation = {
                "observable": False,
                "table_names": [],
                "rule_count": None,
                "canonical_sha256": None,
            }

        listening = self.command("listening-sockets", ["ss", "-H", "-lntup"])
        endpoints = {label: False for _, _, label in EXPECTED_ENDPOINTS}
        if listening is not None:
            for address, port, label in EXPECTED_ENDPOINTS:
                endpoints[label] = any(
                    f"{address}:{port}" in line for line in listening.splitlines()
                )

        resolver_classes = {
            "loopback": 0,
            "private": 0,
            "public": 0,
            "link_local": 0,
            "invalid": 0,
        }
        try:
            for line in (
                Path("/etc/resolv.conf").read_text(encoding="ascii").splitlines()
            ):
                fields = line.split()
                if len(fields) != 2 or fields[0] != "nameserver":
                    continue
                try:
                    address = ipaddress.ip_address(fields[1].split("%", 1)[0])
                except ValueError:
                    resolver_classes["invalid"] += 1
                    continue
                if address.is_loopback:
                    resolver_classes["loopback"] += 1
                elif address.is_link_local:
                    resolver_classes["link_local"] += 1
                elif address.is_private:
                    resolver_classes["private"] += 1
                else:
                    resolver_classes["public"] += 1
        except (OSError, UnicodeDecodeError):
            self.errors.append({"probe": "resolver", "reason": "unreadable"})
        return {
            "nftables": nft_observation,
            "expected_listeners": endpoints,
            "resolver_classes": resolver_classes,
        }

    def service_state(self, name: str) -> dict[str, object]:
        active = self.command(
            f"service:{name}:active",
            ["systemctl", "is-active", name],
            accepted_codes=(0, 3, 4),
        )
        enabled = self.command(
            f"service:{name}:enabled",
            ["systemctl", "is-enabled", name],
            accepted_codes=(0, 1, 3, 4),
        )
        enabled_state = enabled.strip() if enabled is not None else None
        if enabled_state == "":
            enabled_state = "not-found"
        if enabled_state not in {"disabled", "not-found", "enabled", "static", "masked", None}:
            self.errors.append(
                {"probe": f"service:{name}:enabled", "reason": "invalid-state"}
            )
            enabled_state = None
        return {
            "active": active.strip() if active is not None else None,
            "enabled": enabled_state,
        }

    def garm(self) -> dict[str, object]:
        processes = self.command(
            "garm-processes", ["pgrep", "-x", "garm"], accepted_codes=(0, 1)
        )
        process_count = len(processes.splitlines()) if processes is not None else None
        health_path = Path("/etc/self-hosted-ci/garm/health-state.json")
        health: dict[str, object] = {
            "observable": False,
            "zero_scale_sets": None,
            "configured_target_count": None,
        }
        try:
            details = health_path.lstat()
            payload = json.loads(health_path.read_text(encoding="utf-8"))
            secure = (
                stat.S_ISREG(details.st_mode)
                and details.st_uid == 0
                and not details.st_mode & 0o022
            )
            health = {
                "observable": secure and isinstance(payload, dict),
                "zero_scale_sets": payload.get("zero_scale_sets")
                if secure and isinstance(payload, dict)
                else None,
                "configured_target_count": len(payload.get("targets", {}))
                if secure
                and isinstance(payload, dict)
                and isinstance(payload.get("targets"), dict)
                else None,
            }
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            self.errors.append(
                {"probe": "garm-health-state", "reason": "unreadable-or-invalid"}
            )
        return {
            "services": {
                "garm.service": self.service_state("garm.service"),
                "self-hosted-ci-garm.service": self.service_state(
                    "self-hosted-ci-garm.service"
                ),
            },
            "process_count": process_count,
            "health_state": health,
            "state_database_present": Path(
                "/var/lib/self-hosted-ci/garm/garm.db"
            ).exists(),
            "persistent_runner_registration_present": bool(
                self.credential_surfaces()["persistent_actions_runner"]
            ),
        }

    def collect(self) -> dict[str, object]:
        observations = {
            "wsl_boundary": self.wsl_boundary(),
            "mounts_and_interop": self.mounts_and_interop(),
            "credential_surfaces": self.credential_surfaces(),
            "linux_identities": self.identities(),
            "software": self.packages_and_binaries(),
            "incus": self.incus(),
            "network": self.network(),
            "garm": self.garm(),
        }
        return {
            "schema_version": 1,
            "collector": "wsl-jit-semantic-observations",
            "observed_at": utc_now(),
            "expected_distro": EXPECTED_DISTRO,
            "collection_status": "complete" if not self.errors else "incomplete",
            "observations": observations,
            "probe_errors": sorted(
                self.errors, key=lambda item: (item["probe"], item["reason"])
            ),
        }


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("usage: collect-wsl-jit-semantic-observations.py", file=sys.stderr)
        return 2
    result = Collector().collect()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["collection_status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
