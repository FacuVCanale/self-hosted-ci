"""Strict, exact-repository registry with hosted-by-default semantics."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping


_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_TOP_LEVEL = {"$schema", "registry_schema_version", "repositories"}
_ALLOWED_REPOSITORY = {"ci_runner", "ai_reviewer", "execution_trust", "authority"}
_ALLOWED_TRUST = {
    "policy_version",
    "mode",
    "attestation_authority_version",
    "key_manifest_version",
    "key_manifest_generation",
    "key_manifest_digest",
    "offline_root_public_fingerprint",
    "public_key_id",
    "public_key_fingerprint",
    "inventory_drift_guard",
}
_ALLOWED_AUTHORITY = {"kind", "installation_id", "runner_group"}


class RegistryError(ValueError):
    """The registry is unsafe, ambiguous, or outside the versioned contract."""


@dataclass(frozen=True)
class RepositoryConfig:
    repository: str
    ci_runner: str = "github"
    ai_reviewer: str = "disabled"
    execution_trust: Mapping[str, Any] | None = None
    authority: Mapping[str, Any] | None = None

    @property
    def local_requested(self) -> bool:
        return self.ci_runner == "local-with-github-fallback"


@dataclass(frozen=True)
class Registry:
    repositories: Mapping[str, RepositoryConfig]
    registry_schema_version: int = 1

    @classmethod
    def load(cls, path: str | Path) -> "Registry":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def from_json(cls, raw: str) -> "Registry":
        try:
            data = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, RegistryError) as exc:
            raise RegistryError(f"invalid registry JSON: {exc}") from exc
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "Registry":
        _require_mapping(data, "registry")
        _reject_unknown(data, _ALLOWED_TOP_LEVEL, "registry")
        if data.get("registry_schema_version") != 1:
            raise RegistryError("registry_schema_version must be 1")
        entries = _require_mapping(data.get("repositories"), "repositories")
        parsed: dict[str, RepositoryConfig] = {}
        for repository, value in entries.items():
            _validate_repository_name(repository)
            parsed[repository] = _parse_repository(repository, value)
        return cls(repositories=parsed)

    def resolve(self, repository: str) -> RepositoryConfig:
        """Absence is deliberately safe: hosted CI and reviewer disabled."""
        _validate_repository_name(repository)
        return self.repositories.get(repository, RepositoryConfig(repository=repository))


def _parse_repository(repository: str, value: Any) -> RepositoryConfig:
    item = _require_mapping(value, repository)
    _reject_unknown(item, _ALLOWED_REPOSITORY, repository)
    ci_runner = item.get("ci_runner")
    reviewer = item.get("ai_reviewer")
    if ci_runner not in {"github", "local-with-github-fallback"}:
        raise RegistryError(f"{repository}: invalid ci_runner")
    if reviewer not in {"enabled", "disabled"}:
        raise RegistryError(f"{repository}: invalid ai_reviewer")

    trust = item.get("execution_trust")
    authority = item.get("authority")
    if ci_runner == "github":
        if trust is not None or authority is not None:
            raise RegistryError(f"{repository}: hosted entries must not carry local authority")
        return RepositoryConfig(repository, ci_runner, reviewer)

    trust = _require_mapping(trust, f"{repository}.execution_trust")
    authority = _require_mapping(authority, f"{repository}.authority")
    _validate_trust(repository, trust)
    _validate_authority(repository, authority)
    return RepositoryConfig(repository, ci_runner, reviewer, dict(trust), dict(authority))


def _validate_trust(repository: str, trust: Mapping[str, Any]) -> None:
    _reject_unknown(trust, _ALLOWED_TRUST, f"{repository}.execution_trust")
    exact = {
        "policy_version": 1,
        "mode": "exact-sha-attestation",
        "attestation_authority_version": 1,
        "key_manifest_version": 1,
        "inventory_drift_guard": "enabled",
    }
    for key, expected in exact.items():
        if trust.get(key) != expected:
            raise RegistryError(f"{repository}: {key} must be {expected!r}")
    generation = trust.get("key_manifest_generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise RegistryError(f"{repository}: key_manifest_generation must be a positive integer")
    for key in ("key_manifest_digest", "offline_root_public_fingerprint", "public_key_fingerprint"):
        if not isinstance(trust.get(key), str) or not _SHA256.fullmatch(trust[key]):
            raise RegistryError(f"{repository}: {key} must be lowercase SHA-256")
    if not isinstance(trust.get("public_key_id"), str) or not trust["public_key_id"].strip():
        raise RegistryError(f"{repository}: public_key_id is required")


def _validate_authority(repository: str, authority: Mapping[str, Any]) -> None:
    _reject_unknown(authority, _ALLOWED_AUTHORITY, f"{repository}.authority")
    kind = authority.get("kind")
    installation_id = authority.get("installation_id")
    runner_group = authority.get("runner_group")
    if not isinstance(installation_id, int) or isinstance(installation_id, bool) or installation_id < 1:
        raise RegistryError(f"{repository}: installation_id must be a positive integer")
    if kind == "personal-repository":
        if runner_group is not None:
            raise RegistryError(f"{repository}: personal repository cannot use a runner group")
    elif kind == "organization-runner-group":
        if not isinstance(runner_group, str) or not runner_group.strip() or "*" in runner_group:
            raise RegistryError(f"{repository}: exact organization runner_group is required")
    else:
        raise RegistryError(f"{repository}: invalid authority kind")


def _validate_repository_name(repository: Any) -> None:
    if not isinstance(repository, str) or "*" in repository or not _REPOSITORY.fullmatch(repository):
        raise RegistryError(f"invalid exact owner/repo: {repository!r}")


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegistryError(f"{where} must be an object")
    return value


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RegistryError(f"{where}: unknown fields: {', '.join(unknown)}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate key: {key}")
        result[key] = value
    return result
