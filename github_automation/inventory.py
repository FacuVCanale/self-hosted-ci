"""Negative-only effective-writer inventory normalization and freshness."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class InventoryObservation:
    status: str
    required_source_ids: tuple[str, ...]
    missing_source_ids: tuple[str, ...]
    normalized_usable_source_records: tuple[Mapping[str, Any], ...]
    observed_at: datetime
    semantic_hash: str

    def is_fresh(self, now: datetime, maximum_age: timedelta = timedelta(minutes=5)) -> bool:
        _require_aware_utc(now)
        _require_aware_utc(self.observed_at)
        age = now - self.observed_at
        return timedelta(0) <= age <= maximum_age


def classify_inventory(
    required_source_ids: Iterable[str],
    usable_records_by_source: Mapping[str, Iterable[Mapping[str, Any]]],
    observed_at: datetime,
) -> InventoryObservation:
    required = tuple(sorted(set(required_source_ids)))
    if not required or any(not source for source in required):
        raise ValueError("required_source_ids must be a non-empty authenticated set")
    unknown = sorted(set(usable_records_by_source) - set(required))
    if unknown:
        raise ValueError(f"records for unknown sources: {', '.join(unknown)}")
    usable_sources = set(usable_records_by_source)
    missing = tuple(sorted(set(required) - usable_sources))
    if len(usable_sources) == len(required):
        status = "complete"
    elif usable_sources:
        status = "partial"
    else:
        status = "unavailable"
    records = tuple(
        sorted(
            (
                {"source_id": source, "records": list(usable_records_by_source[source])}
                for source in usable_sources
            ),
            key=lambda item: item["source_id"],
        )
    )
    digest = semantic_inventory_hash(status, required, missing, records)
    return InventoryObservation(status, required, missing, records, observed_at, digest)


def semantic_inventory_hash(
    status: str,
    required_source_ids: Iterable[str],
    missing_source_ids: Iterable[str],
    normalized_usable_source_records: Iterable[Mapping[str, Any]],
) -> str:
    if status not in {"complete", "partial", "unavailable"}:
        raise ValueError("invalid inventory status")
    payload = {
        "status": status,
        "required_source_ids": sorted(required_source_ids),
        "missing_source_ids": sorted(missing_source_ids),
        "normalized_usable_source_records": list(normalized_usable_source_records),
    }
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _require_aware_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("authoritative timestamps must be timezone-aware")
    if value.astimezone(timezone.utc).utcoffset() != timedelta(0):
        raise ValueError("invalid UTC timestamp")
