"""Shared timestamp contract for host health snapshots and the operator CLI."""

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must be UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def snapshot_freshness(
    payload: Mapping[str, Any], now: datetime, *, expiry_skew_seconds: int = 0,
) -> tuple[int, str, float | None]:
    """Return validator code, reason and age; CLI permits 30s of clock skew.

    The standalone validator retains its strict expiry boundary (exit 4).
    Both callers reject missing, malformed, future or incoherent timestamps.
    """
    age = None
    try:
        generated = timestamp(payload.get("generated_at"))
        age = (now - generated).total_seconds()
        expires = timestamp(payload.get("expires_at"))
        if expires <= generated or expires - generated > timedelta(seconds=300):
            raise ValueError("invalid snapshot lifetime")
    except (TypeError, ValueError, OverflowError):
        return 5, "invalid_snapshot_contract", age
    if generated > now + timedelta(seconds=30):
        return 5, "snapshot_from_future", age
    if now >= expires + timedelta(seconds=expiry_skew_seconds):
        return 4, "snapshot_expired", age
    return 0, "healthy", age
