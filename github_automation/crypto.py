"""Normative cryptographic primitives for execution-trust authority v1.

This module intentionally contains no key loading or persistence.  Callers pass
runtime key objects and retain responsibility for keeping private keys outside
the repository/model workspace.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import math
import re
import threading
from typing import Any, Iterable, Mapping
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


ATTESTATION_DOMAIN = b"github-automation/execution-trust-attestation/v1"
KEY_MANIFEST_DOMAIN = b"github-automation/execution-trust-key-manifest/v1"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MAX_SAFE_INTEGER = (1 << 53) - 1
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_UINT = re.compile(r"^(0|[1-9][0-9]*)$")


class CryptoContractError(ValueError):
    """Base class for fail-closed contract violations."""


class CanonicalizationError(CryptoContractError):
    pass


class SignatureContractError(CryptoContractError):
    pass


class ManifestContractError(CryptoContractError):
    pass


class AttestationContractError(CryptoContractError):
    pass


@dataclass(frozen=True)
class ExactAttestationTarget:
    """Fresh authoritative target supplied to each attestation gate."""

    repository_id: str
    repository: str
    pr_number: int
    head_sha: str
    head_generation: str
    local_gate_generation: int

    def validate(self) -> None:
        if not isinstance(self.repository_id, str) or not _CANONICAL_UINT.fullmatch(self.repository_id):
            raise AttestationContractError("target repository_id is not canonical")
        if not isinstance(self.repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository
        ):
            raise AttestationContractError("target repository name is invalid")
        if type(self.pr_number) is not int or self.pr_number < 1:
            raise AttestationContractError("target PR number is invalid")
        if not isinstance(self.head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", self.head_sha):
            raise AttestationContractError("target head SHA is invalid")
        if not isinstance(self.head_generation, str) or not _CANONICAL_UINT.fullmatch(self.head_generation):
            raise AttestationContractError("target head generation is not canonical")
        if type(self.local_gate_generation) is not int or self.local_gate_generation < 1:
            raise AttestationContractError("local gate generation is invalid")


@dataclass(frozen=True)
class AttestationAuthorityDecision:
    valid: bool
    boundary: str
    proof_role: str
    decision_id: str
    attestation_id: str
    envelope_digest: str
    request_linkage_hash: str
    nonce_binding_outcome: str


def parse_ijson(data: str | bytes) -> Any:
    """Parse I-JSON while rejecting duplicate keys and non-finite numbers."""

    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalizationError("I-JSON must be valid UTF-8") from exc

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise CanonicalizationError(f"duplicate object key: {key!r}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        raise CanonicalizationError(f"non-finite number is forbidden: {value}")

    try:
        parsed = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except CanonicalizationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CanonicalizationError("invalid I-JSON") from exc
    canonicalize_jcs(parsed)  # validate safe numbers and Unicode scalar values
    return parsed


def canonicalize_jcs(value: Any) -> bytes:
    """Return RFC 8785-style UTF-8 canonical JSON for strict I-JSON values.

    Integers outside the interoperable IEEE-754 range are rejected. Finite
    floats use ECMAScript-compatible decimal/exponent thresholds; negative zero
    canonicalizes to zero. Object member order follows UTF-16 code units.
    """

    return _canonical_text(value).encode("utf-8", errors="strict")


def _canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer exceeds I-JSON safe range; encode it as a string")
        return str(value)
    if isinstance(value, float):
        return _canonical_float(value)
    if isinstance(value, str):
        _validate_unicode(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalizationError("object keys must be strings")
        keys = list(value)
        for key in keys:
            _validate_unicode(key)
        keys.sort(key=lambda item: item.encode("utf-16-be"))
        return "{" + ",".join(
            f"{json.dumps(key, ensure_ascii=False)}:{_canonical_text(value[key])}" for key in keys
        ) + "}"
    raise CanonicalizationError(f"unsupported I-JSON type: {type(value).__name__}")


def _canonical_float(value: float) -> str:
    if not math.isfinite(value):
        raise CanonicalizationError("non-finite numbers are forbidden")
    if value == 0:
        return "0"
    negative = value < 0
    text = repr(abs(value)).lower()
    mantissa, marker, exponent_text = text.partition("e")
    if marker:
        exponent = int(exponent_text)
        digits = mantissa.replace(".", "").rstrip("0")
        decimal_position = 1 + exponent
        if 1e-6 <= abs(value) < 1e21:
            if decimal_position <= 0:
                rendered = "0." + "0" * (-decimal_position) + digits
            elif decimal_position >= len(digits):
                rendered = digits + "0" * (decimal_position - len(digits))
            else:
                rendered = digits[:decimal_position] + "." + digits[decimal_position:]
        else:
            fraction = digits[1:]
            rendered = digits[0] + (("." + fraction) if fraction else "")
            rendered += "e" + ("+" if exponent >= 0 else "") + str(exponent)
    else:
        rendered = text[:-2] if text.endswith(".0") else text
    return ("-" if negative else "") + rendered


def _validate_unicode(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError("Unicode surrogate code points are forbidden")


def domain_separated_payload(domain: bytes, payload: Mapping[str, Any]) -> bytes:
    if not domain or b"\x00" in domain:
        raise CryptoContractError("domain must be non-empty ASCII without NUL")
    try:
        domain.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise CryptoContractError("domain must be ASCII") from exc
    return domain + b"\x00" + canonicalize_jcs(payload)


def payload_digest(domain: bytes, payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain_separated_payload(domain, payload)).hexdigest()


def manifest_digest(payload: Mapping[str, Any]) -> str:
    return payload_digest(KEY_MANIFEST_DOMAIN, payload)


def public_key_spki(public_key: ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def spki_fingerprint(public_key_or_der: Any) -> str:
    der = public_key_or_der if isinstance(public_key_or_der, bytes) else public_key_spki(public_key_or_der)
    return hashlib.sha256(der).hexdigest()


def encode_base64url_raw64(signature: bytes) -> str:
    if len(signature) != 64:
        raise SignatureContractError("signature must be exactly 64 raw bytes")
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def decode_base64url_raw64(encoded: str) -> bytes:
    if not isinstance(encoded, str) or len(encoded) != 86 or "=" in encoded:
        raise SignatureContractError("signature must be unpadded base64url for 64 raw bytes")
    if not re.fullmatch(r"[A-Za-z0-9_-]{86}", encoded):
        raise SignatureContractError("signature contains invalid base64url characters")
    try:
        raw = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SignatureContractError("invalid base64url signature") from exc
    if len(raw) != 64 or encode_base64url_raw64(raw) != encoded:
        raise SignatureContractError("non-canonical signature encoding")
    return raw


def sign_detached(
    payload: Mapping[str, Any],
    private_key: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
    *,
    domain: bytes = ATTESTATION_DOMAIN,
) -> str:
    message = domain_separated_payload(domain, payload)
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        raw = private_key.sign(message)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(private_key.curve, ec.SECP256R1):
        der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        s = min(s, P256_ORDER - s)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise SignatureContractError("only Ed25519 and P-256 private keys are accepted")
    return encode_base64url_raw64(raw)


def verify_detached(
    payload: Mapping[str, Any],
    signature: str,
    public_key: ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey,
    *,
    domain: bytes = ATTESTATION_DOMAIN,
) -> None:
    raw = decode_base64url_raw64(signature)
    message = domain_separated_payload(domain, payload)
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(raw, message)
        elif isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1):
            r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
            if not 1 <= r < P256_ORDER or not 1 <= s <= P256_ORDER // 2:
                raise SignatureContractError("P-256 signature must be valid low-S P1363")
            public_key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        else:
            raise SignatureContractError("only Ed25519 and P-256 public keys are accepted")
    except InvalidSignature as exc:
        raise SignatureContractError("signature verification failed") from exc


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    key_version: int
    algorithm: str
    public_key_fingerprint: str
    state: str

    @property
    def identity(self) -> tuple[str, int]:
        return self.key_id, self.key_version


@dataclass(frozen=True)
class AuthenticatedManifest:
    payload: Mapping[str, Any]
    signature: str
    generation: int
    digest: str
    keys: Mapping[tuple[str, int], KeyRecord]


@dataclass(frozen=True)
class AuthenticatedManifestChain:
    manifests: tuple[AuthenticatedManifest, ...]

    @property
    def current(self) -> AuthenticatedManifest:
        if not self.manifests:
            raise ManifestContractError("manifest chain is empty")
        return self.manifests[-1]

    def at_issuance(self, generation: str, digest: str) -> AuthenticatedManifest:
        if not _CANONICAL_UINT.fullmatch(generation):
            raise AttestationContractError("issuance manifest generation is not canonical")
        matches = [item for item in self.manifests if item.generation == int(generation)]
        if len(matches) != 1 or matches[0].digest != digest:
            raise AttestationContractError("issuance manifest is not in the authenticated chain")
        return matches[0]


def authenticate_manifest_chain(
    envelopes: Iterable[Mapping[str, Any]],
    root_public_key: ed25519.Ed25519PublicKey,
    *,
    pinned_root_fingerprint: str,
    minimum_generation: int | None = None,
    minimum_digest: str | None = None,
) -> AuthenticatedManifestChain:
    if not isinstance(root_public_key, ed25519.Ed25519PublicKey):
        raise ManifestContractError("offline root verifier must be Ed25519")
    if spki_fingerprint(root_public_key) != pinned_root_fingerprint:
        raise ManifestContractError("offline root fingerprint mismatch")
    authenticated: list[AuthenticatedManifest] = []
    previous: AuthenticatedManifest | None = None
    for envelope in envelopes:
        if set(envelope) != {"payload", "signature"} or not isinstance(envelope["payload"], Mapping):
            raise ManifestContractError("manifest envelope must contain only payload and detached signature")
        payload, signature = envelope["payload"], envelope["signature"]
        try:
            verify_detached(payload, signature, root_public_key, domain=KEY_MANIFEST_DOMAIN)
        except (CryptoContractError, TypeError) as exc:
            raise ManifestContractError("offline root signature is invalid") from exc
        generation, keys = _validate_manifest_payload(payload, pinned_root_fingerprint)
        digest = manifest_digest(payload)
        expected_generation = 1 if previous is None else previous.generation + 1
        expected_predecessor = None if previous is None else previous.digest
        if generation != expected_generation or payload["previous_manifest_digest"] != expected_predecessor:
            raise ManifestContractError("manifest chain has a rollback, skip, conflict, or missing predecessor")
        current = AuthenticatedManifest(payload, signature, generation, digest, keys)
        if previous is not None:
            _validate_key_transition(previous.keys, current.keys)
            if _parse_utc(payload["issued_at"], field="issued_at") < _parse_utc(
                previous.payload["issued_at"], field="issued_at"
            ):
                raise ManifestContractError("manifest issued_at moved backwards")
        authenticated.append(current)
        previous = current
    if not authenticated:
        raise ManifestContractError("manifest chain is unavailable")
    highest = authenticated[-1]
    if minimum_generation is not None and highest.generation < minimum_generation:
        raise ManifestContractError("manifest rollback below persisted highest generation")
    if minimum_generation is not None and minimum_digest is not None:
        persisted = next((item for item in authenticated if item.generation == minimum_generation), None)
        if persisted is None or persisted.digest != minimum_digest:
            raise ManifestContractError("conflicting manifest at persisted highest generation")
    return AuthenticatedManifestChain(tuple(authenticated))


def _validate_manifest_payload(
    payload: Mapping[str, Any], root_fingerprint: str
) -> tuple[int, dict[tuple[str, int], KeyRecord]]:
    required = {
        "execution_trust_key_manifest_version", "manifest_generation", "previous_manifest_digest",
        "issued_at", "offline_root_public_fingerprint", "keys",
    }
    if set(payload) != required or payload["execution_trust_key_manifest_version"] != 1:
        raise ManifestContractError("invalid key manifest v1 payload shape")
    generation_text = payload["manifest_generation"]
    if not isinstance(generation_text, str) or not re.fullmatch(r"[1-9][0-9]*", generation_text):
        raise ManifestContractError("manifest_generation must be a canonical positive string")
    if payload["offline_root_public_fingerprint"] != root_fingerprint:
        raise ManifestContractError("manifest root fingerprint mismatch")
    previous = payload["previous_manifest_digest"]
    if previous is not None and (not isinstance(previous, str) or not _HEX_256.fullmatch(previous)):
        raise ManifestContractError("invalid previous_manifest_digest")
    _parse_utc(payload["issued_at"], field="issued_at")
    if not isinstance(payload["keys"], list) or not payload["keys"]:
        raise ManifestContractError("manifest keys must be a non-empty list")
    keys: dict[tuple[str, int], KeyRecord] = {}
    for raw in payload["keys"]:
        if not isinstance(raw, Mapping) or set(raw) != {
            "key_id", "key_version", "algorithm", "public_key_fingerprint", "state"
        }:
            raise ManifestContractError("invalid manifest key entry")
        record = KeyRecord(**raw)
        if (
            not isinstance(record.key_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", record.key_id)
            or type(record.key_version) is not int or record.key_version < 1
            or record.algorithm not in {"Ed25519", "platform-native-P256"}
            or not isinstance(record.public_key_fingerprint, str)
            or not _HEX_256.fullmatch(record.public_key_fingerprint)
            or record.state not in {"active", "retiring", "revoked"}
            or record.identity in keys
        ):
            raise ManifestContractError("invalid or duplicate manifest key entry")
        keys[record.identity] = record
    return int(generation_text), keys


def _validate_key_transition(
    previous: Mapping[tuple[str, int], KeyRecord], current: Mapping[tuple[str, int], KeyRecord]
) -> None:
    allowed = {
        "active": {"active", "retiring", "revoked"},
        "retiring": {"retiring", "revoked"},
        "revoked": {"revoked"},
    }
    for identity, old in previous.items():
        new = current.get(identity)
        if new is None:
            raise ManifestContractError("manifest omitted an existing key version")
        if (old.algorithm, old.public_key_fingerprint) != (new.algorithm, new.public_key_fingerprint):
            raise ManifestContractError("immutable key metadata changed")
        if new.state not in allowed[old.state]:
            raise ManifestContractError("key state rollback/reactivation is forbidden")
    if any(record.state != "active" for identity, record in current.items() if identity not in previous):
        raise ManifestContractError("a newly introduced key version must be active")


def authorize_key_for_issuance(
    chain: AuthenticatedManifestChain, key_id: str, key_version: int
) -> KeyRecord:
    record = chain.current.keys.get((key_id, key_version))
    if record is None or record.state != "active":
        raise AttestationContractError("only a currently active key may sign a new proof")
    return record


def verify_attestation(
    envelope: Mapping[str, Any],
    chain: AuthenticatedManifestChain,
    public_keys: Mapping[tuple[str, int], ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey],
    *,
    now: datetime,
) -> Mapping[str, Any]:
    """Verify signature plus issuance/current key-state and expiry contracts.

    Exact target, inventory and GateStore-generation comparison remains a caller
    gate concern because those values require fresh authoritative observations.
    """

    if set(envelope) != {"payload", "signature"} or not isinstance(envelope["payload"], Mapping):
        raise AttestationContractError("attestation envelope must contain only payload and signature")
    payload, signature = envelope["payload"], envelope["signature"]
    issued_at, expires_at = _validate_attestation_payload(payload)
    _require_utc(now)
    if issued_at > now or not now < expires_at:
        raise AttestationContractError("attestation is not yet valid or is expired")
    identity = (payload.get("key_id"), payload.get("key_version"))
    issuance = chain.at_issuance(
        payload.get("key_manifest_generation_at_issuance", ""),
        payload.get("key_manifest_digest_at_issuance", ""),
    )
    issued_record = issuance.keys.get(identity)
    current_record = chain.current.keys.get(identity)
    if issued_record is None or issued_record.state != "active":
        raise AttestationContractError("key was not active in the authenticated issuance manifest")
    if current_record is None or current_record.state not in {"active", "retiring"}:
        raise AttestationContractError("key is currently revoked or unknown")
    public_key = public_keys.get(identity)
    if public_key is None:
        raise AttestationContractError("public verifier key is unavailable")
    algorithm = payload.get("algorithm")
    algorithm_matches = (
        algorithm == "Ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey)
    ) or (
        algorithm == "platform-native-P256"
        and isinstance(public_key, ec.EllipticCurvePublicKey)
        and isinstance(public_key.curve, ec.SECP256R1)
    )
    if not algorithm_matches or issued_record.algorithm != algorithm or current_record.algorithm != algorithm:
        raise AttestationContractError("attestation algorithm/key mismatch")
    fingerprint = spki_fingerprint(public_key)
    if any(record.public_key_fingerprint != fingerprint for record in (issued_record, current_record)):
        raise AttestationContractError("manifest public-key fingerprint mismatch")
    if payload.get("public_key_fingerprint") != fingerprint:
        raise AttestationContractError("attestation public-key fingerprint mismatch")
    issuance_manifest_time = _parse_utc(issuance.payload["issued_at"], field="issued_at")
    if issued_at < issuance_manifest_time:
        raise AttestationContractError("proof predates its issuance manifest")
    if current_record.state == "retiring":
        retirement = next(
            item for item in chain.manifests
            if item.generation > issuance.generation
            and item.keys.get(identity) is not None
            and item.keys[identity].state != "active"
        )
        if not issued_at < _parse_utc(retirement.payload["issued_at"], field="issued_at"):
            raise AttestationContractError("retiring key proof was not issued before the transition")
    try:
        verify_detached(payload, signature, public_key, domain=ATTESTATION_DOMAIN)
    except (CryptoContractError, TypeError) as exc:
        raise AttestationContractError("attestation signature is invalid") from exc
    return payload


def _validate_attestation_payload(payload: Mapping[str, Any]) -> tuple[datetime, datetime]:
    required = {
        "attestation_schema_version", "execution_trust_policy_version",
        "execution_trust_attestation_authority_version", "execution_trust_key_manifest_version",
        "key_manifest_generation_at_issuance", "key_manifest_digest_at_issuance", "attestation_id",
        "algorithm", "key_id", "key_version", "public_key_fingerprint", "repository_id",
        "repository", "pr_number", "head_sha", "head_generation", "inventory_guard_status",
        "missing_source_ids", "effective_writer_inventory_hash",
        "inventory_guard_freshness_policy_version", "inventory_observed_at_at_issuance",
        "issued_at", "expires_at", "nonce", "request_linkage_hash",
    }
    if set(payload) != required:
        raise AttestationContractError("invalid exact-SHA attestation v1 payload shape")
    for field in (
        "attestation_schema_version", "execution_trust_policy_version",
        "execution_trust_attestation_authority_version", "execution_trust_key_manifest_version",
        "inventory_guard_freshness_policy_version",
    ):
        if payload[field] != 1 or type(payload[field]) is not int:
            raise AttestationContractError(f"unsupported {field}")
    for field in ("key_manifest_generation_at_issuance", "repository_id", "head_generation"):
        if not isinstance(payload[field], str) or not _CANONICAL_UINT.fullmatch(payload[field]):
            raise AttestationContractError(f"{field} must be a canonical unsigned string")
    for field in (
        "key_manifest_digest_at_issuance", "public_key_fingerprint",
        "effective_writer_inventory_hash", "request_linkage_hash",
    ):
        if not isinstance(payload[field], str) or not _HEX_256.fullmatch(payload[field]):
            raise AttestationContractError(f"invalid {field}")
    try:
        attestation_uuid = UUID(payload["attestation_id"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise AttestationContractError("invalid attestation_id") from exc
    if attestation_uuid.version != 7 or str(attestation_uuid) != payload["attestation_id"]:
        raise AttestationContractError("attestation_id must be a canonical UUIDv7")
    if payload["algorithm"] not in {"Ed25519", "platform-native-P256"}:
        raise AttestationContractError("invalid attestation algorithm")
    if not isinstance(payload["key_id"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", payload["key_id"]):
        raise AttestationContractError("invalid key_id")
    if type(payload["key_version"]) is not int or payload["key_version"] < 1:
        raise AttestationContractError("invalid key_version")
    if not isinstance(payload["repository"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", payload["repository"]
    ):
        raise AttestationContractError("invalid exact repository")
    if type(payload["pr_number"]) is not int or payload["pr_number"] < 1:
        raise AttestationContractError("invalid pr_number")
    if not isinstance(payload["head_sha"], str) or not re.fullmatch(r"[0-9a-f]{40}", payload["head_sha"]):
        raise AttestationContractError("invalid head_sha")
    status, missing = payload["inventory_guard_status"], payload["missing_source_ids"]
    if (
        status not in {"complete", "partial"} or not isinstance(missing, list)
        or any(not isinstance(item, str) or not item for item in missing)
        or missing != sorted(set(missing))
        or (status == "complete" and missing)
        or (status == "partial" and not missing)
    ):
        raise AttestationContractError("invalid inventory guard status/missing set")
    if not isinstance(payload["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", payload["nonce"]):
        raise AttestationContractError("nonce must be canonical unpadded base64url")
    try:
        nonce = base64.b64decode(payload["nonce"] + "=", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AttestationContractError("invalid nonce") from exc
    if len(nonce) != 32:
        raise AttestationContractError("nonce must encode exactly 256 bits")
    _parse_utc(payload["inventory_observed_at_at_issuance"], field="inventory_observed_at_at_issuance")
    issued_at = _parse_utc(payload["issued_at"], field="issued_at")
    expires_at = _parse_utc(payload["expires_at"], field="expires_at")
    if not issued_at < expires_at or expires_at - issued_at > timedelta(minutes=90):
        raise AttestationContractError("attestation validity must be positive and at most 90 minutes")
    return issued_at, expires_at


@dataclass(frozen=True)
class NonceBinding:
    attestation_id: str
    nonce_hash: str
    logical_key: str
    generation: int
    expected_head_generation: str
    envelope_digest: str


class NonceBindingStore:
    """Thread-safe reference nonce binding with exact idempotency semantics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_attestation: dict[str, NonceBinding] = {}
        self._by_nonce: dict[str, NonceBinding] = {}

    def bind(self, binding: NonceBinding) -> str:
        if not binding.attestation_id or not binding.nonce_hash or not binding.logical_key:
            raise AttestationContractError("nonce binding identity fields are required")
        with self._lock:
            existing = self._by_attestation.get(binding.attestation_id) or self._by_nonce.get(binding.nonce_hash)
            if existing is None:
                self._by_attestation[binding.attestation_id] = binding
                self._by_nonce[binding.nonce_hash] = binding
                return "bound"
            if existing == binding:
                return "idempotent"
            if (
                existing.logical_key == binding.logical_key
                and (
                    existing.generation != binding.generation
                    or existing.expected_head_generation != binding.expected_head_generation
                )
            ):
                return "generation_mismatch"
            return "replay"

    def require(self, binding: NonceBinding) -> str:
        """Require a pre-dispatch binding without creating one at later gates."""

        with self._lock:
            existing = self._by_attestation.get(binding.attestation_id)
            nonce_existing = self._by_nonce.get(binding.nonce_hash)
            if existing is None or nonce_existing is None:
                return "unbound"
            if existing == binding and nonce_existing == binding:
                return "idempotent"
            if (
                existing.logical_key == binding.logical_key
                and (
                    existing.generation != binding.generation
                    or existing.expected_head_generation != binding.expected_head_generation
                )
            ):
                return "generation_mismatch"
            return "replay"


def verify_attestation_authority(
    envelope: Mapping[str, Any],
    chain: AuthenticatedManifestChain,
    public_keys: Mapping[tuple[str, int], ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey],
    *,
    target: ExactAttestationTarget,
    inventory_status: str,
    inventory_missing_source_ids: Iterable[str],
    inventory_semantic_hash: str,
    inventory_observed_at: datetime,
    now: datetime,
    boundary: str,
    nonce_store: NonceBindingStore,
) -> AttestationAuthorityDecision:
    """Apply the complete current-authority predicate at one local gate.

    The caller supplies freshly authenticated GitHub/GateStore observations;
    this function exact-compares all signed authority fields, verifies their
    freshness, signature, manifest state and expiry, then enforces nonce
    binding. Request linkage is returned for audit and is never compared to an
    external value or used as an independent authorization predicate.
    """

    allowed_boundaries = {"pre-dispatch", "pre-claim", "pre-marker", "local-success"}
    if boundary not in allowed_boundaries:
        raise AttestationContractError("unknown current-authority boundary")
    target.validate()
    _require_utc(now)
    _require_utc(inventory_observed_at)
    inventory_age = now - inventory_observed_at
    if inventory_age < timedelta(0) or inventory_age > timedelta(minutes=5):
        raise AttestationContractError("current inventory observation is not fresh")
    missing = tuple(inventory_missing_source_ids)
    if (
        inventory_status not in {"complete", "partial"}
        or any(not isinstance(item, str) or not item for item in missing)
        or missing != tuple(sorted(set(missing)))
        or (inventory_status == "complete" and missing)
        or (inventory_status == "partial" and not missing)
        or not isinstance(inventory_semantic_hash, str)
        or not _HEX_256.fullmatch(inventory_semantic_hash)
    ):
        raise AttestationContractError("current inventory observation is invalid")

    payload = verify_attestation(envelope, chain, public_keys, now=now)
    exact_expected = {
        "repository_id": target.repository_id,
        "repository": target.repository,
        "pr_number": target.pr_number,
        "head_sha": target.head_sha,
        "head_generation": target.head_generation,
        "inventory_guard_status": inventory_status,
        "missing_source_ids": list(missing),
        "effective_writer_inventory_hash": inventory_semantic_hash,
    }
    for field, expected in exact_expected.items():
        if payload[field] != expected:
            raise AttestationContractError(f"current authority mismatch: {field}")

    envelope_hash = attestation_envelope_digest(envelope)
    nonce_hash = hashlib.sha256(_decode_nonce(payload["nonce"])).hexdigest()
    binding = NonceBinding(
        attestation_id=payload["attestation_id"],
        nonce_hash=nonce_hash,
        logical_key=f"{target.repository_id}:{target.pr_number}:{target.head_sha}",
        generation=target.local_gate_generation,
        expected_head_generation=target.head_generation,
        envelope_digest=envelope_hash,
    )
    binding_outcome = nonce_store.bind(binding) if boundary == "pre-dispatch" else nonce_store.require(binding)
    if binding_outcome not in {"bound", "idempotent"}:
        raise AttestationContractError(f"attestation nonce rejected: {binding_outcome}")

    decision_payload = {
        "boundary": boundary,
        "attestation_id": payload["attestation_id"],
        "envelope_digest": envelope_hash,
        "local_gate_generation": target.local_gate_generation,
        "inventory_observed_at": inventory_observed_at.isoformat(),
    }
    return AttestationAuthorityDecision(
        valid=True,
        boundary=boundary,
        proof_role="current_authority_for_success",
        decision_id=hashlib.sha256(canonicalize_jcs(decision_payload)).hexdigest(),
        attestation_id=payload["attestation_id"],
        envelope_digest=envelope_hash,
        request_linkage_hash=payload["request_linkage_hash"],
        nonce_binding_outcome=binding_outcome,
    )


def attestation_envelope_digest(envelope: Mapping[str, Any]) -> str:
    """Digest the canonical transport envelope; distinct from payload/manifest digests."""

    return hashlib.sha256(canonicalize_jcs(envelope)).hexdigest()


def _decode_nonce(value: str) -> bytes:
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AttestationContractError("invalid nonce") from exc
    if len(raw) != 32:
        raise AttestationContractError("nonce must encode exactly 256 bits")
    return raw


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CryptoContractError(f"{field} must be a canonical UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CryptoContractError(f"invalid {field}") from exc
    _require_utc(parsed)
    return parsed


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise CryptoContractError("authoritative time must be timezone-aware UTC")
    if value.astimezone(timezone.utc).utcoffset().total_seconds() != 0:
        raise CryptoContractError("invalid UTC timestamp")
