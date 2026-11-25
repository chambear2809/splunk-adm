"""Strict, bounded contracts for configuration evidence collections."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from .projections import (
    FieldSpec,
    has_projection,
    projection_definition,
    projection_for,
)

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_COLLECTIONS = 10_000
MAX_OBJECTS = 10_000
MAX_TEXT = 512
MAX_LIST_ITEMS = 100
MAX_FIELDS = 100
MAX_COLLECTION_BYTES = 10 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024
MAX_EPOCH = 253_402_300_799
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_COMPARISON_SECONDS = 86_400
VALID_KINDS = {
    "configuration",
    "audit",
    "deployment",
    "operational",
    "monitoring",
    "measurement",
}
VALID_STATUSES = {"complete", "partial", "failed"}
VALID_ENUMERATIONS = {"full", "incremental"}
COLLECTION_KEYS = {
    "schema_version",
    "capture_id",
    "product",
    "authority",
    "source_version",
    "family",
    "partition",
    "scope",
    "started_at",
    "completed_at",
    "received_at",
    "status",
    "permissions_fingerprint",
    "pages_expected",
    "pages_received",
    "source_reference",
    "enumeration",
    "deletions_authoritative",
    "objects",
}
OBJECT_KEYS = {
    "object_id",
    "revision",
    "observed_at",
    "event_at",
    "effective_at",
    "kind",
    "actor",
    "fields",
}

_FORBIDDEN_TEXT_PATTERNS = (
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]{0,15}://"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:password|passwd|secret|token|authorization|api[_-]?key|private[_-]?key)\b\s*[\"']?\s*[:=]"
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
)
_SCHEMELESS_URL_REFERENCE = re.compile(
    r"(?i)(?:\bwww\.[a-z0-9.-]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?=[:/?#]|$))"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ContractError(ValueError):
    """A safe-to-display validation failure that never includes input values."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def _canonical_float(value: float) -> str:
    if not math.isfinite(value):
        fail("invalid_number", "Numbers must be finite.")
    if abs(value) > MAX_EPOCH:
        fail("invalid_number", "Number is outside the supported range.")
    milliseconds = round(value * 1000)
    if value != milliseconds / 1000:
        fail("invalid_number", "Numbers must use millisecond precision or less.")
    if milliseconds == 0:
        return "0"
    sign = "-" if milliseconds < 0 else ""
    whole, fraction = divmod(abs(milliseconds), 1000)
    if fraction == 0:
        return f"{sign}{whole}"
    fraction_text = f"{fraction:03d}".rstrip("0")
    return f"{sign}{whole}.{fraction_text}"


def canonical_json(value: Any) -> bytes:
    """Encode JSON using the shared bounded-decimal-json-v1 byte format.

    Object keys must be ASCII (all contract keys and projected field names are).
    Strings retain Unicode characters and arrays retain their input order.
    Floats must have finite millisecond precision and are emitted without an
    exponent or redundant decimal zeros, matching the browser implementation.
    """

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            if abs(item) > MAX_SAFE_INTEGER:
                fail("invalid_number", "Integer is outside the interoperable range.")
            return str(item)
        if isinstance(item, float):
            return _canonical_float(item)
        if isinstance(item, str):
            _validate_unicode(item)
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(part) for part in item) + "]"
        if isinstance(item, dict):
            if any(not isinstance(key, str) or not key.isascii() for key in item):
                fail("invalid_key", "Object keys must be ASCII text.")
            keys = sorted(item)
            return (
                "{"
                + ",".join(f"{encode(key)}:{encode(item[key])}" for key in keys)
                + "}"
            )
        fail("invalid_json_value", "Value is not supported by the JSON contract.")

    try:
        return encode(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError("invalid_unicode", "Text must be valid Unicode.") from exc


def sha256_hex(value: bytes | Any) -> str:
    """Hash bytes directly or hash a value's canonical JSON encoding."""

    content = value if isinstance(value, bytes) else canonical_json(value)
    return hashlib.sha256(content).hexdigest()


def _validate_unicode(value: str) -> None:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        fail("invalid_unicode", "Text must be valid Unicode.")


def _text(
    value: Any,
    field: str,
    *,
    required: bool = False,
    allow_url: bool = False,
) -> str | None:
    if value is None or value == "":
        if required:
            fail("missing_field", f"{field} is required.")
        return None
    if not isinstance(value, str):
        fail("invalid_field", f"{field} must be text.")
    result = value.strip()
    if not result:
        if required:
            fail("missing_field", f"{field} is required.")
        return None
    if len(result) > MAX_TEXT or _CONTROL_RE.search(result):
        fail("invalid_field", f"{field} is too long or contains control text.")
    _validate_unicode(result)
    if not allow_url and any(
        pattern.search(result) for pattern in _FORBIDDEN_TEXT_PATTERNS
    ):
        fail("unsafe_text", f"{field} contains a disallowed value.")
    if field == "source_reference" and _SCHEMELESS_URL_REFERENCE.search(result):
        fail("unsafe_text", "source_reference must not contain a URL.")
    return result


def _authority(value: Any) -> str:
    """Accept a safe authority ID or canonical HTTPS origin as inert identity."""

    result = _text(value, "authority", required=True, allow_url=True)
    if result is None:
        fail("missing_field", "authority is required.")
    if "://" not in result:
        if any(pattern.search(result) for pattern in _FORBIDDEN_TEXT_PATTERNS):
            fail("unsafe_text", "authority contains a disallowed value.")
        return result
    try:
        parsed = urlsplit(result)
        port = parsed.port
    except ValueError as exc:
        raise ContractError(
            "invalid_authority", "authority is not a canonical HTTPS origin."
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        fail("invalid_authority", "authority is not a canonical HTTPS origin.")
    hostname = parsed.hostname
    if not hostname.isascii() or hostname != hostname.lower():
        fail("invalid_authority", "authority is not a canonical HTTPS origin.")
    if any(char in hostname for char in " %\\"):
        fail("invalid_authority", "authority is not a canonical HTTPS origin.")
    if not re.fullmatch(r"[a-z0-9.-]+", hostname):
        # IPv6 literals use colons and must be bracketed in the source origin.
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ContractError(
                "invalid_authority", "authority is not a canonical HTTPS origin."
            ) from exc
        if address.version != 6 or f"[{hostname}]" not in parsed.netloc:
            fail("invalid_authority", "authority is not a canonical HTTPS origin.")
        hostname = f"[{address.compressed}]"
    elif hostname.endswith(".") or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in hostname.split(".")
    ):
        fail("invalid_authority", "authority is not a canonical HTTPS origin.")
    if port is not None and not 1 <= port <= 65535:
        fail("invalid_authority", "authority is not a canonical HTTPS origin.")
    suffix = f":{port}" if port is not None and port != 443 else ""
    canonical = f"https://{hostname}{suffix}"
    if result != canonical:
        fail("invalid_authority", "authority is not a canonical HTTPS origin.")
    return canonical


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        fail("invalid_boolean", f"{field} must be true or false.")
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail("invalid_integer", f"{field} must be an integer.")
    if value < minimum or value > MAX_SAFE_INTEGER:
        fail("invalid_integer", f"{field} is outside the supported range.")
    return value


def _number(value: Any, field: str, *, required: bool = False) -> float | int | None:
    if value is None:
        if required:
            fail("missing_time", f"{field} is required.")
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail("invalid_time", f"{field} must be a finite UTC epoch number.")
    if not math.isfinite(float(value)) or value < 0 or value > MAX_EPOCH:
        fail("invalid_time", f"{field} is outside the supported timestamp range.")
    # Use the shared exact millisecond representation. Integral values stay ints.
    if isinstance(value, float):
        _canonical_float(value)
        if value.is_integer():
            return int(value)
    return value


def _normalized_field(value: Any, name: str, spec: FieldSpec) -> Any:
    if value is None:
        return None
    if spec.value_type == "authority":
        return _authority(value)
    if spec.value_type == "text":
        return _text(value, name)
    if spec.value_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            fail("invalid_projection", "Projected integer has an invalid value.")
        if abs(value) > MAX_SAFE_INTEGER:
            fail(
                "invalid_projection",
                "Projected integer is outside the supported range.",
            )
        return value
    if spec.value_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            fail("invalid_projection", "Projected number has an invalid value.")
        if isinstance(value, int):
            if abs(value) > MAX_SAFE_INTEGER:
                fail(
                    "invalid_projection",
                    "Projected integer is outside the supported range.",
                )
            return value
        _canonical_float(value)
        return int(value) if value.is_integer() else value
    if spec.value_type == "boolean":
        return _boolean(value, name)
    if spec.value_type == "text_list":
        if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
            fail("invalid_projection", "Projected list has an invalid shape or size.")
        return [_text(item, name, required=True) for item in value]
    if spec.value_type == "integer_list":
        if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
            fail("invalid_projection", "Projected list has an invalid shape or size.")
        result: list[int] = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, int):
                fail("invalid_projection", "Projected list has an invalid item.")
            if abs(item) > MAX_SAFE_INTEGER:
                fail(
                    "invalid_projection",
                    "Projected integer is outside the supported range.",
                )
            result.append(item)
        return result
    fail("invalid_projection", "Projection registry contains an unsupported type.")


def _normalize_fields(value: Any, product: str, family: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_FIELDS:
        fail("invalid_projection", "fields must be a bounded object.")
    registry = projection_for(product, family)
    result: dict[str, Any] = {}
    for name, field_value in value.items():
        if not isinstance(name, str) or name not in registry:
            fail(
                "unknown_projection_field",
                "Normalized input contains an unreviewed field.",
            )
        normalized = _normalized_field(field_value, name, registry[name])
        if not registry[name].ordered and isinstance(normalized, list):
            # Only explicitly reviewed set fields lose order/duplicates. Rule
            # arrays and parallel port arrays keep their declared order.
            normalized = sorted(set(normalized))
        result[name] = normalized
    return {name: result[name] for name in sorted(result)}


def _unknown_keys(value: dict[str, Any], allowed: set[str]) -> None:
    if set(value) - allowed:
        fail("unknown_field", "Input contains an unrecognized field.")


def _normalize_object(value: Any, product: str, family: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("invalid_object", "Every object observation must be an object.")
    _unknown_keys(value, OBJECT_KEYS)
    required = {"object_id", "observed_at", "kind"}
    if required - set(value):
        fail("missing_field", "Object observation is missing a required field.")
    object_id = _text(value.get("object_id"), "object_id", required=True)
    if object_id is None:
        fail("missing_field", "object_id is required.")
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in VALID_KINDS:
        fail("invalid_kind", "kind is not a supported evidence kind.")
    definition = projection_definition(product, family)
    if definition is None or kind not in definition.allowed_kinds:
        fail("invalid_kind", "kind is not allowed for this reviewed projection.")
    if definition.operational_snapshot and any(
        value.get(field) is not None
        for field in ("revision", "event_at", "effective_at", "actor")
    ):
        fail(
            "unsupported_native_snapshot_metadata",
            "Receipt-observed state requires null native revision, times and actor.",
        )
    revision_value = value.get("revision")
    if revision_value is None or revision_value == "":
        revision = None
    elif isinstance(revision_value, bool):
        fail("invalid_revision", "revision must be text or an integer.")
    elif isinstance(revision_value, int):
        if abs(revision_value) > MAX_SAFE_INTEGER:
            fail("invalid_revision", "revision is outside the supported range.")
        revision = str(revision_value)
    else:
        revision = _text(revision_value, "revision")
    return {
        "object_id": object_id,
        "revision": revision,
        "observed_at": _number(value.get("observed_at"), "observed_at", required=True),
        "event_at": _number(value.get("event_at"), "event_at"),
        "effective_at": _number(value.get("effective_at"), "effective_at"),
        "kind": value["kind"],
        "actor": _text(value.get("actor"), "actor"),
        "fields": _normalize_fields(value.get("fields"), product, family),
    }


def normalize_collection(
    value: Any, *, _administrator_ingress: bool = False
) -> dict[str, Any]:
    """Validate and normalize one explicitly versioned collection receipt."""

    if not isinstance(value, dict):
        fail("invalid_collection", "Collection must be an object.")
    _unknown_keys(value, COLLECTION_KEYS)
    missing = (
        COLLECTION_KEYS
        - {"completed_at", "permissions_fingerprint", "source_reference"}
        - set(value)
    )
    if missing:
        fail("missing_field", "Collection is missing a required field.")
    if (
        isinstance(value.get("schema_version"), bool)
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        fail("unsupported_schema", "Collection schema_version is unsupported.")
    capture_id = _text(value.get("capture_id"), "capture_id", required=True)
    product = _text(value.get("product"), "product", required=True)
    authority = _authority(value.get("authority"))
    source_version = _text(value.get("source_version"), "source_version", required=True)
    family = _text(value.get("family"), "family", required=True)
    if (product, family) == (
        "atlas",
        "relationship_attestation",
    ) and _administrator_ingress is not True:
        fail(
            "reserved_administrator_projection",
            "Administrator relationships require the separate trusted ingress.",
        )
    partition = _text(value.get("partition"), "partition", required=True)
    scope = _text(value.get("scope"), "scope", required=True)
    if not has_projection(product, family):
        fail(
            "unsupported_projection",
            "No reviewed projection exists for product and family.",
        )
    status = value.get("status")
    enumeration = value.get("enumeration")
    if not isinstance(status, str) or status not in VALID_STATUSES:
        fail("invalid_status", "status is not supported.")
    if not isinstance(enumeration, str) or enumeration not in VALID_ENUMERATIONS:
        fail("invalid_enumeration", "enumeration is not supported.")
    started_at = _number(value.get("started_at"), "started_at", required=True)
    completed_at = _number(value.get("completed_at"), "completed_at")
    received_at = _number(value.get("received_at"), "received_at", required=True)
    if completed_at is not None and completed_at < started_at:
        fail("invalid_interval", "completed_at must not precede started_at.")
    pages_expected = _integer(value.get("pages_expected"), "pages_expected")
    pages_received = _integer(value.get("pages_received"), "pages_received")
    if pages_received > pages_expected:
        fail("invalid_pages", "pages_received must not exceed pages_expected.")
    if status == "complete":
        if (
            completed_at is None
            or pages_expected == 0
            or pages_received != pages_expected
        ):
            fail(
                "incomplete_receipt",
                "Complete collection requires every page and a completion time.",
            )
        if not partition:
            fail(
                "incomplete_receipt",
                "Complete collection requires an explicit partition.",
            )
    permissions_fingerprint = _text(
        value.get("permissions_fingerprint"), "permissions_fingerprint"
    )
    if status == "complete" and permissions_fingerprint is None:
        fail(
            "incomplete_receipt",
            "Complete collection requires a permission fingerprint.",
        )
    deletions_authoritative = _boolean(
        value.get("deletions_authoritative"), "deletions_authoritative"
    )
    raw_objects = value.get("objects")
    if not isinstance(raw_objects, list):
        fail("invalid_objects", "objects must be an array.")
    if len(raw_objects) > MAX_OBJECTS:
        fail("object_limit", "Input exceeds the 10,000-object limit.")
    objects = [_normalize_object(obj, product, family) for obj in raw_objects]
    definition = projection_definition(product, family)
    if definition is not None and definition.operational_snapshot:
        if deletions_authoritative:
            fail(
                "invalid_deletion_authority",
                "Learned operational snapshots cannot establish deletion authority.",
            )
        if received_at < started_at or (
            completed_at is not None and received_at < completed_at
        ):
            fail("invalid_interval", "Receipt cannot precede its state collection.")
        if any(obj["observed_at"] != received_at for obj in objects):
            fail(
                "invalid_observation_time",
                "Receipt-observed state must use its actual received_at value.",
            )
    objects.sort(
        key=lambda item: (
            item["object_id"],
            item["revision"] or "",
            canonical_json(item),
        )
    )
    if status == "complete":
        object_ids = [obj["object_id"] for obj in objects]
        if len(object_ids) != len(set(object_ids)):
            fail(
                "duplicate_object_id",
                "Complete collection contains duplicate native object IDs.",
            )
    seen_native_revision: dict[tuple[str, str | None], bytes] = {}
    for obj in objects:
        native_key = (obj["object_id"], obj["revision"])
        content = canonical_json(obj)
        previous = seen_native_revision.get(native_key)
        if previous is not None and previous != content:
            fail(
                "conflicting_observation",
                "Collection contains conflicting native revisions.",
            )
        seen_native_revision[native_key] = content
    if status != "complete":
        unique_objects: dict[tuple[str, str | None], dict[str, Any]] = {}
        for obj in objects:
            unique_objects[(obj["object_id"], obj["revision"])] = obj
        objects = sorted(
            unique_objects.values(),
            key=lambda item: (
                item["object_id"],
                item["revision"] or "",
                canonical_json(item),
            ),
        )
    result = {
        "schema_version": SCHEMA_VERSION,
        "capture_id": capture_id,
        "product": product,
        "authority": authority,
        "source_version": source_version,
        "family": family,
        "partition": partition,
        "scope": scope,
        "started_at": started_at,
        "completed_at": completed_at,
        "received_at": received_at,
        "status": status,
        "permissions_fingerprint": permissions_fingerprint,
        "pages_expected": pages_expected,
        "pages_received": pages_received,
        "source_reference": _text(value.get("source_reference"), "source_reference"),
        "enumeration": enumeration,
        "deletions_authoritative": deletions_authoritative,
        "objects": objects,
    }
    if len(canonical_json(result)) > MAX_COLLECTION_BYTES:
        fail("collection_limit", "Normalized collection exceeds the size limit.")
    return result


def normalize_document(value: Any) -> list[dict[str, Any]]:
    """Validate the offline document wrapper and normalize all collections."""

    if not isinstance(value, dict) or set(value) != {"schema_version", "collections"}:
        fail("invalid_document", "Input must contain schema_version and collections.")
    if (
        isinstance(value.get("schema_version"), bool)
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        fail("unsupported_schema", "Document schema_version is unsupported.")
    raw_collections = value.get("collections")
    if not isinstance(raw_collections, list) or not raw_collections:
        fail("invalid_document", "collections must be a nonempty array.")
    if len(raw_collections) > MAX_COLLECTIONS:
        fail("collection_limit", "Input exceeds the collection limit.")
    total_objects = 0
    normalized: list[dict[str, Any]] = []
    for raw in raw_collections:
        collection = normalize_collection(raw)
        total_objects += len(collection["objects"])
        if total_objects > MAX_OBJECTS:
            fail("object_limit", "Input exceeds the 10,000-object limit.")
        normalized.append(collection)
    return normalized


def parse_json_document(content: bytes) -> list[dict[str, Any]]:
    """Parse bounded JSON without exposing malformed or duplicate input values."""

    if len(content) > MAX_INPUT_BYTES:
        fail("input_limit", "Input exceeds the 50 MiB limit.")

    def unique_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                fail("duplicate_key", "Input JSON contains a duplicate object key.")
            result[key] = item
        return result

    try:
        value = json.loads(content.decode("utf-8-sig"), object_pairs_hook=unique_pairs)
    except ContractError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise ContractError("invalid_json", "Could not parse JSON input.") from exc
    return normalize_document(value)


def _iso_to_epoch(value: str) -> float:
    """Reserved for source adapters that explicitly convert native timestamps."""

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("invalid_time", "Timestamp is not valid ISO-8601.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail("invalid_time", "Timestamp must include a UTC offset.")
    return float(
        _number(parsed.astimezone(timezone.utc).timestamp(), "timestamp", required=True)
    )


def _reject_unsafe_keys(value: Any, depth: int = 0) -> None:
    """Ensure future callers cannot accidentally canonicalize nested raw data."""

    if depth > 3:
        fail("nested_value", "Nested input exceeds the supported depth.")
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or not key.isascii():
                fail("invalid_key", "Object keys must be ASCII text.")
            _reject_unsafe_keys(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _reject_unsafe_keys(nested, depth + 1)
