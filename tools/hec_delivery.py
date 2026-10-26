#!/usr/bin/env python3
"""Queue finalized Atlas HEC captures and deliver them with bounded replay.

The sender is intentionally at-least-once. HEC can accept a batch before this
process durably records that response, so a restart can replay the batch. It
never follows redirects with the HEC authorization header and never disables
TLS verification.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Literal, Mapping
from urllib.parse import quote, urlsplit, urlunsplit
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPOOL_MAX_BYTES = 1_073_741_824
SPOOL_MAX_PENDING_CAPTURES = 10_000
SPOOL_MAX_PENDING_RECORDS = 1_000_000
CAPTURE_MAX_RECORDS = 10_000
CAPTURE_MAX_BYTES = 67_108_864
BATCH_MAX_BYTES = 262_144
LINE_MAX_BYTES = 65_535
HTTP_TIMEOUT_SECONDS = 30
HTTP_ATTEMPTS = 3
DEFAULT_ACK_WAIT_SECONDS = 30
DEFAULT_ACK_POLL_SECONDS = 2
MAX_SEND_CAPTURES_PER_RUN = 100
MAX_SEND_SECONDS_PER_RUN = 300


class DeliveryError(RuntimeError):
    """Safe-to-display sender failure that never includes token or source data."""


class CaptureConflictError(DeliveryError):
    """A capture or snapshot ID was reused for different source bytes."""


class SpoolCapacityError(DeliveryError):
    """A bounded spool has no capacity for a new capture."""

    def __init__(self, capacity_kind: str, message: str):
        self.capacity_kind = capacity_kind
        super().__init__(message)


class SpoolBusyError(DeliveryError):
    """Another sender or queue operation currently owns the spool lock."""


class _DuplicateJSONKeyError(ValueError):
    pass


@dataclass(frozen=True)
class QueueReceipt:
    capture_key: str
    capture_key_field: str
    source_id: str
    queued_path: str
    record_count: int
    byte_count: int
    duplicate: bool


@dataclass(frozen=True)
class DeliverySummary:
    attempted_captures: int
    http_accepted_captures: int
    indexer_acknowledged_captures: int
    failed_captures: int
    pending_captures: int
    pending_records: int
    pending_bytes: int
    status: str


@dataclass(frozen=True)
class SpoolStatus:
    pending_captures: int
    pending_records: int
    pending_bytes: int
    http_accepted_unverified: int
    indexer_acknowledged_not_searchable: int
    quarantined_captures: int
    checkpoint_recoveries: int
    oldest_pending_age_seconds: int | None
    capacity_bytes: int
    capacity_captures: int
    capacity_records: int
    used_bytes: int


@dataclass(frozen=True)
class _Capture:
    capture_key: str
    capture_key_field: str
    source_id: str
    digest: str
    content: bytes
    lines: tuple[bytes, ...]


def _safe_source_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
        raise DeliveryError("Invalid source identifier.")
    return value


def _literal_capture_key(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DeliveryError("Capture lacks one valid capture_id or snapshot_id.")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("Non-standard JSON number")


def _read_capture_file(source_path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(source_path, flags)
    except OSError:
        raise DeliveryError("Capture path must be a readable regular file.") from None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise DeliveryError("Capture path must be a regular file.")
            if before.st_size <= 0 or before.st_size > CAPTURE_MAX_BYTES:
                raise DeliveryError("Capture exceeds the configured byte limit.")
            content = handle.read(CAPTURE_MAX_BYTES + 1)
            after = os.fstat(handle.fileno())
    except DeliveryError:
        raise
    except OSError:
        raise DeliveryError("Capture file could not be read.") from None
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        len(content) > CAPTURE_MAX_BYTES
        or len(content) != before.st_size
        or identity_before != identity_after
    ):
        raise DeliveryError("Capture changed or exceeded the configured byte limit.")
    return content


def _read_bounded_file(path: Path, maximum: int) -> bytes | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError:
        raise DeliveryError("Spool checkpoint path is invalid.") from None
    try:
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                return None
            content = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        raise DeliveryError("Spool checkpoint path is invalid.") from None
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        len(content) > maximum
        or len(content) != before.st_size
        or before_identity != after_identity
    ):
        return None
    return content


def _resolved_spool(path: Path) -> Path:
    if not isinstance(path, Path):
        path = Path(path)
    if path.is_symlink():
        raise DeliveryError("Spool directory must not be a symbolic link.")
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        for ancestor in (resolved, *resolved.parents):
            marker = ancestor / ".git"
            if marker.exists() or marker.is_symlink():
                raise DeliveryError(
                    "Spool directory must be outside every Git checkout."
                )
        return resolved
    raise DeliveryError("Spool directory must be outside the repository.")


def _ensure_spool(path: Path) -> Path:
    spool = _resolved_spool(path)
    spool.mkdir(mode=0o700, parents=True, exist_ok=True)
    if spool.is_symlink() or not spool.is_dir():
        raise DeliveryError("Spool path is not a directory.")
    try:
        if spool.stat().st_uid != os.geteuid():
            raise DeliveryError("Spool directory must be owned by this user.")
        os.chmod(spool, 0o700)
    except OSError:
        raise DeliveryError("Spool permissions are unavailable.") from None
    for name in ("pending", "accepted", "quarantine", "checkpoints"):
        child = spool / name
        if child.is_symlink():
            raise DeliveryError("Spool state directory must not be a symbolic link.")
        child.mkdir(mode=0o700, exist_ok=True)
        if not child.is_dir():
            raise DeliveryError("Spool state path is not a directory.")
        os.chmod(child, 0o700)
    return spool


class _SpoolLock:
    def __init__(self, spool: Path):
        self.path = spool / ".lock"
        self.handle: Any = None

    def __enter__(self) -> "_SpoolLock":
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        self.handle = os.fdopen(descriptor, "r+b")
        os.chmod(self.path, 0o600)
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.close()
            self.handle = None
            raise SpoolBusyError(
                "Spool is busy; operation can be retried after the active run finishes."
            ) from None
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()


def _load_capture(source_path: Path, source_id: str) -> _Capture:
    source_id = _safe_source_id(source_id)
    content = _read_capture_file(source_path)
    if not content.endswith(b"\n"):
        raise DeliveryError("Capture is truncated or lacks a final newline.")
    split_lines = content.splitlines()
    if not split_lines or any(not line for line in split_lines):
        raise DeliveryError("Capture contains an empty JSONL record.")
    lines = tuple(split_lines)
    if len(lines) > CAPTURE_MAX_RECORDS:
        raise DeliveryError("Capture exceeds the configured record limit.")
    capture_key: str | None = None
    capture_key_field: str | None = None
    for line in lines:
        if len(line) > LINE_MAX_BYTES:
            raise DeliveryError("Capture contains an oversized record.")
        try:
            envelope = json.loads(
                line,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ):
            raise DeliveryError("Capture contains invalid JSON.") from None
        if not isinstance(envelope, dict) or not isinstance(
            envelope.get("event"), dict
        ):
            raise DeliveryError("Capture must contain structured HEC event envelopes.")
        timestamp = envelope.get("time")
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp)
            or timestamp < 0
            or not isinstance(envelope.get("source"), str)
            or not envelope["source"]
            or len(envelope["source"]) > 255
            or not isinstance(envelope.get("sourcetype"), str)
            or not envelope["sourcetype"]
            or len(envelope["sourcetype"]) > 255
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in envelope["source"] + envelope["sourcetype"]
            )
            or (
                "host" in envelope
                and (
                    not isinstance(envelope["host"], str)
                    or not envelope["host"]
                    or len(envelope["host"]) > 255
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for character in envelope["host"]
                    )
                )
            )
        ):
            raise DeliveryError("Capture envelope is missing required HEC fields.")
        event = envelope["event"]
        supplied_keys = [
            (name, _literal_capture_key(event[name]))
            for name in ("capture_id", "snapshot_id")
            if name in event
        ]
        if not supplied_keys:
            raise DeliveryError("Capture lacks one valid capture_id or snapshot_id.")
        if len({value for _, value in supplied_keys}) != 1:
            raise DeliveryError(
                "Capture event has conflicting capture_id and snapshot_id."
            )
        current_field, current = supplied_keys[0]
        if capture_key is None:
            capture_key = current
            capture_key_field = current_field
        elif current != capture_key:
            raise DeliveryError(
                "Capture rows do not share one capture_id or snapshot_id."
            )
        record_id = event.get("record_id")
        if record_id is not None and (
            not isinstance(record_id, str)
            or not record_id
            or len(record_id) > 512
            or any(
                ord(character) < 32 or ord(character) == 127 for character in record_id
            )
        ):
            raise DeliveryError("Capture contains an invalid record_id.")
    assert capture_key is not None and capture_key_field is not None
    return _Capture(
        capture_key=capture_key,
        capture_key_field=capture_key_field,
        source_id=source_id,
        digest=hashlib.sha256(content).hexdigest(),
        content=content,
        lines=lines,
    )


def _capture_tag(capture_key: str) -> str:
    return hashlib.sha256(capture_key.encode("utf-8")).hexdigest()[:32]


def _capture_path(spool: Path, capture: _Capture, status: str = "pending") -> Path:
    return (
        spool
        / status
        / f"{capture.source_id}-{_capture_tag(capture.capture_key)}-{capture.digest}.ndjson"
    )


def _checkpoint_path(
    spool: Path, source_id: str, capture_key: str, digest: str
) -> Path:
    return (
        spool / "checkpoints" / f"{source_id}-{_capture_tag(capture_key)}-{digest}.json"
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    spool = path.parent.parent
    if _all_spool_bytes(spool) + len(content) > SPOOL_MAX_BYTES:
        raise SpoolCapacityError(
            "total_spool_bytes",
            "Spool byte limit reached; existing entries were preserved.",
        )
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".partial",
            delete=False,
        ) as handle:
            temporary = handle.name
            os.chmod(temporary, mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _checkpoint_template(capture: _Capture, path: Path) -> dict[str, Any]:
    try:
        queued_at = int(path.stat().st_mtime)
    except OSError:
        queued_at = int(time.time())
    return {
        "version": 1,
        "source_id": capture.source_id,
        "capture_key": capture.capture_key,
        "capture_key_field": capture.capture_key_field,
        "capture_digest": capture.digest,
        "capture_file": path.name,
        "record_count": len(capture.lines),
        "byte_count": len(capture.content),
        "next_record_index": 0,
        "accepted_batches": 0,
        "status": "pending",
        "http_accepted_unverified": False,
        "indexer_acknowledged": False,
        "ack_channel": None,
        "ack_id": None,
        "ack_batch_end": None,
        "ack_mode": None,
        "checkpoint_recovered": False,
        "last_error_code": None,
        "delivery_endpoint": None,
        "queued_at": queued_at,
        "updated_at": int(time.time()),
    }


def _checkpoint_checksum(state: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in state.items() if key != "checksum"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_checkpoint(path: Path, state: Mapping[str, Any]) -> None:
    _atomic_write(path, _checkpoint_content(state))


def _checkpoint_content(state: Mapping[str, Any]) -> bytes:
    updated = dict(state)
    updated["updated_at"] = int(time.time())
    updated.pop("checksum", None)
    updated["checksum"] = _checkpoint_checksum(updated)
    return (
        json.dumps(
            updated, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        + b"\n"
    )


def _read_checkpoint(path: Path) -> dict[str, Any] | None:
    raw = _read_bounded_file(path, 65_536)
    if raw is None or not raw.endswith(b"\n"):
        return None
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if (
        not isinstance(parsed, dict)
        or isinstance(parsed.get("version"), bool)
        or parsed.get("version") != 1
        or parsed.get("checksum") != _checkpoint_checksum(parsed)
    ):
        return None
    return parsed


def _store_capture(spool: Path, capture: _Capture, *, area: str = "pending") -> Path:
    destination = _capture_path(spool, capture, area)
    if destination.is_symlink():
        raise DeliveryError("Spool capture path is invalid.")
    if destination.exists():
        if not destination.is_file():
            raise DeliveryError("Spool capture path is invalid.")
        return destination
    if _all_spool_bytes(spool) + 2 * len(capture.content) > SPOOL_MAX_BYTES:
        raise SpoolCapacityError(
            "total_spool_bytes",
            "Spool byte limit reached; finalized input remains at its source path.",
        )
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".partial",
            delete=False,
        ) as handle:
            temporary = handle.name
            os.chmod(temporary, 0o600)
            handle.write(capture.content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, destination)
        os.unlink(temporary)
        temporary = None
        _fsync_directory(destination.parent)
    except FileExistsError:
        pass
    except OSError:
        raise DeliveryError(
            "Capture could not be committed to the private spool."
        ) from None
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def _checkpoint_matches(state: Mapping[str, Any], capture: _Capture) -> bool:
    return (
        state.get("source_id") == capture.source_id
        and state.get("capture_key") == capture.capture_key
        and state.get("capture_key_field") == capture.capture_key_field
        and state.get("capture_digest") == capture.digest
        and state.get("record_count") == len(capture.lines)
        and state.get("byte_count") == len(capture.content)
        and (
            state.get("delivery_endpoint") is None
            or isinstance(state.get("delivery_endpoint"), str)
        )
    )


def _terminal_checkpoint(state: Mapping[str, Any], capture: _Capture) -> bool:
    batch_count = len(_record_batches(capture.lines))
    next_index = state.get("next_record_index")
    accepted_batches = state.get("accepted_batches")
    if (
        isinstance(next_index, bool)
        or not isinstance(next_index, int)
        or next_index != len(capture.lines)
        or isinstance(accepted_batches, bool)
        or not isinstance(accepted_batches, int)
        or accepted_batches != batch_count
        or state.get("ack_id") is not None
        or state.get("ack_batch_end") is not None
    ):
        return False
    if state.get("ack_mode") == "off":
        return (
            state.get("status") == "http_accepted_unverified"
            and state.get("http_accepted_unverified") is True
            and state.get("indexer_acknowledged") is False
        )
    if state.get("ack_mode") == "enterprise":
        return (
            state.get("status") == "indexer_acknowledged_not_searchable"
            and state.get("indexer_acknowledged") is True
        )
    return False


def _all_spool_bytes(spool: Path) -> int:
    total = 0
    for path in spool.rglob("*"):
        if path.is_symlink():
            raise DeliveryError("Spool contains a symbolic link.")
        if path.is_file():
            total += path.stat().st_size
    return total


def _pending_counts(spool: Path) -> tuple[int, int, int]:
    captures = records = byte_count = 0
    for path in (spool / "pending").glob("*.ndjson"):
        if path.is_symlink() or not path.is_file():
            raise DeliveryError("Pending spool entry is invalid.")
        captures += 1
        byte_count += path.stat().st_size
        checkpoint = spool / "checkpoints" / f"{path.stem}.json"
        state = _read_checkpoint(checkpoint)
        if (
            state
            and isinstance(state.get("record_count"), int)
            and not isinstance(state.get("record_count"), bool)
        ):
            records += max(0, state["record_count"])
        else:
            with path.open("rb") as handle:
                records += sum(1 for line in handle if line.strip())
    return captures, records, byte_count


def enqueue_capture(
    source_path: Path,
    spool_dir: Path,
    *,
    source_id: str,
) -> QueueReceipt:
    """Durably add one finalized JSONL capture; never remove its input file."""
    capture = _load_capture(Path(source_path), source_id)
    spool = _ensure_spool(Path(spool_dir))
    target = _capture_path(spool, capture)
    checkpoint = _checkpoint_path(
        spool, capture.source_id, capture.capture_key, capture.digest
    )
    with _SpoolLock(spool):
        checkpoint_reservation = len(
            _checkpoint_content(_checkpoint_template(capture, target))
        )
        # A capture identity is immutable. If a retry changes source bytes,
        # preserve the conflict evidence separately and refuse to send it.
        for area in ("pending", "accepted", "quarantine"):
            for existing_path in (spool / area).glob(
                f"{capture.source_id}-{_capture_tag(capture.capture_key)}-*.ndjson"
            ):
                if existing_path.is_symlink() or not existing_path.is_file():
                    raise DeliveryError("Spool capture entry is invalid.")
                if existing_path.name == target.name:
                    stored = _capture_from_path(existing_path, capture.source_id)
                    if (
                        stored.capture_key != capture.capture_key
                        or stored.capture_key_field != capture.capture_key_field
                        or stored.digest != capture.digest
                    ):
                        raise DeliveryError(
                            "Stored capture failed its immutable identity check; source input remains preserved."
                        )
                    state = _read_checkpoint(checkpoint)
                    if area == "accepted" and (
                        state is None
                        or not _checkpoint_matches(state, stored)
                        or not _terminal_checkpoint(state, stored)
                    ):
                        raise DeliveryError(
                            "Accepted capture has no valid terminal checkpoint; source input remains preserved."
                        )
                    if area == "pending" and state is None:
                        _write_checkpoint(
                            checkpoint, _checkpoint_template(stored, existing_path)
                        )
                    if area == "quarantine":
                        raise CaptureConflictError(
                            "Capture ID is already quarantined; conflicting input remains preserved."
                        )
                    return QueueReceipt(
                        capture.capture_key,
                        capture.capture_key_field,
                        capture.source_id,
                        str(existing_path),
                        len(capture.lines),
                        len(capture.content),
                        True,
                    )
                conflict_target = _capture_path(spool, capture, "quarantine")
                if (
                    _all_spool_bytes(spool)
                    + 2 * len(capture.content)
                    + checkpoint_reservation
                    > SPOOL_MAX_BYTES
                ):
                    raise SpoolCapacityError(
                        "total_spool_bytes",
                        "Spool is full; conflicting input remains at its source path.",
                    )
                _store_capture(spool, capture, area="quarantine")
                conflict_state = _checkpoint_template(capture, conflict_target)
                conflict_state["status"] = "capture_id_conflict"
                conflict_state["last_error_code"] = "capture_id_conflict"
                _write_checkpoint(checkpoint, conflict_state)
                raise CaptureConflictError(
                    "Capture ID already exists with different content; conflicting input was quarantined."
                )

        pending_captures, pending_records, _ = _pending_counts(spool)
        if pending_captures + 1 > SPOOL_MAX_PENDING_CAPTURES:
            raise SpoolCapacityError(
                "pending_captures",
                "Spool capture limit reached; no new capture was accepted.",
            )
        if pending_records + len(capture.lines) > SPOOL_MAX_PENDING_RECORDS:
            raise SpoolCapacityError(
                "pending_records",
                "Spool record limit reached; no new capture was accepted.",
            )
        if (
            _all_spool_bytes(spool) + 2 * len(capture.content) + checkpoint_reservation
            > SPOOL_MAX_BYTES
        ):
            raise SpoolCapacityError(
                "total_spool_bytes",
                "Spool byte limit reached; no new capture was accepted.",
            )
        _store_capture(spool, capture)
        if not checkpoint.exists():
            _write_checkpoint(checkpoint, _checkpoint_template(capture, target))
        return QueueReceipt(
            capture.capture_key,
            capture.capture_key_field,
            capture.source_id,
            str(target),
            len(capture.lines),
            len(capture.content),
            False,
        )


def _parse_endpoint(value: str) -> tuple[str, str]:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise DeliveryError("HEC endpoint is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except ValueError:
        raise DeliveryError("HEC endpoint is invalid.") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise DeliveryError(
            "HEC endpoint must be a configured HTTPS URL without credentials or query data."
        )
    if parsed.path in ("", "/"):
        event_path = "/services/collector/event"
    elif parsed.path == "/services/collector":
        # Splunk Edge Ingest accepts the structured event envelope on this
        # route. Preserve an explicitly configured route; only a bare origin
        # defaults to the Enterprise `/event` endpoint.
        event_path = parsed.path
    elif parsed.path == "/services/collector/event":
        event_path = parsed.path
    else:
        raise DeliveryError(
            "HEC endpoint path is not a supported collector event route."
        )
    host = hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    authority = host if port in (None, 443) else f"{host}:{port}"
    origin = urlunsplit(("https", authority, "", "", ""))
    return origin + event_path, origin


@dataclass(frozen=True)
class _HTTPResponse:
    status: int
    body: bytes


class _HTTPFailure(Exception):
    def __init__(self, status: int, retryable: bool):
        self.status = status
        self.retryable = retryable
        super().__init__(f"HTTP_{status}")


def _post_json(
    url: str,
    body: bytes,
    token: str,
    timeout_seconds: float,
    ssl_context: ssl.SSLContext,
    channel: str | None = None,
) -> _HTTPResponse:
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Content-Length": str(len(body)),
    }
    if channel:
        headers["X-Splunk-Request-Channel"] = channel
    try:
        parsed = urlsplit(url)
        port = parsed.port
        hostname = parsed.hostname
    except ValueError:
        raise DeliveryError("HEC endpoint is invalid.") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.path
        not in {
            "/services/collector",
            "/services/collector/event",
            "/services/collector/ack",
        }
    ):
        raise DeliveryError("HEC endpoint is invalid.")
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    target_port = port or 443
    deadline = time.monotonic() + timeout_seconds
    addresses: list[tuple[Any, ...]] = []
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        resolved: list[list[tuple[Any, ...]]] = []
        resolve_error: list[OSError] = []
        resolution_finished = threading.Event()

        def resolve() -> None:
            try:
                resolved.append(
                    socket.getaddrinfo(hostname, target_port, type=socket.SOCK_STREAM)
                )
            except OSError as error:
                resolve_error.append(error)
            finally:
                resolution_finished.set()

        threading.Thread(target=resolve, daemon=True, name="atlas-hec-dns").start()
        if not resolution_finished.wait(timeout_seconds):
            raise _HTTPFailure(0, True) from None
        if resolve_error or not resolved or not resolved[0]:
            raise _HTTPFailure(0, True) from None
        addresses = resolved[0]
    else:
        if address.version == 4:
            addresses = [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (str(address), target_port),
                )
            ]
        else:
            addresses = [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (str(address), target_port, 0, 0),
                )
            ]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _HTTPFailure(0, True) from None

    active_socket: socket.socket | None = None
    connection: http.client.HTTPSConnection

    class BoundedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            nonlocal active_socket
            last_error: OSError | None = None
            for family, kind, protocol, _canonical_name, address_tuple in addresses:
                if time.monotonic() >= deadline:
                    raise TimeoutError("HEC request deadline expired")
                raw = socket.socket(family, kind, protocol)
                raw.settimeout(max(0.001, deadline - time.monotonic()))
                self.sock = raw
                active_socket = raw
                try:
                    raw.connect(address_tuple)
                    wrapped = ssl_context.wrap_socket(
                        raw, server_hostname=hostname, do_handshake_on_connect=False
                    )
                    self.sock = wrapped
                    active_socket = wrapped
                    wrapped.settimeout(max(0.001, deadline - time.monotonic()))
                    wrapped.do_handshake()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("HEC request deadline expired")
                    return
                except OSError as error:
                    last_error = error
                    try:
                        raw.close()
                    except OSError:
                        pass
                    self.sock = None
                    active_socket = None
            if last_error is not None:
                raise last_error
            raise TimeoutError("HEC request deadline expired")

    connection = BoundedHTTPSConnection(
        hostname,
        port=target_port,
        timeout=remaining,
        context=ssl_context,
    )

    def abort_request() -> None:
        sock = connection.sock or active_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    request_finished = threading.Event()

    def abort_until_finished() -> None:
        while not request_finished.wait(0.05):
            abort_request()

    timer = threading.Timer(remaining, abort_until_finished)
    timer.daemon = True
    timer.start()
    try:
        connection.request("POST", path, body=body, headers=headers)
        active_socket = connection.sock or active_socket
        response = connection.getresponse()
        response_body = response.read(65_537)
        if len(response_body) > 65_536:
            raise DeliveryError("HEC response exceeds the configured response limit.")
        return _HTTPResponse(int(response.status), response_body)
    except (OSError, http.client.HTTPException, ValueError, TimeoutError):
        raise _HTTPFailure(0, True) from None
    finally:
        request_finished.set()
        timer.cancel()
        connection.close()


def _request_timeout(deadline: float | None, configured: int) -> float | None:
    if deadline is None:
        return configured
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return min(float(configured), remaining)


def _successful_hec_response(response: _HTTPResponse) -> tuple[int | None, int | None]:
    if not 200 <= response.status < 300:
        raise _HTTPFailure(
            response.status, response.status == 429 or response.status >= 500
        )
    try:
        parsed = json.loads(
            response.body,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise DeliveryError(
            "HEC returned an invalid response; capture remains pending."
        ) from None
    code = parsed.get("code") if isinstance(parsed, dict) else None
    if not isinstance(parsed, dict) or isinstance(code, bool) or code not in (0, "0"):
        raise DeliveryError("HEC rejected the batch; capture remains pending.")
    # Splunk's current Enterprise documentation uses ``ackID`` while the
    # supported 10.6 runtime returns ``ackId``. Normalize both forms, but do
    # not silently pick one if a response contains conflicting aliases.
    ack_values = [parsed[key] for key in ("ackID", "ackId") if key in parsed]
    normalized: list[int] = []
    for value in ack_values:
        if isinstance(value, bool):
            raise DeliveryError("HEC returned an invalid acknowledgment ID.")
        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
            number = int(value)
        else:
            raise DeliveryError("HEC returned an invalid acknowledgment ID.")
        if number < 0:
            raise DeliveryError("HEC returned an invalid acknowledgment ID.")
        normalized.append(number)
    if len(set(normalized)) > 1:
        raise DeliveryError("HEC returned conflicting acknowledgment IDs.")
    return (normalized[0] if normalized else None), parsed.get("code")


def _context(ca_bundle: str | None) -> ssl.SSLContext:
    if ca_bundle:
        ca_path = Path(ca_bundle).expanduser()
        if not ca_path.is_file() or ca_path.is_symlink():
            raise DeliveryError("Configured CA bundle is unavailable.")
        return ssl.create_default_context(cafile=str(ca_path))
    return ssl.create_default_context()


def _record_batches(lines: tuple[bytes, ...]) -> list[tuple[int, int, bytes]]:
    batches: list[tuple[int, int, bytes]] = []
    start = 0
    parts: list[bytes] = []
    size = 0
    for index, line in enumerate(lines):
        part = line + b"\n"
        if len(part) > BATCH_MAX_BYTES:
            raise DeliveryError("A single HEC event exceeds the batch byte limit.")
        if parts and size + len(part) > BATCH_MAX_BYTES:
            batches.append((start, index, b"".join(parts)))
            start = index
            parts = []
            size = 0
        parts.append(part)
        size += len(part)
    if parts:
        batches.append((start, len(lines), b"".join(parts)))
    return batches


def _capture_from_path(path: Path, source_id: str) -> _Capture:
    capture = _load_capture(path, source_id)
    match = re.fullmatch(
        rf"{re.escape(source_id)}-[0-9a-f]{{32}}-([0-9a-f]{{64}})\.ndjson",
        path.name,
    )
    if match is None or match.group(1) != capture.digest:
        raise DeliveryError(
            "Queued capture bytes do not match their immutable spool identity."
        )
    return _Capture(
        capture.capture_key,
        capture.capture_key_field,
        capture.source_id,
        capture.digest,
        capture.content,
        capture.lines,
    )


def _recover_checkpoint(
    spool: Path, capture: _Capture, path: Path
) -> tuple[Path, dict[str, Any]]:
    checkpoint = _checkpoint_path(
        spool, capture.source_id, capture.capture_key, capture.digest
    )
    state = _read_checkpoint(checkpoint)
    recovered = False
    if checkpoint.exists() and (
        state is None or not _checkpoint_matches(state, capture)
    ):
        corrupt = checkpoint.with_name(
            f"{checkpoint.name}.corrupt.{int(time.time())}.{uuid.uuid4().hex}"
        )
        try:
            os.replace(checkpoint, corrupt)
            _fsync_directory(checkpoint.parent)
        except OSError:
            raise DeliveryError(
                "Corrupt checkpoint could not be preserved for recovery."
            ) from None
        state = None
        recovered = True
    if state is None:
        state = _checkpoint_template(capture, path)
        state["status"] = "checkpoint_corrupt_replay" if recovered else "pending"
        state["checkpoint_recovered"] = recovered
        _write_checkpoint(checkpoint, state)
    if not _checkpoint_matches(state, capture):
        raise DeliveryError("Checkpoint does not match queued capture.")
    return checkpoint, state


def _ack_url(origin: str, channel: str) -> str:
    return origin + "/services/collector/ack?channel=" + quote(channel, safe="")


def _move_terminal_capture_to_accepted(
    spool: Path,
    path: Path,
    capture: _Capture,
    checkpoint: Path,
    state: dict[str, Any],
) -> None:
    """Finish a terminal checkpoint move after a crash without resending."""
    if not _terminal_checkpoint(state, capture):
        raise DeliveryError(
            "Capture lacks evidence for terminal delivery; pending data was preserved."
        )
    if path.parent.name != "pending":
        return
    accepted_path = _capture_path(spool, capture, "accepted")
    if accepted_path.exists():
        accepted_capture = _capture_from_path(accepted_path, capture.source_id)
        if accepted_capture.digest != capture.digest:
            raise DeliveryError(
                "Accepted capture conflicts with its pending copy; both were preserved."
            )
        try:
            path.unlink()
            _fsync_directory(path.parent)
        except OSError:
            raise DeliveryError(
                "Duplicate pending capture could not be removed after acceptance."
            ) from None
    else:
        try:
            os.replace(path, accepted_path)
            _fsync_directory(path.parent)
            _fsync_directory(accepted_path.parent)
        except OSError:
            raise DeliveryError(
                "Terminal capture could not be moved to accepted storage."
            ) from None
    state["capture_file"] = accepted_path.name
    _write_checkpoint(checkpoint, state)


def _poll_ack(
    *,
    origin: str,
    channel: str,
    ack_id: int,
    token: str,
    timeout_seconds: int,
    ssl_context: ssl.SSLContext,
    ack_wait_seconds: int,
    poll_interval_seconds: int,
    post_json: Callable[..., _HTTPResponse],
    deadline: float | None = None,
) -> bool | None:
    ack_deadline = time.monotonic() + ack_wait_seconds
    if deadline is not None:
        ack_deadline = min(ack_deadline, deadline)
    while True:
        request_timeout = _request_timeout(deadline, timeout_seconds)
        if request_timeout is None:
            return None
        try:
            response = post_json(
                _ack_url(origin, channel),
                json.dumps({"acks": [ack_id]}, separators=(",", ":")).encode(),
                token,
                request_timeout,
                ssl_context,
                channel,
            )
        except _HTTPFailure:
            return None
        if not 200 <= response.status < 300:
            return None
        try:
            parsed = json.loads(
                response.body,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
            acknowledgements = parsed["acks"]
            result = acknowledgements.get(str(ack_id))
        except (
            KeyError,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ):
            return None
        if result is True:
            return True
        if result is not False:
            return None
        remaining = ack_deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(max(0.0, poll_interval_seconds), remaining))


def _send_capture(
    spool: Path,
    path: Path,
    *,
    endpoint: str,
    origin: str,
    token: str,
    timeout_seconds: int,
    ssl_context: ssl.SSLContext,
    ack_mode: Literal["off", "enterprise"],
    ack_wait_seconds: int,
    poll_interval_seconds: int,
    post_json: Callable[..., _HTTPResponse],
    deadline: float | None,
) -> tuple[str, int, int]:
    source_id = path.name.split("-", 1)[0]
    capture = _capture_from_path(path, source_id)
    checkpoint, state = _recover_checkpoint(spool, capture, path)
    bound_endpoint = state.get("delivery_endpoint")
    if bound_endpoint is None:
        state["delivery_endpoint"] = endpoint
        _write_checkpoint(checkpoint, state)
    elif bound_endpoint != endpoint:
        raise DeliveryError(
            "Capture is already bound to another HEC endpoint; pending data was preserved."
        )
    if ack_mode == "enterprise" and (urlsplit(origin).hostname or "").endswith(
        ".splunkcloud.com"
    ):
        raise DeliveryError(
            "HEC indexer acknowledgment is unavailable for direct Splunk Cloud delivery."
        )

    batches = _record_batches(capture.lines)
    bound_mode = state.get("ack_mode")
    if bound_mode is None:
        next_index = state.get("next_record_index", 0)
        if (
            next_index != 0
            or state.get("accepted_batches", 0) != 0
            or state.get("ack_id") is not None
            or state.get("http_accepted_unverified") is True
            or state.get("indexer_acknowledged") is True
        ):
            raise DeliveryError(
                "Delivery mode cannot be established after progress; pending data was preserved."
            )
        state["ack_mode"] = ack_mode
        _write_checkpoint(checkpoint, state)
    elif bound_mode != ack_mode:
        raise DeliveryError(
            "Capture is already bound to another HEC acknowledgment mode; pending data was preserved."
        )
    if state.get("status") in {
        "http_accepted_unverified",
        "indexer_acknowledged_not_searchable",
    }:
        if not _terminal_checkpoint(state, capture):
            raise DeliveryError(
                "Terminal checkpoint lacks complete delivery evidence; pending data was preserved."
            )
        _move_terminal_capture_to_accepted(spool, path, capture, checkpoint, state)
        return str(state["status"]), 0, 0
    if state.get("ack_id") is not None:
        channel = state.get("ack_channel")
        end_index = state.get("ack_batch_end")
        ack_id = state.get("ack_id")
        if (
            not isinstance(channel, str)
            or not re.fullmatch(r"[0-9a-fA-F-]{36}", channel)
            or isinstance(end_index, bool)
            or not isinstance(end_index, int)
            or not 0 < end_index <= len(capture.lines)
            or isinstance(ack_id, bool)
            or not isinstance(ack_id, int)
        ):
            raise DeliveryError("Acknowledgment checkpoint is invalid.")
        acknowledged = _poll_ack(
            origin=origin,
            channel=channel,
            ack_id=ack_id,
            token=token,
            timeout_seconds=timeout_seconds,
            ssl_context=ssl_context,
            ack_wait_seconds=ack_wait_seconds,
            poll_interval_seconds=poll_interval_seconds,
            post_json=post_json,
            deadline=deadline,
        )
        if acknowledged is not True:
            state["status"] = (
                "acknowledgment_pending"
                if acknowledged is False
                else "acknowledgment_unavailable"
            )
            state["last_error_code"] = state["status"]
            _write_checkpoint(checkpoint, state)
            return str(state["status"]), 0, 0
        state["next_record_index"] = end_index
        state["accepted_batches"] = int(state.get("accepted_batches", 0)) + 1
        state["indexer_acknowledged"] = True
        state["ack_id"] = None
        state["ack_batch_end"] = None
        state["status"] = "pending"
        state["last_error_code"] = None
        _write_checkpoint(checkpoint, state)

    channel = state.get("ack_channel")
    if ack_mode == "enterprise" and not channel:
        channel = str(uuid.uuid4())
        state["ack_channel"] = channel
        _write_checkpoint(checkpoint, state)

    attempted_batches = accepted_batches = 0
    next_index = state.get("next_record_index", 0)
    if (
        isinstance(next_index, bool)
        or not isinstance(next_index, int)
        or not 0 <= next_index <= len(capture.lines)
    ):
        raise DeliveryError("Delivery checkpoint index is invalid.")
    accepted_batches = state.get("accepted_batches", 0)
    if (
        isinstance(accepted_batches, bool)
        or not isinstance(accepted_batches, int)
        or not 0 <= accepted_batches <= len(batches)
    ):
        raise DeliveryError("Delivery checkpoint batch count is invalid.")
    for batch_start, batch_end, body in batches:
        if batch_end <= next_index:
            continue
        if batch_start != next_index:
            raise DeliveryError(
                "Delivery checkpoint is not aligned to a batch boundary."
            )
        attempt = 0
        while True:
            request_timeout = _request_timeout(deadline, timeout_seconds)
            if request_timeout is None:
                state["status"] = "run_budget_exhausted"
                state["last_error_code"] = "run_budget_exhausted"
                _write_checkpoint(checkpoint, state)
                return str(state["status"]), attempted_batches, accepted_batches
            attempted_batches += 1
            attempt += 1
            try:
                response = post_json(
                    endpoint,
                    body,
                    token,
                    request_timeout,
                    ssl_context,
                    channel if ack_mode == "enterprise" else None,
                )
                ack_id, _ = _successful_hec_response(response)
                if ack_mode == "enterprise":
                    if ack_id is None:
                        # HEC accepted this request but supplied no ACK ID, so
                        # we cannot prove indexing. Leave the checkpoint at
                        # this batch's start and replay it on restart.
                        state["http_accepted_unverified"] = True
                        state["status"] = "acknowledgment_id_missing"
                        state["last_error_code"] = "acknowledgment_id_missing"
                        _write_checkpoint(checkpoint, state)
                        return str(state["status"]), attempted_batches, accepted_batches
                    state["ack_id"] = ack_id
                    state["ack_batch_end"] = batch_end
                    state["status"] = "acknowledgment_pending"
                    state["http_accepted_unverified"] = True
                    state["last_error_code"] = None
                    _write_checkpoint(checkpoint, state)
                    acknowledged = _poll_ack(
                        origin=origin,
                        channel=str(channel),
                        ack_id=ack_id,
                        token=token,
                        timeout_seconds=timeout_seconds,
                        ssl_context=ssl_context,
                        ack_wait_seconds=ack_wait_seconds,
                        poll_interval_seconds=poll_interval_seconds,
                        post_json=post_json,
                        deadline=deadline,
                    )
                    if acknowledged is not True:
                        state["status"] = (
                            "acknowledgment_pending"
                            if acknowledged is False
                            else "acknowledgment_unavailable"
                        )
                        state["last_error_code"] = state["status"]
                        _write_checkpoint(checkpoint, state)
                        return str(state["status"]), attempted_batches, accepted_batches
                    state["next_record_index"] = batch_end
                    state["accepted_batches"] = (
                        int(state.get("accepted_batches", 0)) + 1
                    )
                    state["indexer_acknowledged"] = True
                    state["ack_id"] = None
                    state["ack_batch_end"] = None
                    state["status"] = "pending"
                    state["last_error_code"] = None
                    _write_checkpoint(checkpoint, state)
                else:
                    if ack_id is not None:
                        state["next_record_index"] = batch_end
                        state["accepted_batches"] = (
                            int(state.get("accepted_batches", 0)) + 1
                        )
                        state["http_accepted_unverified"] = True
                        state["status"] = "acknowledgment_mode_required"
                        state["last_error_code"] = "acknowledgment_mode_required"
                        _write_checkpoint(checkpoint, state)
                        return str(state["status"]), attempted_batches, accepted_batches
                    state["next_record_index"] = batch_end
                    state["accepted_batches"] = (
                        int(state.get("accepted_batches", 0)) + 1
                    )
                    state["http_accepted_unverified"] = True
                    state["status"] = "pending"
                    state["last_error_code"] = None
                    _write_checkpoint(checkpoint, state)
                accepted_batches += 1
                next_index = batch_end
                break
            except _HTTPFailure as error:
                state["last_error_code"] = (
                    f"HTTP_{error.status}" if error.status else "transport_error"
                )
                state["status"] = (
                    "retry_pending" if error.retryable else "rejected_pending"
                )
                _write_checkpoint(checkpoint, state)
                if not error.retryable or attempt >= HTTP_ATTEMPTS:
                    return str(state["status"]), attempted_batches, accepted_batches
                retry_delay = min(2 ** (attempt - 1), 4)
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return (
                            "run_budget_exhausted",
                            attempted_batches,
                            accepted_batches,
                        )
                    retry_delay = min(retry_delay, remaining)
                time.sleep(retry_delay)
            except DeliveryError as error:
                code = str(error).split(";", 1)[0].lower().replace(" ", "_")[:96]
                state["last_error_code"] = code
                state["status"] = "rejected_pending"
                _write_checkpoint(checkpoint, state)
                return str(state["status"]), attempted_batches, accepted_batches

    if state.get("next_record_index") == len(capture.lines):
        accepted_batches = state.get("accepted_batches")
        if (
            isinstance(accepted_batches, bool)
            or not isinstance(accepted_batches, int)
            or accepted_batches != len(batches)
        ):
            raise DeliveryError(
                "Delivery checkpoint has incomplete batch evidence; pending data was preserved."
            )
        if ack_mode == "enterprise":
            if (
                state.get("indexer_acknowledged") is not True
                or state.get("ack_id") is not None
                or state.get("ack_batch_end") is not None
            ):
                raise DeliveryError(
                    "Enterprise acknowledgment is incomplete; pending data was preserved."
                )
            state["status"] = "indexer_acknowledged_not_searchable"
        else:
            if state.get("indexer_acknowledged") is True:
                raise DeliveryError(
                    "Indexer acknowledgment mode changed; pending data was preserved."
                )
            state["status"] = "http_accepted_unverified"
        state["last_error_code"] = None
        _write_checkpoint(checkpoint, state)
        _move_terminal_capture_to_accepted(spool, path, capture, checkpoint, state)
        return str(state["status"]), attempted_batches, accepted_batches
    return str(state.get("status", "pending")), attempted_batches, accepted_batches


def _checkpoint_paths(spool: Path, area: str) -> list[Path]:
    return sorted((spool / area).glob("*.ndjson"))


def spool_status(spool_dir: Path) -> SpoolStatus:
    """Return bounded backlog counts without revealing source payloads."""
    spool = _ensure_spool(Path(spool_dir))
    with _SpoolLock(spool):
        return _spool_status_locked(spool)


def _spool_status_locked(spool: Path) -> SpoolStatus:
    pending_captures, pending_records, pending_bytes = _pending_counts(spool)
    accepted_unverified = acknowledged = quarantined = recoveries = 0
    oldest: int | None = None
    now = int(time.time())
    for area in ("pending", "accepted", "quarantine"):
        for path in _checkpoint_paths(spool, area):
            source_id = path.name.split("-", 1)[0]
            digest = path.stem.rsplit("-", 1)[-1]
            checkpoint_candidates = list(
                (spool / "checkpoints").glob(f"{source_id}-*-{digest}.json")
            )
            state = (
                _read_checkpoint(checkpoint_candidates[0])
                if len(checkpoint_candidates) == 1
                else None
            )
            if not state:
                recoveries += 1
                continue
            if state.get("checkpoint_recovered") is True:
                recoveries += 1
            if area == "accepted":
                if state.get("indexer_acknowledged"):
                    acknowledged += 1
                else:
                    accepted_unverified += 1
            if area == "quarantine":
                quarantined += 1
            if area == "pending":
                queued_at = state.get("queued_at")
                if isinstance(queued_at, int) and not isinstance(queued_at, bool):
                    age = max(0, now - queued_at)
                    oldest = age if oldest is None else max(oldest, age)
                else:
                    # Checkpoints written before `queued_at` used the pending
                    # file's creation time; retry updates must not reset age.
                    age = max(0, now - int(path.stat().st_mtime))
                    oldest = age if oldest is None else max(oldest, age)
    return SpoolStatus(
        pending_captures=pending_captures,
        pending_records=pending_records,
        pending_bytes=pending_bytes,
        http_accepted_unverified=accepted_unverified,
        indexer_acknowledged_not_searchable=acknowledged,
        quarantined_captures=quarantined,
        checkpoint_recoveries=recoveries,
        oldest_pending_age_seconds=oldest,
        capacity_bytes=SPOOL_MAX_BYTES,
        capacity_captures=SPOOL_MAX_PENDING_CAPTURES,
        capacity_records=SPOOL_MAX_PENDING_RECORDS,
        used_bytes=_all_spool_bytes(spool),
    )


def deliver_pending(
    spool_dir: Path,
    *,
    endpoint: str,
    token: str,
    timeout_seconds: int = HTTP_TIMEOUT_SECONDS,
    ack_mode: Literal["off", "enterprise"] = "off",
    ack_wait_seconds: int = DEFAULT_ACK_WAIT_SECONDS,
    poll_interval_seconds: int = DEFAULT_ACK_POLL_SECONDS,
    ca_bundle: str | None = None,
    max_captures: int = MAX_SEND_CAPTURES_PER_RUN,
    max_run_seconds: int = MAX_SEND_SECONDS_PER_RUN,
    post_json: Callable[..., _HTTPResponse] = _post_json,
) -> DeliverySummary:
    """Send queued captures. 200 and indexer acknowledgment are separate from search readback."""
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise DeliveryError("ATLAS_HEC_TOKEN is required.")
    if not 1 <= timeout_seconds <= 300:
        raise DeliveryError("Timeout must be between 1 and 300 seconds.")
    if ack_mode not in ("off", "enterprise"):
        raise DeliveryError("Unsupported HEC acknowledgment mode.")
    if not 0 <= ack_wait_seconds <= 300 or not 1 <= poll_interval_seconds <= 30:
        raise DeliveryError(
            "Acknowledgment wait values are outside the configured limits."
        )
    if (
        isinstance(max_captures, bool)
        or not 1 <= max_captures <= MAX_SEND_CAPTURES_PER_RUN
    ):
        raise DeliveryError(
            "Capture count per send run is outside the configured limit."
        )
    if (
        isinstance(max_run_seconds, bool)
        or not 1 <= max_run_seconds <= MAX_SEND_SECONDS_PER_RUN
    ):
        raise DeliveryError("Duration per send run is outside the configured limit.")
    event_url, origin = _parse_endpoint(endpoint)
    ssl_context = _context(ca_bundle)
    spool = _ensure_spool(Path(spool_dir))
    attempted = accepted = indexed_acknowledged = failed = 0
    deadline = time.monotonic() + max_run_seconds
    with _SpoolLock(spool):
        paths = sorted(
            _checkpoint_paths(spool, "pending"),
            key=lambda path: path.stat().st_mtime,
        )[:max_captures]
        for path in paths:
            if _request_timeout(deadline, timeout_seconds) is None:
                break
            attempted += 1
            try:
                status, _, batch_count = _send_capture(
                    spool,
                    path,
                    endpoint=event_url,
                    origin=origin,
                    token=token,
                    timeout_seconds=timeout_seconds,
                    ssl_context=ssl_context,
                    ack_mode=ack_mode,
                    ack_wait_seconds=ack_wait_seconds,
                    poll_interval_seconds=poll_interval_seconds,
                    post_json=post_json,
                    deadline=deadline,
                )
                if status == "http_accepted_unverified":
                    accepted += 1
                elif status == "indexer_acknowledged_not_searchable":
                    accepted += 1
                    indexed_acknowledged += 1
                elif status not in ("pending", "acknowledgment_pending"):
                    failed += 1
                elif batch_count:
                    accepted += 0
            except DeliveryError:
                failed += 1
        status = _spool_status_locked(spool)
    return DeliverySummary(
        attempted_captures=attempted,
        http_accepted_captures=accepted,
        indexer_acknowledged_captures=indexed_acknowledged,
        failed_captures=failed,
        pending_captures=status.pending_captures,
        pending_records=status.pending_records,
        pending_bytes=status.pending_bytes,
        status=(
            "backlog"
            if status.pending_captures
            else "accepted_unverified"
            if status.http_accepted_unverified
            else "indexer_acknowledged_not_searchable"
            if status.indexer_acknowledged_not_searchable
            else "empty"
        ),
    )


def _env(name: str, required: bool = False) -> str | None:
    value = os.environ.get(name)
    if required and not value:
        raise DeliveryError(f"{name} is required.")
    return value or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Report safe spool backlog counts.")
    subparsers.add_parser(
        "send", help="Retry pending captures from the configured spool."
    )
    enqueue = subparsers.add_parser(
        "enqueue", help="Add one finalized capture to the configured spool."
    )
    enqueue.add_argument("--input", type=Path, required=True)
    enqueue.add_argument("--source-id", required=True)
    sender = subparsers.choices["send"]
    sender.add_argument("--ack-mode", choices=("off", "enterprise"), default="off")
    sender.add_argument(
        "--ack-wait-seconds", type=int, default=DEFAULT_ACK_WAIT_SECONDS
    )
    args = parser.parse_args(argv)
    try:
        spool = Path(_env("ATLAS_HEC_SPOOL_DIR", required=True) or "")
        if args.command == "status":
            print(json.dumps(asdict(spool_status(spool)), sort_keys=True))
            return 0
        if args.command == "enqueue":
            receipt = enqueue_capture(args.input, spool, source_id=args.source_id)
            print(json.dumps(asdict(receipt), sort_keys=True))
            return 0
        summary = deliver_pending(
            spool,
            endpoint=_env("ATLAS_HEC_URL", required=True) or "",
            token=_env("ATLAS_HEC_TOKEN", required=True) or "",
            ack_mode=args.ack_mode,
            ack_wait_seconds=args.ack_wait_seconds,
            ca_bundle=_env("ATLAS_HEC_CA_BUNDLE"),
        )
        print(json.dumps(asdict(summary), sort_keys=True))
        return 1 if summary.failed_captures else 0
    except (DeliveryError, OSError):
        print(
            "HEC delivery operation failed; private spool entries were preserved.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
