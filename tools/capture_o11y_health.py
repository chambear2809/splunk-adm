#!/usr/bin/env python3
"""Capture one scheduled health interval and durably transfer it to the HEC queue.

No delivery is performed here. Run the common hec_delivery sender separately.
One private state directory belongs to one configuration and delivery spool.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from typing import Any, Callable, Iterator

try:
    from tools import export_o11y_health as exporter
except ModuleNotFoundError:  # Direct invocation from the separately packaged tools.
    import export_o11y_health as exporter


ROOT = Path(__file__).resolve().parents[1]
STATE_MAX_BYTES = 16_384
DIRECTORY_MAX_BYTES = 2 * exporter.MAX_OUTPUT_BYTES + 65_536
CONFIG_FIELDS = {
    "schema_version",
    "observer",
    "organization_id",
    "realm",
    "scope",
    "service_name",
    "environment",
    "cluster",
    "kubernetes_namespace",
    "apm_mms_id",
    "service_namespace",
    "timeout_seconds",
}


class CaptureStateError(RuntimeError):
    """A recoverable failure with no source payload or credentials in its message."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaptureStateError("Duplicate JSON keys are unsupported.")
        result[key] = value
    return result


def _json(content: bytes | str) -> Any:
    try:
        return json.loads(content, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError):
        raise CaptureStateError(
            "Malformed state/configuration/capture JSON; preserved for recovery."
        ) from None


def _read(path: Path, cap: int, *, private: bool = True) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (private and (info.st_uid != os.getuid() or info.st_mode & 0o077))
            or info.st_size > cap
        ):
            raise CaptureStateError("State/configuration file is unsafe or oversized.")
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise CaptureStateError("State/configuration file exceeds its byte limit.")
    return data


def read_config(path: Path) -> dict[str, Any]:
    value = _json(_read(path, STATE_MAX_BYTES, private=False))
    if (
        not isinstance(value, dict)
        or set(value) - CONFIG_FIELDS
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
    ):
        raise CaptureStateError("Unsupported capture configuration.")
    fields = {key: item for key, item in value.items() if key != "schema_version"}
    fields.setdefault("service_namespace", None)
    fields.setdefault("timeout_seconds", exporter.DEFAULT_TIMEOUT_SECONDS)
    if type(fields["timeout_seconds"]) is not int:
        raise CaptureStateError("Capture timeout must be a whole number of seconds.")
    request = exporter.ExportRequest(**fields, start=0, end=300)
    request.validate()
    return fields


def _outside_checkout(path: Path) -> Path:
    if path.is_symlink():
        raise CaptureStateError("State and spool directories cannot be symbolic links.")
    resolved = path.expanduser().resolve()
    if resolved.is_relative_to(ROOT) or any(
        (parent / ".git").exists() for parent in (resolved, *resolved.parents)
    ):
        raise CaptureStateError(
            "Capture state and delivery spool must be outside checkouts."
        )
    return resolved


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save(path: Path, state: dict[str, Any]) -> None:
    payload = {key: value for key, value in state.items() if key != "state_sha256"}
    payload["state_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(content) > STATE_MAX_BYTES:
        raise CaptureStateError("Capture checkpoint exceeds its byte limit.")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".state-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def _locked(directory: Path) -> Iterator[None]:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CaptureStateError(
            "Capture state directory must be private and user-owned."
        )
    descriptor = os.open(
        directory / ".lock",
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "r+b") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise CaptureStateError("Capture lock is unsafe.")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CaptureStateError(
                "Another capture owns this state directory."
            ) from None
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _directory_budget(directory: Path) -> None:
    total = 0
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise CaptureStateError(
                "Unexpected capture state entry; preserve it for recovery."
            )
        total += path.stat().st_size
        if path.name not in {".lock", "state.json", "pending.ndjson"}:
            raise CaptureStateError(
                "Interrupted temporary data requires operator recovery; nothing was removed."
            )
    if total > DIRECTORY_MAX_BYTES:
        raise CaptureStateError(
            "Capture state disk limit reached; nothing was removed."
        )


def _window(value: Any) -> list[int]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(type(item) is not int for item in value)
        or not 0 <= value[0] < value[1] <= 253_402_300_799
        or value[1] - value[0] > exporter.MAX_WINDOW_SECONDS
    ):
        raise CaptureStateError("Invalid capture checkpoint interval.")
    return value


def _validate_capture(path: Path, request: exporter.ExportRequest) -> None:
    rows = [
        _json(line)
        for line in _read(path, exporter.MAX_OUTPUT_BYTES).splitlines()
        if line.strip()
    ]
    if (
        not rows
        or len(rows) > exporter.MAX_METRIC_RECORDS + 1
        or any(
            not isinstance(row, dict) or not isinstance(row.get("event"), dict)
            for row in rows
        )
    ):
        raise CaptureStateError(
            "Pending capture is incomplete or malformed; preserved for recovery."
        )
    final = rows[-1]["event"]
    captured = final.get("captured_at")
    if (
        isinstance(captured, bool)
        or not isinstance(captured, (int, float))
        or not math.isfinite(captured)
        or not 0 <= captured <= 253_402_300_799
    ):
        raise CaptureStateError(
            "Pending capture time is invalid; preserved for recovery."
        )
    if (
        final.get("event_type") != "export_completion"
        or type(final.get("expected_record_count")) is not int
        or final.get("expected_record_count") != len(rows) - 1
        or not isinstance(final.get("capture_id"), str)
        or not final["capture_id"]
    ):
        raise CaptureStateError(
            "Pending capture completion is invalid; preserved for recovery."
        )
    expected = {
        "schema": exporter.SCHEMA,
        "observer_id": request.observer,
        "organization_id": request.organization_id,
        "realm": request.realm,
        "routing_scope": request.scope,
        "service_name": request.service_name,
        "environment": request.environment,
        "cluster": request.cluster,
        "kubernetes_namespace": request.kubernetes_namespace,
        "capture_window_start": request.start,
        "capture_window_end": request.end,
        "capture_id": final["capture_id"],
    }
    for position, row in enumerate(rows):
        event = row["event"]
        if (
            type(row.get("time")) not in (int, float)
            or row.get("host") != request.observer
            or row.get("sourcetype") != exporter.SOURCETYPE
            or row.get("source") != "atlas:o11y_health/export"
            or any(event.get(key) != value for key, value in expected.items())
            or row.get("time") != final.get("captured_at")
            or event.get("captured_at") != final.get("captured_at")
            or (position < len(rows) - 1 and event.get("event_type") != "metric")
        ):
            raise CaptureStateError(
                "Pending capture identity disagrees with its checkpoint; preserved."
            )
    if final.get("apm_mms_id") != request.apm_mms_id or (
        request.service_namespace is not None
        and final.get("service_namespace") != request.service_namespace
    ):
        raise CaptureStateError("Pending capture service identity changed; preserved.")


def run_once(
    config: dict[str, Any],
    state_dir: Path,
    spool_dir: Path,
    *,
    now: float | None = None,
    window_seconds: int = 300,
    lag_seconds: int = 120,
    token: str = "",
    delivery: Any = None,
    capture: Callable[..., Any] = exporter.run_export,
) -> dict[str, Any]:
    """Recover one pending handoff or capture at most one contiguous interval."""
    if (
        type(window_seconds) is not int
        or not 60 <= window_seconds <= exporter.MAX_WINDOW_SECONDS
        or type(lag_seconds) is not int
        or not 0 <= lag_seconds <= exporter.MAX_WINDOW_SECONDS
    ):
        raise CaptureStateError("Capture cadence/lag is outside supported bounds.")
    now = time.time() if now is None else now
    if (
        isinstance(now, bool)
        or not isinstance(now, (float, int))
        or not math.isfinite(now)
        or not 0 <= now <= 253_402_300_799
    ):
        raise CaptureStateError("Invalid capture clock.")
    state_dir, spool_dir = (
        _outside_checkout(Path(state_dir)),
        _outside_checkout(Path(spool_dir)),
    )
    if state_dir.is_relative_to(spool_dir) or spool_dir.is_relative_to(state_dir):
        raise CaptureStateError(
            "Capture state and delivery spool must be separate directories."
        )
    if delivery is None:
        try:
            from tools import hec_delivery as delivery
        except ModuleNotFoundError:
            import hec_delivery as delivery
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "config": config,
                "window_seconds": window_seconds,
                "lag_seconds": lag_seconds,
                "spool": str(spool_dir),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with _locked(state_dir):
        _directory_budget(state_dir)
        checkpoint, pending = state_dir / "state.json", state_dir / "pending.ndjson"
        if checkpoint.exists():
            state = _json(_read(checkpoint, STATE_MAX_BYTES))
            if (
                not isinstance(state, dict)
                or set(state)
                != {
                    "schema_version",
                    "fingerprint",
                    "last_enqueued_end",
                    "pending_window",
                    "state_sha256",
                }
                or type(state.get("schema_version")) is not int
                or state.get("schema_version") != 1
                or state.get("fingerprint") != fingerprint
            ):
                raise CaptureStateError(
                    "Capture configuration/checkpoint changed; existing data is preserved."
                )
            digest = state["state_sha256"]
            content = {
                key: value for key, value in state.items() if key != "state_sha256"
            }
            if (
                digest
                != hashlib.sha256(
                    json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            ):
                raise CaptureStateError(
                    "Capture checkpoint integrity check failed; preserved."
                )
            last = state["last_enqueued_end"]
            if last is not None and (
                type(last) is not int or not 0 <= last <= 253_402_300_799
            ):
                raise CaptureStateError(
                    "Capture checkpoint is invalid; existing data is preserved."
                )
            if state["pending_window"] is not None:
                interval = _window(state["pending_window"])
                if interval[1] - interval[0] != window_seconds or (
                    last is not None and interval[0] != last
                ):
                    raise CaptureStateError(
                        "Capture checkpoint continuity is invalid; preserved."
                    )
        else:
            if pending.exists():
                raise CaptureStateError(
                    "Pending capture lacks a checkpoint; preserve it for recovery."
                )
            state = {
                "schema_version": 1,
                "fingerprint": fingerprint,
                "last_enqueued_end": None,
                "pending_window": None,
            }
        recovered = pending.exists()
        if recovered:
            rows = _read(pending, exporter.MAX_OUTPUT_BYTES).splitlines()
            if not rows:
                raise CaptureStateError(
                    "Pending capture is empty; preserved for recovery."
                )
            final_row = _json(rows[-1])
            if not isinstance(final_row, dict) or not isinstance(
                final_row.get("event"), dict
            ):
                raise CaptureStateError(
                    "Malformed pending capture; preserved for recovery."
                )
            final = final_row["event"]
            interval = _window(
                [final.get("capture_window_start"), final.get("capture_window_end")]
            )
            if state["pending_window"] is None:
                if interval[1] != state["last_enqueued_end"]:
                    raise CaptureStateError(
                        "Untracked pending capture is preserved for recovery."
                    )
            elif interval != state["pending_window"]:
                raise CaptureStateError(
                    "Pending capture interval disagrees with checkpoint; preserved."
                )
        else:
            latest = int((now - lag_seconds) // window_seconds) * window_seconds
            interval = state["pending_window"]
            if interval is None:
                start = (
                    latest - window_seconds
                    if state["last_enqueued_end"] is None
                    else state["last_enqueued_end"]
                )
                if start + window_seconds > latest:
                    return {
                        "status": "idle",
                        "last_enqueued_end": state["last_enqueued_end"],
                    }
                interval = _window([start, start + window_seconds])
            request = exporter.ExportRequest(
                **config, start=interval[0], end=interval[1]
            )
            request.validate()
            backlog = delivery.spool_status(spool_dir)
            if (
                backlog.pending_captures + 1 > backlog.capacity_captures
                or backlog.pending_records + exporter.MAX_METRIC_RECORDS + 1
                > backlog.capacity_records
                or backlog.used_bytes + exporter.MAX_OUTPUT_BYTES + 65_536
                > backlog.capacity_bytes
            ):
                raise CaptureStateError(
                    "Delivery spool capacity reached; no new capture started."
                )
            if not token:
                raise CaptureStateError(
                    "SPLUNK_OBSERVABILITY_TOKEN is required for a new capture."
                )
            state["pending_window"] = interval
            _save(checkpoint, state)
            capture(request, pending, token=token)
            _directory_budget(state_dir)
        request = exporter.ExportRequest(**config, start=interval[0], end=interval[1])
        _validate_capture(pending, request)
        receipt = delivery.enqueue_capture(pending, spool_dir, source_id="o11y_health")
        # Queue acceptance means the common sender owns a durable copy. It does
        # not mean HEC accepted it or that it is indexed/searchable.
        state["last_enqueued_end"], state["pending_window"] = interval[1], None
        _save(checkpoint, state)
        pending.unlink()
        _fsync_directory(state_dir)
        return {
            "status": "recovered_to_queue" if recovered else "captured_to_queue",
            "window_start": interval[0],
            "window_end": interval[1],
            "record_count": receipt.record_count,
            "queue_duplicate": receipt.duplicate,
            "searchable": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--lag-seconds", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        spool = os.environ.get("ATLAS_HEC_SPOOL_DIR")
        if not spool:
            raise CaptureStateError("ATLAS_HEC_SPOOL_DIR is required.")
        result = run_once(
            read_config(args.config),
            args.state_dir,
            Path(spool),
            window_seconds=args.window_seconds,
            lag_seconds=args.lag_seconds,
            token=os.environ.get("SPLUNK_OBSERVABILITY_TOKEN", ""),
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except CaptureStateError as error:
        print(
            f"Health capture paused: {error} No data was declared searchable.",
            file=sys.stderr,
        )
        return 75
    except Exception:
        print(
            "Health capture/queue handoff failed; retained state and captures require retry or operator recovery. No data was declared searchable.",
            file=sys.stderr,
        )
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
