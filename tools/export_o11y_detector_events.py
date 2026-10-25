#!/usr/bin/env python3
"""Export a bounded history of configured Splunk Observability detector events.

The token is read only from SPLUNK_OBSERVABILITY_TOKEN. The exporter performs
read-only GETs and writes finalized HEC event envelopes to a new mode-0600 file.
It does not send events to Splunk or reconstruct incident state.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
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
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlencode, urlsplit
import uuid


SCHEMA = "application_atlas.o11y_detector_event.v1"
SOURCETYPE = "atlas:o11y_detector_event"
MAX_WINDOW_SECONDS = 86_400
MAX_DETECTORS = 16
PAGE_SIZE = 1_000
MAX_EVENTS_PER_CAPTURE = 10_000
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 65_536  # app TRUNCATE boundary including the JSONL newline
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
HTTP_ATTEMPTS = 3
DEFAULT_TIMEOUT_SECONDS = 30
MAX_CAPTURE_SECONDS = 300


class DetectorExportError(RuntimeError):
    """Safe-to-display export failure without a token or source response body."""


@dataclass(frozen=True)
class DetectorExportRequest:
    observer: str
    organization_id: str
    realm: str
    scope: str
    cluster: str
    detector_ids: tuple[str, ...]
    start: float
    end: float
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    def validate(self) -> None:
        for name in ("observer", "organization_id", "scope", "cluster"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                raise ValueError(f"{name} is invalid")
        if self.observer != self.observer.lower():
            raise ValueError("observer must be a lowercase ingestion identity")
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", self.realm):
            raise ValueError("realm is invalid")
        if (
            not isinstance(self.detector_ids, tuple)
            or not 1 <= len(self.detector_ids) <= MAX_DETECTORS
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
                for value in self.detector_ids
            )
            or len(set(self.detector_ids)) != len(self.detector_ids)
        ):
            raise ValueError("detector_ids must contain one to 16 unique literal IDs")
        if (
            isinstance(self.start, bool)
            or not isinstance(self.start, (int, float))
            or isinstance(self.end, bool)
            or not isinstance(self.end, (int, float))
            or not math.isfinite(self.start)
            or not math.isfinite(self.end)
            or self.start < 0
            or self.end <= self.start
            or self.end - self.start > MAX_WINDOW_SECONDS
        ):
            raise ValueError("window must be an interval no longer than 24h")
        if (
            isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 300
        ):
            raise ValueError("timeout must be between 1 and 300 seconds")


@dataclass(frozen=True)
class _HTTPResponse:
    status: int
    body: bytes


class _HTTPFailure(Exception):
    def __init__(self, status: int, retryable: bool):
        self.status = status
        self.retryable = retryable
        super().__init__(f"HTTP_{status}")


def build_events_url(
    realm: str,
    detector_id: str,
    start: float,
    end: float,
    *,
    offset: int,
    limit: int = PAGE_SIZE,
) -> str:
    """Build a realm-scoped, paged v2 detector events GET URL."""
    if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", realm):
        raise ValueError("realm is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", detector_id):
        raise ValueError("detector ID is invalid")
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= PAGE_SIZE
    ):
        raise ValueError("pagination values are invalid")
    if (
        isinstance(start, bool)
        or not isinstance(start, (int, float))
        or isinstance(end, bool)
        or not isinstance(end, (int, float))
        or not math.isfinite(start)
        or not math.isfinite(end)
        or start < 0
        or end <= start
    ):
        raise ValueError("event time interval is invalid")
    host = f"api.{realm}.observability.splunkcloud.com"
    query = urlencode(
        {
            "from": int(start * 1000),
            "to": int(end * 1000),
            "offset": offset,
            "limit": limit,
        }
    )
    return f"https://{host}/v2/detector/{quote(detector_id, safe='')}/events?{query}"


def _get_json(
    url: str,
    token: str,
    timeout_seconds: int,
    ssl_context: ssl.SSLContext,
) -> _HTTPResponse:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or 443
    except ValueError:
        raise DetectorExportError("Observability request URL is invalid.") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or not re.fullmatch(
            r"api\.[a-z][a-z0-9]{0,7}\.observability\.splunkcloud\.com", hostname
        )
        or parsed.port not in (None, 443)
        or not parsed.path.startswith("/v2/detector/")
        or "\r" in parsed.query
        or "\n" in parsed.query
    ):
        raise DetectorExportError("Observability request URL is invalid.")
    headers = {
        "X-SF-TOKEN": token,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    request_target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
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
                    socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
                )
            except OSError as error:
                resolve_error.append(error)
            finally:
                resolution_finished.set()

        threading.Thread(
            target=resolve, daemon=True, name="atlas-o11y-detector-dns"
        ).start()
        if not resolution_finished.wait(timeout_seconds):
            raise _HTTPFailure(0, True) from None
        if resolve_error or not resolved or not resolved[0]:
            raise _HTTPFailure(0, True) from None
        addresses = resolved[0]
    else:
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        socket_address = (
            (str(address), port) if address.version == 4 else (str(address), port, 0, 0)
        )
        addresses = [
            (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", socket_address)
        ]

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _HTTPFailure(0, True) from None
    active_socket: socket.socket | None = None

    class BoundedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            nonlocal active_socket
            last_error: OSError | None = None
            for family, kind, protocol, _canonical_name, address_tuple in addresses:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise TimeoutError("Observability request deadline expired")
                raw = socket.socket(family, kind, protocol)
                raw.settimeout(remaining_time)
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
                        raise TimeoutError("Observability request deadline expired")
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
            raise TimeoutError("Observability request deadline expired")

        def send(self, data: Any) -> None:
            if time.monotonic() >= deadline:
                raise TimeoutError("Observability request deadline expired")
            super().send(data)
            if time.monotonic() >= deadline:
                raise TimeoutError("Observability request deadline expired")

    connection = BoundedHTTPSConnection(
        hostname,
        port=port,
        timeout=remaining,
        context=ssl_context,
    )

    def abort_request() -> None:
        current = connection.sock or active_socket
        if current is not None:
            try:
                current.shutdown(socket.SHUT_RDWR)
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
        connection.request("GET", request_target, headers=headers)
        active_socket = connection.sock or active_socket
        response = connection.getresponse()
        status = int(response.status)
        if not 200 <= status < 300:
            raise _HTTPFailure(status, status == 429 or status >= 500)
        encoding = response.getheader("Content-Encoding", "identity").strip().lower()
        if encoding not in {"", "identity"}:
            raise DetectorExportError("Observability response encoding is unsupported.")
        content_length = response.getheader("Content-Length")
        if content_length is not None and (
            not content_length.isdecimal() or int(content_length) > MAX_RESPONSE_BYTES
        ):
            raise DetectorExportError(
                "Observability response exceeds the configured limit."
            )
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise DetectorExportError(
                "Observability response exceeds the configured limit."
            )
        if time.monotonic() >= deadline:
            raise TimeoutError("Observability request deadline expired")
        return _HTTPResponse(status, body)
    except _HTTPFailure:
        raise
    except (OSError, http.client.HTTPException, ValueError, TimeoutError, ssl.SSLError):
        raise _HTTPFailure(0, True) from None
    finally:
        request_finished.set()
        timer.cancel()
        connection.close()


def _decode_page(response: _HTTPResponse) -> list[dict[str, Any]]:
    if not 200 <= response.status < 300:
        raise _HTTPFailure(
            response.status, response.status == 429 or response.status >= 500
        )
    try:
        parsed = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DetectorExportError("Observability returned invalid JSON.") from None
    if not isinstance(parsed, list) or any(
        not isinstance(item, dict) for item in parsed
    ):
        raise DetectorExportError("Detector events response is not an event array.")
    return parsed


def _context(ca_bundle: str | None) -> ssl.SSLContext:
    if ca_bundle:
        ca_path = Path(ca_bundle).expanduser()
        if not ca_path.is_file() or ca_path.is_symlink():
            raise DetectorExportError("Configured CA bundle is unavailable.")
        return ssl.create_default_context(cafile=str(ca_path))
    return ssl.create_default_context()


def _event_timestamp_ms(event: Mapping[str, Any]) -> int:
    value = event.get("timestamp")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DetectorExportError("Detector event lacks a numeric timestamp.")
    if not math.isfinite(value) or value < 0 or value > 253_402_300_799_999:
        raise DetectorExportError(
            "Detector event timestamp is outside supported bounds."
        )
    return int(value)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise DetectorExportError(
            "Detector event contains unsupported JSON values."
        ) from None


def _optional_text(
    event: Mapping[str, Any], key: str, maximum: int = 512
) -> str | None:
    value = event.get(key)
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DetectorExportError(f"Detector event field {key} is malformed.")
    return value


def _record_id(capture_id: str, detector_id: str, event: Mapping[str, Any]) -> str:
    identity = _optional_text(event, "id") or _optional_text(event, "eventId") or ""
    timestamp = _event_timestamp_ms(event)
    canonical = _canonical_json(event)
    material = json.dumps(
        [capture_id, detector_id, identity, timestamp, canonical],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _event_records(
    request: DetectorExportRequest,
    event_batches: Mapping[str, list[dict[str, Any]]],
    capture_id: str,
    captured_at: int,
) -> list[dict[str, Any]]:
    start_ms = int(request.start * 1000)
    end_ms = int(request.end * 1000)
    output: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], str] = {}
    for detector_id in request.detector_ids:
        for source_event in event_batches[detector_id]:
            timestamp = _event_timestamp_ms(source_event)
            if not start_ms <= timestamp <= end_ms:
                raise DetectorExportError(
                    "Detector API returned an event outside the requested interval."
                )
            reported_detector_id = source_event.get("detectorId")
            if reported_detector_id is not None and reported_detector_id != detector_id:
                raise DetectorExportError(
                    "Detector API returned an event for another detector."
                )
            record_id = _record_id(capture_id, detector_id, source_event)
            event_identity = (
                detector_id,
                _optional_text(source_event, "id")
                or _optional_text(source_event, "eventId")
                or record_id,
            )
            source_digest = hashlib.sha256(
                _canonical_json(source_event).encode("utf-8")
            ).hexdigest()
            previous = seen.get(event_identity)
            if previous is not None:
                if previous != source_digest:
                    raise DetectorExportError(
                        "Duplicate detector event ID has conflicting event content."
                    )
                continue
            seen[event_identity] = source_digest
            event = {
                "schema": SCHEMA,
                "event_type": "detector_event",
                "capture_id": capture_id,
                "record_id": record_id,
                "captured_at": captured_at,
                "capture_window_start": request.start,
                "capture_window_end": request.end,
                "observer_id": request.observer,
                "organization_id": request.organization_id,
                "realm": request.realm,
                "routing_scope": request.scope,
                "cluster": request.cluster,
                "configured_detector_ids": list(request.detector_ids),
                "detector_id": detector_id,
                "event_id": _optional_text(source_event, "id")
                or _optional_text(source_event, "eventId"),
                "incident_id": _optional_text(source_event, "incidentId"),
                "rule_id": _optional_text(source_event, "ruleId"),
                "detector_label": _optional_text(source_event, "detectLabel"),
                "source_event_type": _optional_text(source_event, "eventType"),
                "anomaly_state": _optional_text(source_event, "anomalyState"),
                "severity": _optional_text(source_event, "severity"),
                "event_timestamp_ms": timestamp,
                "source_event_json": _canonical_json(source_event),
            }
            envelope = {
                "time": captured_at,
                "host": request.observer,
                "source": "atlas:o11y_detector_events/export",
                "sourcetype": SOURCETYPE,
                "event": event,
            }
            line = _canonical_json(envelope).encode("utf-8")
            if len(line) + 1 > MAX_EVENT_BYTES:
                raise DetectorExportError(
                    "Detector event exceeds the configured record size limit."
                )
            output.append(event)
            if len(output) > MAX_EVENTS_PER_CAPTURE:
                raise DetectorExportError("Detector export exceeded the event cap.")
    output.sort(
        key=lambda row: (
            row["detector_id"],
            row["event_timestamp_ms"],
            row.get("event_id") or "",
            row["record_id"],
        )
    )
    return output


def collect_detector_events(
    request: DetectorExportRequest,
    token: str,
    *,
    ca_bundle: str | None = None,
    get_json: Callable[[str, str, int, ssl.SSLContext], _HTTPResponse] = _get_json,
    captured_at: int | None = None,
) -> list[dict[str, Any]]:
    """Read all configured detector event pages for one closed UTC interval."""
    request.validate()
    if not isinstance(token, str) or not token or "\n" in token or "\r" in token:
        raise ValueError("SPLUNK_OBSERVABILITY_TOKEN is required")
    ssl_context = _context(ca_bundle)
    captured = int(time.time()) if captured_at is None else captured_at
    if isinstance(captured, bool) or not isinstance(captured, int) or captured < 0:
        raise ValueError("capture time is invalid")
    event_batches: dict[str, list[dict[str, Any]]] = {}
    total = 0
    capture_deadline = time.monotonic() + MAX_CAPTURE_SECONDS
    for detector_id in request.detector_ids:
        events: list[dict[str, Any]] = []
        offset = 0
        while True:
            remaining = MAX_EVENTS_PER_CAPTURE - total
            limit = min(PAGE_SIZE, remaining + 1)
            url = build_events_url(
                request.realm,
                detector_id,
                request.start,
                request.end,
                offset=offset,
                limit=limit,
            )
            attempt = 0
            while True:
                attempt += 1
                remaining = capture_deadline - time.monotonic()
                if remaining <= 0:
                    raise DetectorExportError(
                        "Detector event export exceeded its total time limit."
                    )
                try:
                    response = get_json(
                        url, token, min(request.timeout_seconds, remaining), ssl_context
                    )
                    page = _decode_page(response)
                    break
                except _HTTPFailure as error:
                    remaining = capture_deadline - time.monotonic()
                    if (
                        not error.retryable
                        or attempt >= HTTP_ATTEMPTS
                        or remaining <= 0
                    ):
                        raise DetectorExportError(
                            "Observability detector event request failed."
                        ) from None
                    time.sleep(min(2 ** (attempt - 1), 4, remaining))
            if len(page) > limit:
                raise DetectorExportError(
                    "Detector events response exceeded the requested page size."
                )
            events.extend(page)
            total += len(page)
            if total > MAX_EVENTS_PER_CAPTURE:
                raise DetectorExportError("Detector export exceeded the event cap.")
            if len(page) < limit:
                break
            offset += len(page)
        event_batches[detector_id] = events
    capture_id = str(uuid.uuid4())
    return _event_records(request, event_batches, capture_id, captured)


def render_hec_ndjson(
    request: DetectorExportRequest,
    events: list[dict[str, Any]],
    *,
    captured_at: int,
    capture_id: str | None = None,
) -> str:
    if len(events) > MAX_EVENTS_PER_CAPTURE:
        raise ValueError("capture exceeds its event cap")
    if capture_id is None:
        capture_id = str(uuid.uuid4())
    completion = {
        "schema": SCHEMA,
        "event_type": "export_completion",
        "capture_id": capture_id,
        "record_id": hashlib.sha256(f"{capture_id}:completion".encode()).hexdigest(),
        "captured_at": captured_at,
        "capture_window_start": request.start,
        "capture_window_end": request.end,
        "observer_id": request.observer,
        "organization_id": request.organization_id,
        "realm": request.realm,
        "routing_scope": request.scope,
        "cluster": request.cluster,
        "configured_detector_ids": list(request.detector_ids),
        "expected_record_count": len(events),
    }
    output = []
    for event in events:
        if event.get("capture_id") != capture_id:
            raise ValueError("event capture IDs do not agree")
        output.append(
            {
                "time": captured_at,
                "host": request.observer,
                "source": "atlas:o11y_detector_events/export",
                "sourcetype": SOURCETYPE,
                "event": event,
            }
        )
    output.append(
        {
            "time": captured_at,
            "host": request.observer,
            "source": "atlas:o11y_detector_events/export",
            "sourcetype": SOURCETYPE,
            "event": completion,
        }
    )
    content = "".join(_canonical_json(row) + "\n" for row in output)
    if len(content.encode("utf-8")) > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds the configured byte cap")
    return content


def _publish_new(path: Path, content: str) -> None:
    if path.is_symlink() or path.exists():
        raise FileExistsError("output path already exists")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".partial",
            delete=False,
        ) as handle:
            temporary = handle.name
            os.chmod(temporary, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        os.unlink(temporary)
        temporary = None
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _parse_time(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("use ISO-8601 time with UTC offset") from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("time must include a UTC offset")
    return parsed.astimezone(timezone.utc).timestamp()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", required=True)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--detector-id", action="append", required=True)
    parser.add_argument("--start", required=True, type=_parse_time)
    parser.add_argument("--end", required=True, type=_parse_time)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    request = DetectorExportRequest(
        observer=args.observer,
        organization_id=args.organization_id,
        realm=args.realm,
        scope=args.scope,
        cluster=args.cluster,
        detector_ids=tuple(args.detector_id),
        start=args.start,
        end=args.end,
        timeout_seconds=args.timeout,
    )
    try:
        token = os.environ.get("SPLUNK_OBSERVABILITY_TOKEN")
        events = collect_detector_events(
            request,
            token or "",
            ca_bundle=str(args.ca_bundle) if args.ca_bundle else None,
        )
        capture_id = events[0]["capture_id"] if events else str(uuid.uuid4())
        captured_at = events[0]["captured_at"] if events else int(time.time())
        _publish_new(
            args.output,
            render_hec_ndjson(
                request, events, captured_at=captured_at, capture_id=capture_id
            ),
        )
        print(json.dumps({"capture_id": capture_id, "event_count": len(events)}))
        return 0
    except (DetectorExportError, FileExistsError, OSError, ValueError):
        print(
            "Observability detector event export failed; no partial capture was published.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
