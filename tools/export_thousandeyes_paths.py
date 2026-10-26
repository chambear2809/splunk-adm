#!/usr/bin/env python3
"""Bounded read-only ThousandEyes CEA path capture using the shared HEC queue.

The API token is read only from THOUSANDEYES_API_TOKEN. This exporter fetches
path summaries and their constructed per-agent/per-round detail routes for
explicitly selected existing tests. It never creates or edits ThousandEyes
tests, follows redirects, or sends HEC data directly.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
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
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
import uuid

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import hec_delivery


API_HOST = "api.thousandeyes.com"
API_ORIGIN = f"https://{API_HOST}"
ATLAS_PATH_SOURCE = "atlas:thousandeyes:path"
ATLAS_PATH_SOURCETYPE = "atlas:thousandeyes:path"
PATH_SCHEMA = "application_atlas.thousandeyes_path.v1"
MAX_WINDOW_SECONDS = 86_400
MAX_TESTS = 16
MAX_PAGES_PER_TEST = 100
MAX_ROUNDS_PER_CAPTURE = 1_000
MAX_CAPTURE_RECORDS = min(hec_delivery.CAPTURE_MAX_RECORDS - 1, MAX_ROUNDS_PER_CAPTURE)
MAX_CAPTURE_BYTES = min(64 * 1024 * 1024, hec_delivery.CAPTURE_MAX_BYTES)
MAX_EVENT_BYTES = min(65_535, hec_delivery.LINE_MAX_BYTES)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES_PER_CAPTURE = 64 * 1024 * 1024
MAX_HTTP_ATTEMPTS = 3
MAX_HTTP_REQUESTS = 3_200
MAX_CAPTURE_SECONDS = 300
MAX_TIMEOUT_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_RETRY_DELAY_SECONDS = 0.25


class ThousandEyesPathExportError(RuntimeError):
    """Safe-to-display failure without source response data or token values."""


class _HTTPFailure(Exception):
    def __init__(
        self,
        status: int,
        retryable: bool,
        headers: dict[str, str] | None = None,
    ):
        self.status = status
        self.retryable = retryable
        self.headers = headers or {}
        super().__init__(f"HTTP_{status}")


class _DuplicateJSONKey(ValueError):
    pass


@dataclass(frozen=True)
class PathExportRequest:
    authority: str
    account_group_id: str
    test_ids: tuple[str, ...]
    target_index: str
    start: int
    end: int
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    def validate(self) -> None:
        if not isinstance(self.authority, str) or not re.fullmatch(
            r"[a-z][a-z0-9._:-]{0,127}", self.authority
        ):
            raise ValueError("authority must be one configured lowercase identity")
        if not isinstance(self.account_group_id, str) or not re.fullmatch(
            r"[1-9][0-9]{0,19}", self.account_group_id
        ):
            raise ValueError("account_group_id must be one literal account-group ID")
        if not isinstance(self.target_index, str) or not re.fullmatch(
            r"[a-z][a-z0-9_-]{0,79}", self.target_index
        ):
            raise ValueError("target_index must be one literal Splunk index")
        if (
            not isinstance(self.test_ids, tuple)
            or not 1 <= len(self.test_ids) <= MAX_TESTS
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value)
                for value in self.test_ids
            )
            or len(set(self.test_ids)) != len(self.test_ids)
        ):
            raise ValueError("test_ids must contain one to 16 unique literal IDs")
        if (
            isinstance(self.start, bool)
            or not isinstance(self.start, int)
            or isinstance(self.end, bool)
            or not isinstance(self.end, int)
            or self.start < 0
            or self.end <= self.start
            or self.end - self.start > MAX_WINDOW_SECONDS
            or self.end > 253_402_300_799
        ):
            raise ValueError("time range must be whole UTC seconds and at most 24h")
        if self.end > int(time.time()) + 60:
            raise ValueError("end must not be in the future")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout must be between 1 and 300 seconds")


@dataclass(frozen=True)
class _HTTPResponse:
    status: int
    body: bytes
    headers: dict[str, str] | None = None


@dataclass
class _CaptureBudget:
    deadline: float
    requests: int = 0
    response_bytes: int = 0


def _safe_source_text(value: Any, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ThousandEyesPathExportError(f"API returned an invalid {label}.")
    return value


def _native_id(value: Any, label: str) -> str:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 9_007_199_254_740_991
    ):
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value
    ):
        raise ThousandEyesPathExportError(f"API returned an invalid {label}.")
    return value


def _matching_native_aliases(
    row: dict[str, Any], fields: tuple[str, ...], label: str, *, required: bool
) -> str | None:
    values = [
        _native_id(row[field], label) for field in fields if row.get(field) is not None
    ]
    if not values:
        if required:
            raise ThousandEyesPathExportError(f"API returned an invalid {label}.")
        return None
    if len(set(values)) != 1:
        raise ThousandEyesPathExportError(
            f"Path response contains conflicting {label} aliases."
        )
    return values[0]


def _round_id(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 253_402_300_799
    ):
        raise ThousandEyesPathExportError("API returned an invalid round ID.")
    return value


def _iso_epoch(value: Any, label: str) -> float:
    if not isinstance(value, str) or len(value) > 64:
        raise ThousandEyesPathExportError(f"API returned an invalid {label}.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ThousandEyesPathExportError(f"API returned an invalid {label}.") from None
    if parsed.tzinfo is None:
        raise ThousandEyesPathExportError(f"API returned an invalid {label}.")
    epoch = parsed.astimezone(timezone.utc).timestamp()
    if not math.isfinite(epoch) or epoch < 0 or epoch > 253_402_300_799:
        raise ThousandEyesPathExportError(f"API returned an invalid {label}.")
    return epoch


def _utc_date(epoch_seconds: int) -> str:
    try:
        value = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise ValueError("time range is outside the supported UTC calendar") from None
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_results_url(
    test_id: str, aid: str, start: int, end: int, *, cursor: str | None = None
) -> str:
    test_id = _native_id(test_id, "test ID")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", aid):
        raise ValueError("aid must be one literal account-group ID")
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or isinstance(end, bool)
        or not isinstance(end, int)
        or start < 0
        or end <= start
        or end - start > MAX_WINDOW_SECONDS
        or end > 253_402_300_799
    ):
        raise ValueError(
            "path result range must use whole UTC seconds and span at most 24h"
        )
    query = [
        ("aid", aid),
        ("startDate", _utc_date(start)),
        ("endDate", _utc_date(end)),
    ]
    if cursor is not None:
        if (
            not cursor
            or len(cursor) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in cursor)
        ):
            raise ValueError("invalid pagination cursor")
        query.append(("cursor", cursor))
    return (
        f"{API_ORIGIN}/v7/test-results/{quote(test_id, safe='')}/path-vis?"
        f"{urlencode(query)}"
    )


def build_detail_url(test_id: str, agent_id: str, round_id: int, aid: str) -> str:
    test_id = _native_id(test_id, "test ID")
    agent_id = _native_id(agent_id, "agent ID")
    round_value = _round_id(round_id)
    if not re.fullmatch(r"[1-9][0-9]{0,19}", aid):
        raise ValueError("aid must be one literal account-group ID")
    path = (
        f"/v7/test-results/{quote(test_id, safe='')}/path-vis/agent/"
        f"{quote(agent_id, safe='')}/round/{round_value}"
    )
    return f"{API_ORIGIN}{path}?{urlencode({'aid': aid})}"


def _validated_page_url(
    href: Any,
    request: PathExportRequest,
    test_id: str,
) -> str:
    if not isinstance(href, str) or len(href) > 8192:
        raise ThousandEyesPathExportError("API pagination link is invalid.")
    try:
        parsed = urlsplit(href)
        port = parsed.port
    except ValueError:
        raise ThousandEyesPathExportError("API pagination link is invalid.") from None
    expected_path = f"/v7/test-results/{quote(test_id, safe='')}/path-vis"
    if (
        parsed.scheme != "https"
        or parsed.hostname != API_HOST
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.fragment
        or parsed.path != expected_path
        or not parsed.query
    ):
        raise ThousandEyesPathExportError(
            "API pagination link is outside the fixed route."
        )
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)) or set(keys) != {
        "aid",
        "startDate",
        "endDate",
        "cursor",
    }:
        raise ThousandEyesPathExportError(
            "API pagination link changed the query scope."
        )
    query = dict(pairs)
    if (
        query["aid"] != request.account_group_id
        or query["startDate"] != _utc_date(request.start)
        or query["endDate"] != _utc_date(request.end)
        or not query["cursor"]
        or len(query["cursor"]) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in query["cursor"])
    ):
        raise ThousandEyesPathExportError(
            "API pagination link changed the identity or date bounds."
        )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-standard JSON number")


def _rate_limit_delay_seconds(headers: dict[str, str]) -> float | None:
    """Return the latest supported API reset hint without trusting response text."""
    candidates: list[float] = []
    retry_after = headers.get("retry-after")
    if retry_after:
        if re.fullmatch(r"[0-9]{1,10}", retry_after):
            candidates.append(float(retry_after))
        else:
            try:
                parsed = parsedate_to_datetime(retry_after)
            except (TypeError, ValueError, OverflowError):
                parsed = None
            if parsed is not None and parsed.tzinfo is not None:
                candidates.append(max(0.0, parsed.timestamp() - time.time()))

    organization_reset = headers.get("x-organization-rate-limit-reset")
    if organization_reset and re.fullmatch(r"[0-9]{1,12}", organization_reset):
        candidates.append(max(0.0, float(organization_reset) - time.time()))

    return max(candidates) if candidates else None


def _decode_object(response: _HTTPResponse) -> dict[str, Any]:
    if not 200 <= response.status < 300:
        raise _HTTPFailure(
            response.status,
            response.status == 429 or response.status >= 500,
            response.headers,
        )
    try:
        parsed = json.loads(
            response.body,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ThousandEyesPathExportError(
            "ThousandEyes returned invalid JSON."
        ) from None
    if not isinstance(parsed, dict):
        raise ThousandEyesPathExportError("ThousandEyes response is not an object.")
    return parsed


def _context(ca_bundle: str | None) -> ssl.SSLContext:
    if ca_bundle:
        path = Path(ca_bundle).expanduser()
        if not path.is_file() or path.is_symlink():
            raise ThousandEyesPathExportError("Configured CA bundle is unavailable.")
        context = ssl.create_default_context(cafile=str(path))
    else:
        context = ssl.create_default_context()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ThousandEyesPathExportError("TLS certificate verification is required.")
    return context


def _valid_api_url(url: str) -> tuple[str, int, str, str]:
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except ValueError:
        raise ThousandEyesPathExportError(
            "ThousandEyes request URL is invalid."
        ) from None
    if (
        parsed.scheme != "https"
        or parsed.hostname != API_HOST
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.fragment
        or parsed.path.count("/") < 4
        or not parsed.path.startswith("/v7/test-results/")
        or not re.fullmatch(
            r"/v7/test-results/[A-Za-z0-9._:%-]+/path-vis(?:/agent/[A-Za-z0-9._:%-]+/round/[0-9]+)?",
            parsed.path,
        )
        or any(ord(char) < 32 or ord(char) == 127 for char in parsed.query)
    ):
        raise ThousandEyesPathExportError(
            "ThousandEyes request URL is outside the fixed API routes."
        )
    return parsed.hostname, port, parsed.path, parsed.query


def _get_json(
    url: str,
    token: str,
    timeout_seconds: float,
    ssl_context: ssl.SSLContext,
) -> _HTTPResponse:
    """Fixed-host HTTPS GET with a total deadline, bounded body and no redirects."""
    hostname, port, path, query = _valid_api_url(url)
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 8192
        or any(ord(char) < 33 or ord(char) > 126 for char in token)
    ):
        raise ValueError("THOUSANDEYES_API_TOKEN is required")
    if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
        raise ThousandEyesPathExportError("TLS certificate verification is required.")
    deadline = time.monotonic() + timeout_seconds
    addresses: list[tuple[Any, ...]] = []
    resolved: list[list[tuple[Any, ...]]] = []
    resolve_error: list[OSError] = []
    resolution_finished = threading.Event()

    def resolve() -> None:
        try:
            resolved.append(socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM))
        except OSError as error:
            resolve_error.append(error)
        finally:
            resolution_finished.set()

    threading.Thread(target=resolve, daemon=True, name="atlas-thousandeyes-dns").start()
    if not resolution_finished.wait(max(0.001, deadline - time.monotonic())):
        raise _HTTPFailure(0, True) from None
    if resolve_error or not resolved or not resolved[0]:
        raise _HTTPFailure(0, True) from None
    addresses = resolved[0]
    active_socket: socket.socket | None = None

    class BoundedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            nonlocal active_socket
            last_error: OSError | None = None
            for family, kind, protocol, _canonical_name, address in addresses:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("ThousandEyes request deadline expired")
                raw = socket.socket(family, kind, protocol)
                raw.settimeout(remaining)
                self.sock = raw
                active_socket = raw
                try:
                    raw.connect(address)
                    wrapped = ssl_context.wrap_socket(
                        raw, server_hostname=hostname, do_handshake_on_connect=False
                    )
                    self.sock = wrapped
                    active_socket = wrapped
                    wrapped.settimeout(max(0.001, deadline - time.monotonic()))
                    wrapped.do_handshake()
                    if time.monotonic() >= deadline:
                        raise TimeoutError("ThousandEyes request deadline expired")
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
            raise TimeoutError("ThousandEyes request deadline expired")

        def send(self, data: Any) -> None:
            if time.monotonic() >= deadline:
                raise TimeoutError("ThousandEyes request deadline expired")
            super().send(data)
            if time.monotonic() >= deadline:
                raise TimeoutError("ThousandEyes request deadline expired")

    connection = BoundedHTTPSConnection(
        hostname,
        port=port,
        timeout=max(0.001, deadline - time.monotonic()),
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

    timer = threading.Timer(
        max(0.001, deadline - time.monotonic()), abort_until_finished
    )
    timer.daemon = True
    timer.start()
    try:
        request_target = path + (f"?{query}" if query else "")
        connection.request(
            "GET",
            request_target,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        active_socket = connection.sock or active_socket
        response = connection.getresponse()
        status = int(response.status)
        if not 200 <= status < 300:
            retry_headers: dict[str, str] = {}
            for name in (
                "Retry-After",
                "X-Organization-Rate-Limit-Reset",
            ):
                value = response.getheader(name)
                if value is not None and len(value) <= 128:
                    retry_headers[name.lower()] = value.strip()
            raise _HTTPFailure(
                status,
                status == 429 or status >= 500,
                retry_headers,
            )
        encoding = response.getheader("Content-Encoding", "identity").strip().lower()
        content_length = response.getheader("Content-Length")
        if encoding not in {"", "identity"} or (
            content_length is not None
            and (
                not content_length.isdecimal()
                or int(content_length) > MAX_RESPONSE_BYTES
            )
        ):
            raise ThousandEyesPathExportError(
                "ThousandEyes response exceeds the configured transfer limits."
            )
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES or time.monotonic() >= deadline:
            raise ThousandEyesPathExportError(
                "ThousandEyes response exceeds the configured transfer limits."
            )
        return _HTTPResponse(status, body)
    except _HTTPFailure:
        raise
    except ThousandEyesPathExportError:
        raise
    except (OSError, http.client.HTTPException, ValueError, TimeoutError, ssl.SSLError):
        raise _HTTPFailure(0, True) from None
    finally:
        request_finished.set()
        timer.cancel()
        connection.close()


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ThousandEyesPathExportError(
            "ThousandEyes response contains invalid JSON values."
        ) from None


def _summary_identity(
    summary: dict[str, Any], request: PathExportRequest, test_id: str
) -> tuple[str, int, tuple[str, ...]]:
    supplied_aid = summary.get("aid")
    if supplied_aid is not None and str(supplied_aid) != request.account_group_id:
        raise ThousandEyesPathExportError("Path summary account identity changed.")
    supplied_test = _matching_native_aliases(
        summary, ("testId", "test_id"), "test ID", required=False
    )
    if supplied_test is not None and str(supplied_test) != test_id:
        raise ThousandEyesPathExportError("Path summary test identity changed.")
    agent = summary.get("agent")
    nested_agent = agent.get("agentId") if isinstance(agent, dict) else None
    agent_aliases = dict(summary)
    if nested_agent is not None:
        agent_aliases["nestedAgentId"] = nested_agent
    agent_id = _matching_native_aliases(
        agent_aliases,
        ("agentId", "agent_id", "nestedAgentId"),
        "agent ID",
        required=True,
    )
    assert agent_id is not None
    round_values = [
        _round_id(summary[field])
        for field in ("roundId", "round_id")
        if summary.get(field) is not None
    ]
    if not round_values or len(set(round_values)) != 1:
        raise ThousandEyesPathExportError(
            "Path summary has missing or conflicting round IDs."
        )
    round_id = round_values[0]
    path_id_sets: list[list[str]] = []
    for field in ("pathTraces", "path_traces"):
        if field not in summary:
            continue
        path_traces = summary[field]
        if not isinstance(path_traces, list) or not path_traces:
            raise ThousandEyesPathExportError("Path summary lacks path iteration IDs.")
        path_ids: list[str] = []
        for trace in path_traces:
            if not isinstance(trace, dict):
                raise ThousandEyesPathExportError(
                    "Path summary contains an invalid iteration."
                )
            path_ids.append(
                _matching_native_aliases(
                    trace, ("pathId", "path_id"), "path ID", required=True
                )
                or ""
            )
        path_id_sets.append(path_ids)
    if not path_id_sets or any(
        sorted(values) != sorted(path_id_sets[0]) for values in path_id_sets[1:]
    ):
        raise ThousandEyesPathExportError(
            "Path summary has missing or conflicting path iterations."
        )
    path_ids = path_id_sets[0]
    if len(set(path_ids)) != len(path_ids):
        raise ThousandEyesPathExportError("Path summary repeats an iteration ID.")
    if not request.start <= round_id <= request.end:
        raise ThousandEyesPathExportError(
            "Path summary returned a round outside the requested interval."
        )
    date_value = summary.get("date")
    if date_value is not None:
        date_time = _iso_epoch(date_value, "path result date")
        if not request.start <= date_time <= request.end:
            raise ThousandEyesPathExportError(
                "Path summary returned a date outside the requested interval."
            )
    return agent_id, round_id, tuple(sorted(path_ids))


def _validated_detail(
    detail: dict[str, Any],
    request: PathExportRequest,
    test_id: str,
    agent_id: str,
    round_id: int,
    summary_path_ids: tuple[str, ...],
) -> dict[str, Any]:
    supplied_aid = detail.get("aid")
    if supplied_aid is not None and str(supplied_aid) != request.account_group_id:
        raise ThousandEyesPathExportError(
            "Path detail identity does not match its request route."
        )
    supplied_test = _matching_native_aliases(
        detail, ("testId", "test_id"), "test ID", required=False
    )
    if supplied_test is not None and supplied_test != test_id:
        raise ThousandEyesPathExportError(
            "Path detail identity does not match its request route."
        )
    supplied_rounds = [
        _round_id(detail[field])
        for field in ("roundId", "round_id")
        if detail.get(field) is not None
    ]
    if not supplied_rounds or any(value != round_id for value in supplied_rounds):
        raise ThousandEyesPathExportError(
            "Path detail round does not match its request route."
        )
    native_agent = detail.get("agent")
    nested_agent = (
        native_agent.get("agentId") if isinstance(native_agent, dict) else None
    )
    agent_aliases = dict(detail)
    if nested_agent is not None:
        agent_aliases["nestedAgentId"] = nested_agent
    actual_agent = _matching_native_aliases(
        agent_aliases,
        ("agentId", "agent_id", "nestedAgentId"),
        "detail agent ID",
        required=True,
    )
    if actual_agent != agent_id:
        raise ThousandEyesPathExportError(
            "Path detail agent does not match its request route."
        )
    detail_date = detail.get("date")
    if (
        detail_date is not None
        and not request.start
        <= _iso_epoch(detail_date, "path detail date")
        <= request.end
    ):
        raise ThousandEyesPathExportError(
            "Path detail date is outside the requested interval."
        )
    traces = detail.get("pathTraces", detail.get("path_traces"))
    if not isinstance(traces, list) or not traces:
        raise ThousandEyesPathExportError("Path detail lacks measured path iterations.")
    detail_path_ids: list[str] = []
    for trace in traces:
        if not isinstance(trace, dict):
            raise ThousandEyesPathExportError(
                "Path detail contains an invalid iteration."
            )
        path_id = _native_id(
            trace.get("pathId", trace.get("path_id")), "detail path ID"
        )
        hops = trace.get("hops")
        if not isinstance(hops, list):
            raise ThousandEyesPathExportError(
                "Path detail does not contain native hop rows."
            )
        detail_path_ids.append(path_id)
    if (
        len(set(detail_path_ids)) != len(detail_path_ids)
        or tuple(sorted(detail_path_ids)) != summary_path_ids
    ):
        raise ThousandEyesPathExportError(
            "Path detail iteration IDs do not match their summary."
        )
    return detail


def _outside_checkouts(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    for ancestor in (resolved, *resolved.parents):
        marker = ancestor / ".git"
        if marker.exists() or marker.is_symlink():
            raise ThousandEyesPathExportError(
                "Path capture files must be outside every Git checkout."
            )
    return resolved


def _private_directory(path: Path) -> Path:
    resolved = _outside_checkouts(path)
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise ThousandEyesPathExportError("Capture directory is invalid.")
    try:
        if resolved.stat().st_uid != os.geteuid():
            raise ThousandEyesPathExportError(
                "Capture directory must be owned by this user."
            )
        os.chmod(resolved, 0o700)
    except OSError:
        raise ThousandEyesPathExportError(
            "Capture directory permissions are unavailable."
        ) from None
    return resolved


def _publish_new(path: Path, content: bytes) -> None:
    if (
        not isinstance(path, Path)
        or not path.name
        or path.name in {".", ".."}
        or any(ord(char) < 32 or ord(char) == 127 for char in path.name)
    ):
        raise ThousandEyesPathExportError("Capture output path is invalid.")
    if path.is_symlink() or path.exists():
        raise FileExistsError("output path already exists")
    parent = _private_directory(path.parent)
    target = parent / path.name
    if target.is_symlink() or target.exists():
        raise FileExistsError("output path already exists")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".partial",
            delete=False,
        ) as handle:
            temporary = handle.name
            os.chmod(temporary, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
        os.unlink(temporary)
        temporary = None
        os.chmod(target, 0o600)
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def collect_path_results(
    request: PathExportRequest,
    token: str,
    *,
    ca_bundle: str | None = None,
    get_json: Callable[[str, str, float, ssl.SSLContext], _HTTPResponse] = _get_json,
    captured_at: int | None = None,
    monotonic: Any = time.monotonic,
    sleep: Any = time.sleep,
) -> tuple[list[dict[str, Any]], str, int]:
    """Read bounded path summaries and constructed detail routes for selected tests."""
    request.validate()
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 8192
        or any(ord(char) < 33 or ord(char) > 126 for char in token)
    ):
        raise ValueError("THOUSANDEYES_API_TOKEN is required")
    context = _context(ca_bundle)
    started = int(time.time()) if captured_at is None else captured_at
    if isinstance(started, bool) or not isinstance(started, int) or started < 0:
        raise ValueError("capture time is invalid")
    capture_id = str(uuid.uuid4())
    deadline = monotonic() + min(request.timeout_seconds, MAX_CAPTURE_SECONDS)
    budget = _CaptureBudget(deadline=deadline)

    def get(url: str) -> dict[str, Any]:
        attempt = 0
        while True:
            attempt += 1
            remaining = budget.deadline - monotonic()
            if remaining <= 0:
                raise ThousandEyesPathExportError(
                    "ThousandEyes path export exceeded its time limit."
                )
            if budget.requests >= MAX_HTTP_REQUESTS:
                raise ThousandEyesPathExportError(
                    "ThousandEyes path export exceeded its request cap."
                )
            budget.requests += 1
            try:
                response = get_json(
                    url, token, min(request.timeout_seconds, remaining), context
                )
                if len(response.body) > MAX_RESPONSE_BYTES:
                    raise ThousandEyesPathExportError(
                        "ThousandEyes response exceeds the configured byte limit."
                    )
                budget.response_bytes += len(response.body)
                if budget.response_bytes > MAX_RESPONSE_BYTES_PER_CAPTURE:
                    raise ThousandEyesPathExportError(
                        "ThousandEyes path export exceeded its total response byte cap."
                    )
                return _decode_object(response)
            except _HTTPFailure as error:
                remaining = budget.deadline - monotonic()
                if (
                    not error.retryable
                    or attempt >= MAX_HTTP_ATTEMPTS
                    or remaining <= 0
                ):
                    raise ThousandEyesPathExportError(
                        "ThousandEyes path request failed."
                    ) from None
                if error.status == 429:
                    delay = _rate_limit_delay_seconds(error.headers)
                    if delay is None:
                        raise ThousandEyesPathExportError(
                            "ThousandEyes rate limit response omitted a supported reset delay."
                        ) from None
                    delay = max(delay, DEFAULT_RETRY_DELAY_SECONDS)
                    if delay >= remaining:
                        raise ThousandEyesPathExportError(
                            "ThousandEyes rate limit reset exceeds the remaining capture deadline."
                        ) from None
                else:
                    delay = min(
                        DEFAULT_RETRY_DELAY_SECONDS * (2 ** (attempt - 1)),
                        4,
                        remaining,
                    )
                sleep(delay)

    all_summaries: dict[tuple[str, str, int], tuple[tuple[str, ...], bytes]] = {}
    for test_id in request.test_ids:
        page_url = build_results_url(
            test_id, request.account_group_id, request.start, request.end
        )
        seen_pages: set[str] = set()
        for _page_number in range(MAX_PAGES_PER_TEST):
            if page_url in seen_pages:
                raise ThousandEyesPathExportError(
                    "ThousandEyes repeated a pagination page."
                )
            seen_pages.add(page_url)
            page = get(page_url)
            summaries = page.get("results")
            if not isinstance(summaries, list) or any(
                not isinstance(item, dict) for item in summaries
            ):
                raise ThousandEyesPathExportError(
                    "ThousandEyes path page lacks a result array."
                )
            for summary in summaries:
                agent_id, round_id, path_ids = _summary_identity(
                    summary, request, test_id
                )
                key = (test_id, agent_id, round_id)
                encoded = _json_bytes(summary)
                previous = all_summaries.get(key)
                if previous is not None:
                    if previous != (path_ids, encoded):
                        raise ThousandEyesPathExportError(
                            "Conflicting path summaries share one round identity."
                        )
                    continue
                all_summaries[key] = (path_ids, encoded)
                if len(all_summaries) > MAX_ROUNDS_PER_CAPTURE:
                    raise ThousandEyesPathExportError(
                        "ThousandEyes path export exceeded its round cap."
                    )
            links = page.get("_links", {})
            if not isinstance(links, dict):
                raise ThousandEyesPathExportError(
                    "ThousandEyes path pagination metadata is invalid."
                )
            next_link = links.get("next")
            if next_link is None:
                break
            if not isinstance(next_link, dict):
                raise ThousandEyesPathExportError(
                    "ThousandEyes next-page link is invalid."
                )
            href = next_link.get("href")
            if isinstance(href, str) and href.startswith("/"):
                href = urljoin(API_ORIGIN, href)
            page_url = _validated_page_url(href, request, test_id)
        else:
            raise ThousandEyesPathExportError(
                "ThousandEyes path export exceeded the page cap."
            )

    if not all_summaries:
        raise ThousandEyesPathExportError(
            "No path results were returned for the selected tests and interval."
        )
    validated_details: list[tuple[str, str, int, dict[str, Any]]] = []
    for test_id, agent_id, round_id in sorted(all_summaries):
        path_ids, _summary_bytes = all_summaries[(test_id, agent_id, round_id)]
        detail_url = build_detail_url(
            test_id, agent_id, round_id, request.account_group_id
        )
        detail = _validated_detail(
            get(detail_url), request, test_id, agent_id, round_id, path_ids
        )
        validated_details.append((test_id, agent_id, round_id, detail))

    completed = int(time.time())
    wrappers: list[dict[str, Any]] = []
    for test_id, agent_id, round_id, detail in validated_details:
        wrapper = {
            "schema": PATH_SCHEMA,
            "schema_version": 1,
            "capture_id": capture_id,
            "record_id": hashlib.sha256(
                f"{capture_id}:{test_id}:{agent_id}:{round_id}".encode("utf-8")
            ).hexdigest(),
            "authority": request.authority,
            "account_group_id": request.account_group_id,
            "test_id": test_id,
            "test_domain": "cea",
            "collection_started_at": started,
            "collection_completed_at": completed,
            "result": detail,
        }
        encoded = _json_bytes(wrapper)
        if len(encoded) + 1 > MAX_EVENT_BYTES:
            raise ThousandEyesPathExportError(
                "Path detail exceeds the configured record byte cap."
            )
        wrappers.append(wrapper)
        if len(wrappers) > MAX_CAPTURE_RECORDS:
            raise ThousandEyesPathExportError(
                "ThousandEyes path export exceeded its record cap."
            )
    return wrappers, capture_id, completed


def render_hec_ndjson(
    request: PathExportRequest,
    wrappers: list[dict[str, Any]],
    *,
    capture_id: str,
    captured_at: int,
) -> bytes:
    request.validate()
    if not wrappers or len(wrappers) > MAX_CAPTURE_RECORDS:
        raise ValueError("capture must contain one to 1,000 path detail records")
    lines: list[bytes] = []
    for wrapper in wrappers:
        if (
            wrapper.get("schema") != PATH_SCHEMA
            or wrapper.get("schema_version") != 1
            or wrapper.get("capture_id") != capture_id
            or wrapper.get("authority") != request.authority
            or wrapper.get("account_group_id") != request.account_group_id
            or wrapper.get("test_id") not in request.test_ids
            or wrapper.get("test_domain") != "cea"
        ):
            raise ValueError("path wrapper identity does not match the capture request")
        envelope = {
            "time": captured_at,
            "index": request.target_index,
            "source": ATLAS_PATH_SOURCE,
            "sourcetype": ATLAS_PATH_SOURCETYPE,
            "event": wrapper,
        }
        line = _json_bytes(envelope)
        if len(line) + 1 > MAX_EVENT_BYTES:
            raise ValueError("capture envelope exceeds the configured record byte cap")
        lines.append(line + b"\n")
    content = b"".join(lines)
    if len(content) > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds the configured byte cap")
    return content


def _parse_time(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError("use ISO-8601 time with UTC offset") from None
    if parsed.tzinfo is None or parsed.microsecond:
        raise argparse.ArgumentTypeError(
            "time must include an offset and whole seconds"
        )
    epoch = parsed.astimezone(timezone.utc).timestamp()
    if not math.isfinite(epoch) or epoch < 0 or epoch > 253_402_300_799:
        raise argparse.ArgumentTypeError("time is outside supported bounds")
    return int(epoch)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--aid", required=True)
    parser.add_argument("--test-id", action="append", required=True)
    parser.add_argument("--index", required=True)
    parser.add_argument("--start", required=True, type=_parse_time)
    parser.add_argument("--end", required=True, type=_parse_time)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spool-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    request = PathExportRequest(
        authority=args.authority,
        account_group_id=args.aid,
        test_ids=tuple(args.test_id),
        target_index=args.index,
        start=args.start,
        end=args.end,
        timeout_seconds=args.timeout,
    )
    try:
        token = os.environ.get("THOUSANDEYES_API_TOKEN", "")
        wrappers, capture_id, captured_at = collect_path_results(
            request,
            token,
            ca_bundle=str(args.ca_bundle) if args.ca_bundle else None,
        )
        content = render_hec_ndjson(
            request,
            wrappers,
            capture_id=capture_id,
            captured_at=captured_at,
        )
        _publish_new(args.output, content)
        receipt = hec_delivery.enqueue_capture(
            args.output,
            args.spool_dir,
            source_id="thousandeyes_path",
        )
        print(
            json.dumps(
                {
                    "capture_id": capture_id,
                    "record_count": receipt.record_count,
                    "byte_count": receipt.byte_count,
                    "duplicate": receipt.duplicate,
                    "queued": True,
                },
                sort_keys=True,
            )
        )
        return 0
    except (
        OSError,
        ValueError,
        hec_delivery.DeliveryError,
        ThousandEyesPathExportError,
    ) as error:
        print(f"ThousandEyes path export unavailable: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
