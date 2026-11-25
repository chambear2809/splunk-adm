"""Bounded, owner-verified REST search transport for activation readback.

This module intentionally contains no lab lifecycle, allocation, startup, or
credential handling.  The caller supplies an already-owned transport object.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
import json
import re
import time
from typing import Any
from urllib.parse import quote

MAX_REST_BYTES = 8 * 1024 * 1024
_SEARCH_SID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
_HISTORY_QUERY_RE = re.compile(
    r'search index=atlas_changes sourcetype="adm:configuration_change_activation:v1" '
    r"\| spath input=_raw path=activation_id output=activation_id "
    r'\| where activation_id="([a-f0-9]{64})" '
    r"\| eval timeline_payload=_raw \| table timeline_payload \| head 2"
)


class LabTransportError(RuntimeError):
    """A bounded transport or response validation failure."""


class SearchPermissionDenied(LabTransportError):
    def __init__(self, evidence: Mapping[str, Any]) -> None:
        super().__init__("Selected configuration history access was denied by Splunk.")
        self.evidence = dict(evidence)


class CallerProfile(str, Enum):
    ADMIN = "admin"
    HISTORY_DENIED = "history_denied"


def _caller_profile(value: Any) -> CallerProfile:
    try:
        return CallerProfile(value)
    except (TypeError, ValueError) as exc:
        raise LabTransportError("caller profile is unsupported") from exc


def _is_selected_history_query(query: Any) -> bool:
    return isinstance(query, str) and _HISTORY_QUERY_RE.fullmatch(query) is not None


def _permission_message(messages: Any) -> str | None:
    if not isinstance(messages, list):
        return None
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        text = message.get("text")
        if (
            str(message.get("type", "")).upper()
            in {"WARN", "WARNING", "ERROR", "FATAL"}
            and isinstance(text, str)
            and re.search(r"(?i)permission|authorized|searchable", text)
        ):
            return text
    return None


def _decode_json(raw: bytes | str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


class BoundedSearchClient:
    """Perform one bounded Splunk search through an owned REST transport."""

    def __init__(
        self,
        transport: Any,
        max_rows: int,
        *,
        caller_profile: CallerProfile = CallerProfile.ADMIN,
        query: str = "",
    ) -> None:
        self._transport = transport
        self._max_rows = max_rows
        self._caller_profile = _caller_profile(caller_profile)
        self._owner = (
            "admin"
            if self._caller_profile is CallerProfile.ADMIN
            else transport._search_owner(self._caller_profile)
        )
        self._selected_query = query
        self._sid: str | None = None
        self._last_response_sha256: str | None = None

    def _json(
        self, method: str, path: str, data: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        dispatch = "/servicesNS/admin/splunk_adm/search/v2/jobs"
        owner_path = (
            f"/servicesNS/{quote(self._owner, safe='')}/splunk_adm/search/v2/jobs"
        )
        if method == "POST" and path == dispatch:
            if not isinstance(data, Mapping) or set(data) != {
                "search",
                "exec_mode",
                "earliest_time",
                "latest_time",
            }:
                raise LabTransportError("bounded search dispatch is invalid")
            if data.get("exec_mode") != "blocking" or not isinstance(
                data.get("search"), str
            ):
                raise LabTransportError("bounded search dispatch is invalid")
            if self._caller_profile is CallerProfile.HISTORY_DENIED and data[
                "search"
            ] != self._query(self._selected_query):
                raise LabTransportError(
                    "restricted caller dispatch differs from its selected query"
                )
            request_path, form_encoded, stage = (
                owner_path + "?output_mode=json",
                True,
                "dispatch",
            )
        elif method == "GET" and re.fullmatch(
            r"/services/search/v2/jobs/[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", path
        ):
            sid = path.rsplit("/", 1)[-1]
            if (
                self._caller_profile is CallerProfile.HISTORY_DENIED
                and sid != self._sid
            ):
                raise LabTransportError("restricted caller job identity changed")
            request_path, form_encoded, stage = (
                path + "?output_mode=json",
                False,
                "job_status",
            )
        elif method == "GET" and re.fullmatch(
            r"/services/search/v2/jobs/[A-Za-z0-9][A-Za-z0-9_.-]{0,255}/results\?count=[1-9][0-9]*",
            path,
        ):
            if int(path.rsplit("=", 1)[-1]) != self._max_rows + 1:
                raise LabTransportError("bounded search result count is invalid")
            sid = path.split("/jobs/", 1)[-1].split("/results", 1)[0]
            if (
                self._caller_profile is CallerProfile.HISTORY_DENIED
                and sid != self._sid
            ):
                raise LabTransportError("restricted caller job identity changed")
            request_path, form_encoded, stage = (
                path + "&output_mode=json",
                False,
                "results",
            )
        else:
            raise LabTransportError("bounded search requested an unsupported REST path")
        if self._caller_profile is CallerProfile.HISTORY_DENIED:
            response = self._transport._rest_request(
                method,
                request_path,
                data,
                form_encoded=form_encoded,
                caller_profile=self._caller_profile,
            )
        else:
            response = self._transport._rest_request(
                method, request_path, data, form_encoded=form_encoded
            )
        if not 200 <= response.get("status", 0) < 300:
            if (
                response.get("status") == 403
                and self._caller_profile is CallerProfile.HISTORY_DENIED
                and _is_selected_history_query(self._selected_query)
                and stage == "dispatch"
            ):
                raise SearchPermissionDenied(
                    self._transport._permission_denial_evidence(
                        self._caller_profile,
                        self._selected_query,
                        stage=stage,
                        status_code=403,
                        denial_kind="http_forbidden",
                        response_sha256=response.get("response_sha256"),
                    )
                )
            raise LabTransportError("bounded search REST request failed")
        payload = response.get("body")
        self._last_response_sha256 = response.get("response_sha256")
        if not isinstance(payload, dict):
            raise LabTransportError("Splunk returned malformed bounded search JSON")
        if stage == "dispatch":
            sid = payload.get("sid")
            if not isinstance(sid, str) or not _SEARCH_SID_RE.fullmatch(sid):
                raise LabTransportError("Splunk returned an invalid bounded search SID")
            if self._caller_profile is CallerProfile.HISTORY_DENIED:
                if self._sid is not None:
                    raise LabTransportError("restricted caller started multiple jobs")
                self._sid = sid
        if (
            _permission_message(payload.get("messages")) is not None
            and self._caller_profile is CallerProfile.HISTORY_DENIED
            and _is_selected_history_query(self._selected_query)
        ):
            raise SearchPermissionDenied(
                self._transport._permission_denial_evidence(
                    self._caller_profile,
                    self._selected_query,
                    stage=stage,
                    status_code=response["status"],
                    denial_kind="splunk_permission_message",
                    response_sha256=response.get("response_sha256"),
                )
            )
        messages = payload.get("messages", [])
        if not isinstance(messages, list) or any(
            not isinstance(m, Mapping) or str(m.get("type", "")).upper() != "INFO"
            for m in messages
        ):
            raise LabTransportError(
                "Splunk reported incomplete or malformed search messages"
            )
        return payload

    @staticmethod
    def _query(query: str) -> str:
        text = query.strip()
        return (
            text
            if text.startswith("|") or text.startswith("search ")
            else f"search {text}"
        )

    def _wait_job(self, sid: str, timeout: float = 600) -> dict[str, Any]:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 600
        ):
            raise LabTransportError("bounded search wait limit is invalid")
        deadline = time.monotonic() + float(timeout)
        while True:
            payload = self._json(
                "GET", "/services/search/v2/jobs/" + quote(sid, safe="")
            )
            entries = payload.get("entry")
            if (
                not isinstance(entries, list)
                or len(entries) != 1
                or not isinstance(entries[0], Mapping)
                or not isinstance(entries[0].get("content"), Mapping)
            ):
                raise LabTransportError("Splunk returned malformed search status")
            content = dict(entries[0]["content"])
            if content.get("dispatchState") == "FAILED":
                raise LabTransportError("Splunk bounded search failed")
            if content.get("isDone") is True:
                return content
            if time.monotonic() >= deadline:
                raise LabTransportError("Splunk bounded search did not complete")
            time.sleep(min(1.0, deadline - time.monotonic()))

    def _results(self, sid: str) -> list[dict[str, Any]]:
        payload = self._json(
            "GET",
            f"/services/search/v2/jobs/{quote(sid, safe='')}/results?count={self._max_rows + 1}",
        )
        rows = payload.get("results")
        if not isinstance(rows, list):
            raise LabTransportError("Splunk returned malformed bounded search rows")
        if len(rows) > self._max_rows:
            raise LabTransportError("bounded search returned more rows than requested")
        if payload.get("resultIsTruncated") not in (None, False, 0, "0"):
            raise LabTransportError("Splunk truncated the bounded search results")
        return rows

    def search(
        self, query: str, earliest_time: str, latest_time: str
    ) -> list[dict[str, Any]]:
        payload = self._json(
            "POST",
            "/servicesNS/admin/splunk_adm/search/v2/jobs",
            {
                "search": self._query(query),
                "exec_mode": "blocking",
                "earliest_time": earliest_time,
                "latest_time": latest_time,
            },
        )
        sid = payload["sid"]
        self._wait_job(sid)
        return self._results(sid)
