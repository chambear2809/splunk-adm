#!/usr/bin/env python3
"""Guarded source-only role narrowing for an existing non-admin investigator.

Requires an externally prepared private case and original capture request.
"""

import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import threading
import time
import stat
import sys
from urllib.parse import quote, urlencode

from qualify_native_real_source import installed_request, journal_append, journal_events

STAGE = Path("/opt/splunk/var/atlas-real-revocation-20261118")
PROFILE = Path("/opt/splunk/etc/apps/splunk_adm/local/adm_identity.conf")
PROFILE_HASH = "1e7d289037f437f48bc1cc48c2d6003a2b3298d63b1eeac7632e2754677e948e"
FINGERPRINT = "23337b1eb5770878cf5098f123ca7db4d3af4bebb6b213470e43a1ca91db4341"
EVIDENCE_HASH = "3f749c656afab7c0a56369437226c88e4e2cc397c9b1b49a7050685d73bf31e8"
SCOPE = {
    "service": "coreapi",
    "environment": "lab",
    "cluster": "k8s-01.uktme.cisco.com",
    "namespace": "tenant-jobs",
}
WINDOWS = [
    {"start": 1794844500, "end": 1794844560},
    {"start": 1794844560, "end": 1794844620},
]
SOURCE = "atlas:k8s:uktme:tenant-jobs"
BASE_FILTER = '((index="atlas_identity" source="atlas:identity:uktme" sourcetype="adm:pod_ip_interval:v2") OR (index="otel_traces" source="atlas:k8s:uktme:tenant-jobs" sourcetype="otel:traces")) AND _time>=1794844500 AND _time<1794844620'
MAX_INPUT = 65536


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


COUNT_INFO = "Your timerange was substituted based on your search string"
COUNT_INFO_SHA256 = "efd5f3b2ef4858dff7751a36e5683c0c9f1d4263386122dea1eb0459d9a288fc"
ROLE_WINDOW = (1794844500, 1794844620)


def validate_count_observation(
    data, job, principal, sid, query, start, end, *, task_role
):
    """Validate one fixture count and its actual native job, never app capture."""
    from adm_cases_lib.native import NativeComparisonSearch, _absolute

    require(
        type(start) is int
        and type(end) is int
        and start < end
        and type(task_role) is bool,
        "invalid count window",
    )
    require(
        isinstance(sid, str)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid) is not None,
        "invalid count SID",
    )
    record = {
        "server_sid": sid,
        "query_hash": hashlib.sha256(query.encode()).hexdigest(),
        "window_start": start,
        "window_end": end,
    }
    NativeComparisonSearch._verify_metadata(
        principal, record, job, require_complete=True
    )
    entry = job["entry"][0]
    content = entry["content"]
    require(
        entry.get("sid") in (None, "", sid) and job.get("sid") in (None, "", sid),
        "conflicting count SID",
    )
    false = (False, 0, "0")
    require(
        content.get("isFailed") in false
        and content.get("isFinalized") in false
        and content.get("eventIsTruncated") in false
        and content.get("resultIsTruncated", False) in false
        and str(content.get("dropCount")) == "0"
        and str(content.get("resultCount")) == "1",
        "native count incomplete",
    )
    effective_start = max(start, ROLE_WINDOW[0]) if task_role else start
    effective_end = min(end, ROLE_WINDOW[1]) if task_role else end
    require(effective_start < effective_end, "empty role intersection")

    def normalized(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return str(value) if abs(value) <= 10**16 and math.isfinite(value) else None
        return value if isinstance(value, str) and len(value) <= 80 else None

    earliest, latest = (
        normalized(content.get("earliestTime")),
        normalized(content.get("latestTime")),
    )
    require(
        _absolute(earliest, effective_start) and _absolute(latest, effective_end),
        "effective count window differs",
    )
    for name, requested, effective in (
        ("searchEarliestTime", start, effective_start),
        ("searchLatestTime", end, effective_end),
    ):
        value = content.get(name)
        if value not in (None, ""):
            value = normalized(value)
            require(
                value is not None
                and (_absolute(value, requested) or _absolute(value, effective)),
                "search count window differs",
            )
    require(
        isinstance(data, dict) and data.get("preview") in (False, 0, "0"),
        "count preview or response unavailable",
    )
    rows = data.get("results")
    require(
        isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
        "count row unavailable",
    )
    count = rows[0].get("count")
    require(
        isinstance(count, (str, int))
        and not isinstance(count, bool)
        and str(count).isdigit()
        and len(str(count)) <= 20,
        "invalid count",
    )
    message_locations = []
    for location, messages, optional in (
        ("job", job.get("messages"), True),
        ("job_content", content.get("messages"), True),
        ("results", data.get("messages"), False),
    ):
        if messages is None and optional:
            continue
        require(
            isinstance(messages, list) and len(messages) <= 1,
            "unsupported count messages",
        )
        if messages:
            message = messages[0]
            require(
                isinstance(message, dict)
                and set(message) == {"type", "text"}
                and message.get("type") == "INFO"
                and message.get("text") == COUNT_INFO
                and hashlib.sha256(message["text"].encode()).hexdigest()
                == COUNT_INFO_SHA256,
                "unsupported count message",
            )
            message_locations.append(location)
    retained_content = {
        key: content.get(key)
        for key in (
            "sid",
            "dispatchState",
            "isDone",
            "isFailed",
            "isFinalized",
            "eventIsTruncated",
            "resultIsTruncated",
            "dropCount",
            "resultCount",
            "search",
            "earliestTime",
            "latestTime",
            "searchEarliestTime",
            "searchLatestTime",
            "messages",
        )
    }
    if "resultIsTruncated" not in content:
        retained_content.pop("resultIsTruncated")
    retained_content["request"] = {
        key: content["request"].get(key)
        for key in ("id", "search", "earliest_time", "latest_time")
    }
    retained_job = {
        "entry": [
            {
                "sid": entry.get("sid"),
                "acl": {"owner": entry["acl"]["owner"], "app": entry["acl"]["app"]},
                "content": retained_content,
            }
        ],
        "sid": job.get("sid"),
        "messages": job.get("messages"),
    }
    return {
        "count": int(count),
        "message": COUNT_INFO if message_locations else None,
        "message_sha256": COUNT_INFO_SHA256 if message_locations else None,
        "message_locations": message_locations,
        "effective_start": earliest,
        "effective_end": latest,
        "expected_start": effective_start,
        "expected_end": effective_end,
        "search_start": normalized(content.get("searchEarliestTime")),
        "search_end": normalized(content.get("searchLatestTime")),
        "native_binding_verified": True,
        "result_truncated_present": "resultIsTruncated" in content,
        "native_job": retained_job,
    }


def scoped_filter(old):
    require(
        isinstance(old, str)
        and len(old) <= 2048
        and "\n" not in old
        and "\r" not in old,
        "unsupported original filter",
    )
    term = 'NOT source="' + SOURCE + '"'
    return "(" + old + ") AND " + term if old.strip() else term


def verify_context(ops, principal, role):
    context = ops.user_context()
    require(
        context.get("username") == principal and context.get("roles") == [role],
        "caller identity or roles differ",
    )
    require(
        set(context.get("capabilities", [])) == {"search", "adm_investigate"},
        "caller is not restricted investigator",
    )
    role_content = ops.role(role)
    require(role_content.get("imported_roles") in ("", []), "role imports other roles")
    require(
        set(role_content.get("srchIndexesAllowed", []))
        == {"atlas_identity", "otel_traces"}
        and role_content.get("srchIndexesDefault") in ("", []),
        "role index grants differ",
    )
    require(
        role_content.get("srchFilter") in (BASE_FILTER, scoped_filter(BASE_FILTER)),
        "role source/time filter differs",
    )
    require(
        set(role_content.get("capabilities", [])) == {"search", "adm_investigate"},
        "role capabilities unsafe",
    )
    members = ops.members(role)
    require(members == {principal}, "role is not exclusive to investigator")
    require(ops.profile_sha256() == PROFILE_HASH, "source profile differs")
    return context, role_content


def verify_original(ops, principal, case_id, original):
    events = ops.original_events()
    matches = [
        event
        for event in events
        if event.get("state") == "dispatching" and event.get("operation") == original
    ]
    require(len(matches) == 1, "original capture intent missing")
    intent = matches[0]
    require(
        intent.get("action") == "capture"
        and intent.get("caller") == principal
        and intent.get("method") == "POST"
        and intent.get("path") == "/cases/" + case_id + "/captures"
        and isinstance(intent.get("key"), str)
        and intent["key"]
        and isinstance(intent.get("body"), str),
        "original identity mismatch",
    )
    responses = [
        event
        for event in events
        if event.get("state") == "response" and event.get("operation") == original
    ]
    require(
        len(responses) == 1 and responses[0].get("status") == 200,
        "original outcome unresolved",
    )
    return intent


def same_user_context(before, after):
    """Ignore only the observed login timestamp while preserving its schema."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    for context in (before, after):
        timestamp = context.get("last_successful_login")
        if type(timestamp) is not int or timestamp < 0:
            return False
    left, right = dict(before), dict(after)
    left.pop("last_successful_login")
    right.pop("last_successful_login")
    return left == right


def record_context_comparison(stage, label, before, after):
    equal = same_user_context(before, after)
    journal_append(
        stage,
        {
            "state": "context_comparison",
            "label": label,
            "before": before,
            "after": after,
            "equal": equal,
            "excluded_field": "last_successful_login",
            "reason": "login updates this nonnegative integer timestamp",
        },
    )
    return equal


def observe(
    ops,
    principal,
    role,
    case_id,
    capture_id,
    original,
    visible,
    expected_entries=None,
    *,
    stage,
):
    context, _ = verify_context(ops, principal, role)
    results = {}
    for action in ("read", "export", "retry"):
        response = ops.case_action(action, case_id, capture_id, original)
        require(response["status"] == 200, "case request failed or uncertain")
        result = response["result"]
        captures = result.get("captures")
        require(
            isinstance(captures, list) and bool(result.get("entries")),
            "case notes unavailable",
        )
        entries_digest = hashlib.sha256(
            json.dumps(
                result["entries"], sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        if expected_entries is None:
            expected_entries = entries_digest
        require(entries_digest == expected_entries, "notes changed")
        if visible:
            require(
                len(captures) == 1 and captures[0].get("id") == capture_id,
                "capture not visible",
            )
            data = captures[0]["data"]
            require(
                data.get("scope") == SCOPE
                and [
                    {k: w[k] for k in ("start", "end")} for w in data.get("windows", [])
                ]
                == WINDOWS
                and data.get("evidence_digest") == EVIDENCE_HASH
                and data.get("configuration_fingerprint") == FINGERPRINT
                and data.get("source_contract") == "admqualified-comparison-v1",
                "real source evidence mismatch",
            )
        else:
            require(
                not captures and result.get("redactions", {}).get("captures", 0) >= 1,
                "capture was not redacted",
            )
        results[action] = {
            "status": response["status"],
            "operation": response["operation"],
            "entries_sha256": entries_digest,
            "response_sha256": hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
    after_context = ops.user_context()
    require(
        record_context_comparison(stage, "observation", context, after_context),
        "caller context changed",
    )
    return results


def run_exercise(ops, stage, principal, role, case_id, capture_id, original):
    """Execute one reversible role change; preserve failures and restoration evidence."""
    stage = Path(stage)
    m = stage.lstat()
    require(
        stat.S_ISDIR(m.st_mode)
        and m.st_uid == os.getuid()
        and stat.S_IMODE(m.st_mode) == 0o700,
        "unsafe private stage",
    )
    require(
        not os.path.lexists(stage / "operations.jsonl"), "revocation stage already used"
    )
    require(
        all(
            isinstance(v, str) and v
            for v in (principal, role, case_id, capture_id, original)
        ),
        "missing identity",
    )
    require(principal != ops.admin_principal(), "administrator is not eligible")
    original_context, before = verify_context(ops, principal, role)
    intent = verify_original(ops, principal, case_id, original)
    require("srchFilter" in before, "original filter missing")
    old_filter = before["srchFilter"]
    narrowed = scoped_filter(old_filter)
    require(narrowed != old_filter, "filter unchanged")
    # This record includes original role values, but never credentials.
    journal_append(
        stage,
        {
            "state": "prepared",
            "principal": principal,
            "role": role,
            "context": original_context,
            "role_before": before,
            "original_operation": original,
            "original_body_sha256": hashlib.sha256(intent["body"].encode()).hexdigest(),
            "original_key": intent["key"],
            "original_path": intent["path"],
            "profile_sha256": PROFILE_HASH,
        },
    )
    result = {
        "status": "failed_or_uncertain",
        "scope": "existing exclusive-role non-admin real-source revocation",
        "phase": {},
    }
    mutate_attempted = False
    try:
        result["phase"]["allowed"] = observe(
            ops, principal, role, case_id, capture_id, original, True, stage=stage
        )
        context, current = verify_context(ops, principal, role)
        require(
            record_context_comparison(stage, "before_narrow", original_context, context)
            and current == before,
            "role changed before narrowing",
        )
        journal_append(
            stage,
            {
                "state": "narrow_intent",
                "role": role,
                "from_filter": old_filter,
                "to_filter": narrowed,
            },
        )
        mutate_attempted = True
        ops.set_filter(role, narrowed)
        actual = ops.role(role)
        expected = dict(before, srchFilter=narrowed)
        require(actual == expected, "narrowed role differs")
        result["phase"]["revoked"] = observe(
            ops,
            principal,
            role,
            case_id,
            capture_id,
            original,
            False,
            result["phase"]["allowed"]["read"]["entries_sha256"],
            stage=stage,
        )
    except BaseException as exc:
        result["primary_error"] = type(exc).__name__
    finally:
        restore = {"attempted": False, "verified": False, "journal_ok": True}
        if mutate_attempted:
            try:
                context, current = verify_context(ops, principal, role)
                context_matches = same_user_context(original_context, context)
                try:
                    record_context_comparison(
                        stage, "before_restore", original_context, context
                    )
                except BaseException:
                    restore["journal_ok"] = False
                require(context_matches, "caller context changed during restoration")
                require(
                    current in (before, dict(before, srchFilter=narrowed)),
                    "unrelated role change",
                )
                if current != before:
                    restore["attempted"] = True
                    try:
                        journal_append(
                            stage,
                            {
                                "state": "restore_intent",
                                "role": role,
                                "filter": old_filter,
                            },
                        )
                    except BaseException:
                        restore["journal_ok"] = False
                    ops.set_filter(role, old_filter)
                context, after = verify_context(ops, principal, role)
                context_matches = same_user_context(original_context, context)
                try:
                    record_context_comparison(
                        stage, "after_restore", original_context, context
                    )
                except BaseException:
                    restore["journal_ok"] = False
                require(
                    context_matches and after == before, "original role not restored"
                )
                restore["verified"] = True
            except BaseException as exc:
                restore["error"] = type(exc).__name__
        else:
            try:
                context, after = verify_context(ops, principal, role)
                restore["verified"] = (
                    record_context_comparison(
                        stage, "after_restore", original_context, context
                    )
                    and after == before
                )
            except BaseException as exc:
                restore["error"] = type(exc).__name__
        result["restoration"] = restore
    if restore["verified"] and restore["journal_ok"] and "primary_error" not in result:
        try:
            result["phase"]["restored"] = observe(
                ops,
                principal,
                role,
                case_id,
                capture_id,
                original,
                True,
                result["phase"]["allowed"]["read"]["entries_sha256"],
                stage=stage,
            )
            result["status"] = "passed_fixture_checks"
        except BaseException as exc:
            result["restored_error"] = type(exc).__name__
    try:
        journal_append(stage, {"state": "finished", "result": result})
    except BaseException as exc:
        result["status"] = "failed_or_uncertain"
        result["result_journal_error"] = type(exc).__name__
    return result


class FixedAdminTransport:
    """Bounded loopback role/user API for this one reviewed role only."""

    def __init__(self, transport, token, role):
        require(
            isinstance(token, str)
            and token
            and len(token) <= 16384
            and all(33 <= ord(c) <= 126 for c in token),
            "invalid token",
        )
        require(
            isinstance(role, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", role) is not None,
            "invalid role",
        )
        self.transport, self.token, self.role = transport, token, role

    def __call__(self, method, path, data, timeout):
        if (
            method == "GET"
            and path
            in ("/services/authentication/current-context", "/services/server/info")
            and data is None
        ):
            return self.transport(method, path, None, timeout)
        role_path = "/services/authorization/roles/" + quote(self.role, safe="")
        is_role = path == role_path and (
            (method == "GET" and data is None)
            or (
                method == "POST"
                and isinstance(data, dict)
                and set(data) == {"srchFilter"}
                and isinstance(data["srchFilter"], str)
            )
        )
        is_users = (
            method == "GET"
            and path == "/services/authentication/users?count=1001&offset=0"
            and data is None
        )
        require((is_role or is_users) and 0 < timeout <= 3, "unapproved admin request")
        return self._exchange(method, path, data, timeout)

    def _exchange(self, method, path, data, timeout):
        from adm_cases_lib.transport import _read_ca

        require(
            _read_ca("/opt/splunk/etc/auth/cacert.pem") == self.transport.ca_bytes,
            "CA changed",
        )
        ca = (
            self.transport.ca_bytes.decode("ascii")
            if b"-----BEGIN" in self.transport.ca_bytes
            else self.transport.ca_bytes
        )
        context = ssl.create_default_context(cadata=ca)
        deadline = time.monotonic() + timeout
        raw = socket.create_connection(("127.0.0.1", 8089), timeout=timeout)
        active = [raw]

        def expire():
            try:
                active[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        remaining = deadline - time.monotonic()
        require(remaining > 0, "admin request timed out")
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        connection = None
        try:
            connection = context.wrap_socket(
                raw, server_hostname="127.0.0.1", do_handshake_on_connect=False
            )
            active[0] = connection
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.do_handshake()
            body = urlencode(data).encode() if data is not None else b""
            target = path + ("&" if "?" in path else "?") + "output_mode=json"
            auth = (
                "Bearer "
                if self.token.startswith("eyJ") and self.token.count(".") == 2
                else "Splunk "
            ) + self.token
            headers = (
                method
                + " "
                + target
                + " HTTP/1.1\r\nHost: 127.0.0.1:8089\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nAuthorization: "
                + auth
                + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "
                + str(len(body))
                + "\r\n\r\n"
            ).encode("ascii")
            connection.sendall(headers + body)
            response = http.client.HTTPResponse(connection)
            response.begin()
            require(response.status in (200, 201), "admin response unavailable")
            content = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "admin request timed out")
                connection.settimeout(remaining)
                chunk = response.read1(min(65536, 1024 * 1024 + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                require(len(content) <= 1024 * 1024, "admin response too large")
            require(time.monotonic() < deadline, "admin request timed out")
            value = json.loads(bytes(content)) if content else {}
            require(isinstance(value, dict), "invalid admin response")
            return value
        finally:
            timer.cancel()
            timer.join()
            if connection is not None:
                connection.close()
            else:
                raw.close()


class NativeOps:
    def __init__(self, stage, config, user_transport, admin_transport):
        self.stage, self.config = stage, config
        self.user, self.admin = (
            user_transport,
            FixedAdminTransport(admin_transport, config["admin_token"], config["role"]),
        )
        self.expected_admin = None

    def admin_principal(self):
        content = self.admin(
            "GET", "/services/authentication/current-context", None, 3
        )["entry"][0]["content"]
        require(
            {"admin_all_objects", "search"}.issubset(content.get("capabilities", [])),
            "admin context unavailable",
        )
        if self.expected_admin is None:
            self.expected_admin = content["username"]
        require(content["username"] == self.expected_admin, "admin identity changed")
        return content["username"]

    def user_context(self):
        return self.user("GET", "/services/authentication/current-context", None, 3)[
            "entry"
        ][0]["content"]

    def role(self, role):
        response = self.admin(
            "GET", "/services/authorization/roles/" + quote(role, safe=""), None, 3
        )
        entries = response.get("entry")
        require(
            isinstance(entries, list)
            and len(entries) == 1
            and entries[0].get("name") == role
            and isinstance(entries[0].get("content"), dict),
            "role response mismatch",
        )
        return entries[0]["content"]

    def members(self, role):
        result = self.admin(
            "GET", "/services/authentication/users?count=1001&offset=0", None, 3
        )
        rows, paging = result.get("entry"), result.get("paging")
        require(
            isinstance(rows, list)
            and isinstance(paging, dict)
            and isinstance(paging.get("total"), int)
            and paging["total"] == len(rows)
            and len(rows) <= 1000,
            "user inventory incomplete",
        )
        names = set()
        members = set()
        for row in rows:
            require(
                isinstance(row, dict)
                and isinstance(row.get("name"), str)
                and row["name"] not in names
                and isinstance(row.get("content"), dict)
                and isinstance(row["content"].get("roles"), list)
                and all(isinstance(value, str) for value in row["content"]["roles"]),
                "invalid user inventory",
            )
            names.add(row["name"])
            if role in row["content"]["roles"]:
                members.add(row["name"])
        return members

    def profile_sha256(self):
        fd = os.open(PROFILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_uid in (0, os.getuid())
                and stat.S_IMODE(before.st_mode) & 0o022 == 0
                and before.st_size <= 128 * 1024,
                "profile unsafe",
            )
            chunks = []
            remaining = before.st_size
            while remaining:
                part = os.read(fd, min(remaining, 65536))
                require(bool(part), "profile changed")
                chunks.append(part)
                remaining -= len(part)
            after = os.fstat(fd)
            entry = PROFILE.lstat()
            require(
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_mode,
                    before.st_uid,
                    before.st_gid,
                    before.st_nlink,
                )
                == (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                    after.st_mode,
                    after.st_uid,
                    after.st_gid,
                    after.st_nlink,
                )
                and (entry.st_dev, entry.st_ino) == (before.st_dev, before.st_ino),
                "profile changed",
            )
            return hashlib.sha256(b"".join(chunks)).hexdigest()
        finally:
            os.close(fd)

    def set_filter(self, role, value):
        self.admin_principal()
        self.admin(
            "POST",
            "/services/authorization/roles/" + quote(role, safe=""),
            {"srchFilter": value},
            3,
        )

    def original_events(self):
        directory = self.stage / "requests"
        info = directory.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe request journal directory",
        )
        return journal_events(directory)

    def case_action(self, action, case_id, capture_id, original):
        command = {
            "username": self.config["principal"],
            "password": self.config["password"],
            "action": action,
        }
        if action == "retry":
            command["original_operation"] = original
        else:
            command.update(case_id=case_id, capture_id=capture_id)
        response = installed_request(command, self.stage / "requests")
        require(response.get("state") == "response", "case outcome uncertain")
        events = [
            event
            for event in self.original_events()
            if event.get("state") == "response"
            and event.get("operation") == response["operation"]
        ]
        require(len(events) == 1, "case response missing")
        return {**response, "result": events[0]["result"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed", action="store_true", required=True)
    parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        require(len(raw) <= MAX_INPUT, "input too large")
        config = json.loads(raw)
        require(
            set(config)
            == {
                "principal",
                "password",
                "user_token",
                "admin_token",
                "role",
                "case_id",
                "capture_id",
                "original_operation",
            },
            "invalid input",
        )
        require(
            all(isinstance(value, str) and value for value in config.values()),
            "missing credential or identity",
        )
        import pwd

        require(
            os.uname().machine == "x86_64"
            and os.getuid() == pwd.getpwnam("splunk").pw_uid,
            "unsupported runtime",
        )
        sys.path.insert(0, "/opt/splunk/etc/apps/splunk_adm/bin")
        from adm_cases_lib.transport import SupervisedTransport

        ca = "/opt/splunk/etc/auth/cacert.pem"
        user = SupervisedTransport(config["user_token"], "https://127.0.0.1:8089", ca)
        admin = SupervisedTransport(config["admin_token"], "https://127.0.0.1:8089", ca)
        require(user.preflight() and admin.preflight(), "transport unavailable")
        expected_guid = (
            "8c003a4afae8d1197dd165a6ed76e66090d73f1ea9ddcd1723991a5143de6ca3"
        )
        for transport in (user, admin):
            info = transport("GET", "/services/server/info", None, 3)["entry"][0][
                "content"
            ]
            require(
                hashlib.sha256(info["guid"].encode()).hexdigest() == expected_guid
                and info.get("version") == "10.6.0.5"
                and info.get("activeLicenseGroup") == "Enterprise",
                "unexpected host",
            )
        ops = NativeOps(STAGE, config, user, admin)
        result = run_exercise(
            ops,
            STAGE,
            config["principal"],
            config["role"],
            config["case_id"],
            config["capture_id"],
            config["original_operation"],
        )
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "passed_fixture_checks" else 1
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed_or_uncertain", "error_type": type(exc).__name__}
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
