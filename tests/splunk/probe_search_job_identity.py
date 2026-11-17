"""Task-owned local experiment for client-selected Splunk search job IDs.

Exploratory probe: client-selected IDs proved nonexclusive on Splunk 10.6.0.5.
This is intentionally outside normal test discovery and requires explicit opt-in.
Only `makeresults` searches are dispatched. Diagnostics emit status and JSON
field names, never job IDs, credentials, search results, or source records.
A pending or unprovable job is not treated as absent and is never deleted.
"""

import base64
import datetime as dt
from decimal import Decimal, InvalidOperation
import re
import http.client
import json
import os
import secrets
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402

APP = "splunk_adm"
CREATE_PATH = "/servicesNS/nobody/splunk_adm/search/jobs"
JOB_PATH = "/services/search/jobs/"
SEARCH = "| makeresults"


def _metadata(label, status, payload):
    """Log field names and status only, never user data or source values."""
    summary = {"phase": label, "status": status}
    if isinstance(payload, dict):
        summary["response_fields"] = sorted(str(k) for k in payload)
        entries = payload.get("entry")
        if (
            isinstance(entries, list)
            and len(entries) == 1
            and isinstance(entries[0], dict)
        ):
            entry = entries[0]
            summary["entry_fields"] = sorted(str(k) for k in entry)
            for field in ("acl", "eai:acl", "content"):
                if isinstance(entry.get(field), dict):
                    summary[field + "_fields"] = sorted(str(k) for k in entry[field])
            content = entry.get("content")
            if isinstance(content, dict) and isinstance(content.get("request"), dict):
                summary["request_fields"] = sorted(str(k) for k in content["request"])
    print(json.dumps(summary, sort_keys=True), flush=True)


def _instant(value):
    try:
        if type(value) in (int, float) or (
            isinstance(value, str)
            and len(value) <= 64
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value)
        ):
            number = Decimal(str(value))
            return number if number.is_finite() and 0 <= number <= 2**53 else None
        if isinstance(value, str):
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                return parsed.timestamp()
    except (ValueError, OverflowError, InvalidOperation):
        pass
    return None


def _proof(payload, sid, owner, earliest, latest, search=SEARCH):
    """Require exact caller, app, ID, query, and time bounds before deletion."""
    if not isinstance(payload, dict):
        return False
    entries = payload.get("entry")
    if (
        not isinstance(entries, list)
        or len(entries) != 1
        or not isinstance(entries[0], dict)
    ):
        return False
    entry = entries[0]
    acl = entry.get("acl", entry.get("eai:acl"))
    content = entry.get("content")
    if not isinstance(acl, dict) or not isinstance(content, dict):
        return False
    if content.get("sid") != sid or acl.get("owner") != owner or acl.get("app") != APP:
        return False
    request = content.get("request")
    if not isinstance(request, dict):
        request = {}
    starts = [request.get("earliest_time")]
    ends = [request.get("latest_time")]
    return (
        request.get("id") == sid
        and request.get("search") == search
        and content.get("search") == search
        and content.get("dispatchState") == "DONE"
        and content.get("isDone") in (True, 1, "1")
        and any(_instant(value) == earliest for value in starts)
        and any(_instant(value) == latest for value in ends)
    )


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1" and os.environ.get("ADM_SID_EXPERIMENT") == "1",
    "requires an explicitly opted-in task-owned experiment",
)
class ClientSelectedSearchJobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if lab.task_identity() is None:
            raise RuntimeError("This experiment requires a task-owned lab")
        lab.verify_target()
        cls.users = []
        cls.candidates = {}
        cls.last_dispatch = None
        suffix = secrets.token_hex(6)
        roles = ["atlas_sid_" + suffix + tail for tail in ("a", "b")]
        for role, source_filter in zip(
            roles, ("source=*", 'NOT source="synthetic-never-indexed"')
        ):
            lab._json(
                "POST",
                "/services/authorization/roles",
                {
                    "name": role,
                    "capabilities": "search",
                    "srchFilter": source_filter,
                    "srchIndexesAllowed": ["main"],
                    "srchIndexesDefault": ["main"],
                },
            )
            cls.addClassCleanup(
                cls._cleanup_resource, "/services/authorization/roles/" + role
            )
            lab._json(
                "POST",
                "/services/authorization/roles/" + role,
                {
                    "capabilities": "search",
                    "srchFilter": source_filter,
                    "srchIndexesAllowed": ["main"],
                    "srchIndexesDefault": ["main"],
                },
            )
            content = lab._json("GET", "/services/authorization/roles/" + role)[
                "entry"
            ][0]["content"]
            if (
                set(content.get("srchIndexesAllowed", [])) != {"main"}
                or content.get("srchFilter") != source_filter
            ):
                raise AssertionError("Task role search restrictions did not apply")
        for role, tail in zip(roles, ("a", "b")):
            user = "atlas_sid_" + suffix + tail
            password = secrets.token_urlsafe(24)
            lab._json(
                "POST",
                "/services/authentication/users",
                {"name": user, "password": password, "roles": role},
            )
            cls.addClassCleanup(
                cls._cleanup_resource, "/services/authentication/users/" + user
            )
            cls.users.append((user, password))
        # Register after users so jobs are handled before users and roles.
        cls.addClassCleanup(cls._cleanup_jobs)

    @staticmethod
    def _cleanup_resource(path):
        try:
            lab._json("DELETE", path)
        except (lab.LabError, OSError):
            print(
                json.dumps({"phase": "resource_cleanup", "status": "failed"}),
                flush=True,
            )

    @classmethod
    def _request(cls, user, method, path, data=None):
        name, password = cls.users[user]
        auth = base64.b64encode((name + ":" + password).encode()).decode()
        headers = {"Authorization": "Basic " + auth}
        body = None if data is None else urllib.parse.urlencode(data).encode()
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(
            lab.MGMT + path + ("&" if "?" in path else "?") + "output_mode=json",
            method=method,
            data=body,
            headers=headers,
        )
        try:
            response = lab.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, None
        with response:
            payload = response.read(2_000_001)
            if len(payload) > 2_000_000:
                raise AssertionError("Job response exceeded the bounded limit")
            return response.status, json.loads(payload) if payload else {}

    @classmethod
    def _status(cls, user, sid):
        return cls._request(user, "GET", JOB_PATH + urllib.parse.quote(sid, safe=""))

    @classmethod
    def _observe(cls, user, sid, earliest, latest, label, timeout=8, search=SEARCH):
        deadline = time.monotonic() + timeout
        last_status = None
        reported = False
        while time.monotonic() < deadline:
            status, payload = cls._status(user, sid)
            last_status = status
            if status == 200:
                if not reported:
                    _metadata(label, status, payload)
                    entry = payload.get("entry", [{}])[0]
                    acl = entry.get("acl", entry.get("eai:acl", {}))
                    content = entry.get("content", {})
                    request = content.get("request", {})
                    print(
                        json.dumps(
                            {
                                "phase": label + "_proof_checks",
                                "name_matches": entry.get("name") == sid,
                                "content_sid_matches": content.get("sid") == sid,
                                "request_id_matches": request.get("id") == sid,
                                "owner_matches": acl.get("owner") == cls.users[user][0],
                                "app_matches": acl.get("app") == APP,
                                "app_basis": acl.get("app")
                                if acl.get("app") in ("search", APP)
                                else "other",
                                "content_search_matches": content.get("search")
                                == SEARCH,
                                "request_search_matches": request.get("search")
                                == SEARCH,
                                "request_earliest_matches": _instant(
                                    request.get("earliest_time")
                                )
                                == earliest,
                                "request_latest_matches": _instant(
                                    request.get("latest_time")
                                )
                                == latest,
                                "content_earliest_matches": _instant(
                                    content.get("earliestTime")
                                )
                                == earliest,
                                "content_latest_matches": _instant(
                                    content.get("latestTime")
                                )
                                == latest,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    reported = True
                if _proof(payload, sid, cls.users[user][0], earliest, latest, search):
                    return payload
                # Completion metadata may lag creation; never delete an unproven job.
                time.sleep(0.25)
                continue
            if status != 404:
                break
            time.sleep(0.25)
        print(
            json.dumps(
                {"phase": label, "status": last_status, "outcome": "pending_unknown"}
            ),
            flush=True,
        )
        return None

    @classmethod
    def _cleanup_jobs(cls):
        # Recheck every candidate as the original caller; do not rely on a stale proof.
        for sid, (user, earliest, latest, search) in list(cls.candidates.items()):
            try:
                status, payload = cls._status(user, sid)
                if status == 200 and _proof(
                    payload, sid, cls.users[user][0], earliest, latest, search
                ):
                    result, _ = cls._request(
                        user, "DELETE", JOB_PATH + urllib.parse.quote(sid, safe="")
                    )
                    print(
                        json.dumps({"phase": "verified_cleanup", "status": result}),
                        flush=True,
                    )
                else:
                    print(
                        json.dumps(
                            {
                                "phase": "verified_cleanup",
                                "status": status,
                                "outcome": "not_deleted_without_proof",
                            }
                        ),
                        flush=True,
                    )
            except Exception:
                print(
                    json.dumps(
                        {
                            "phase": "verified_cleanup",
                            "outcome": "not_deleted_without_proof",
                        }
                    ),
                    flush=True,
                )
        # Do not treat a first 404 as final absence; short-lived unproven dispatches
        # remain unknown until their bounded TTL has elapsed.
        if cls.last_dispatch is not None:
            remaining = cls.last_dispatch + 35 - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

    def _payload(self, sid, earliest, latest, search=SEARCH):
        return {
            "id": sid,
            "search": search,
            "earliest_time": str(earliest),
            "latest_time": str(latest),
            "exec_mode": "normal",
            "ttl": "30",
            "max_time": "5",
            "auto_cancel": "10",
        }

    def _lost_response(self, sid, earliest, latest, search=SEARCH):
        # Direct HTTPSConnection has no proxy or redirect handling; its trusted
        # context performs certificate and hostname verification before send.
        lab.verify_target()
        port = urllib.parse.urlsplit(lab.MGMT).port
        name, password = self.users[0]
        auth = base64.b64encode((name + ":" + password).encode()).decode()
        body = urllib.parse.urlencode(
            self._payload(sid, earliest, latest, search)
        ).encode()
        connection = http.client.HTTPSConnection(
            "127.0.0.1", port, timeout=15, context=lab._CTX
        )
        try:
            connection.request(
                "POST",
                CREATE_PATH + "?output_mode=json",
                body=body,
                headers={
                    "Authorization": "Basic " + auth,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        finally:
            connection.close()  # Discard the response without reading it.

    def test_selected_sid_collision_isolation_and_lost_response(self):
        earliest = int(time.time()) - 120
        latest = earliest + 60
        sid = "adm-sid-" + secrets.token_hex(16)
        self.__class__.last_dispatch = time.monotonic()
        status, created = self._request(
            0, "POST", CREATE_PATH, self._payload(sid, earliest, latest)
        )
        _metadata("create", status, created)
        self.assertIn(status, (200, 201))
        self.assertEqual(created.get("sid"), sid)
        original = self._observe(0, sid, earliest, latest, "original")
        self.assertIsNotNone(original)
        # Native aliases are deliberately tested for mutability, not assumed unique.
        replacement = SEARCH + " | eval collision_probe=1"
        self.__class__.last_dispatch = time.monotonic()
        status, body = self._request(
            0, "POST", CREATE_PATH, self._payload(sid, earliest, latest, replacement)
        )
        _metadata("same_caller_duplicate", status, body)
        after = self._observe(
            0,
            sid,
            earliest,
            latest,
            "same_caller_replacement",
            search=replacement if 200 <= status < 300 else SEARCH,
        )
        self.assertIsNotNone(after)
        active = replacement if 200 <= status < 300 else SEARCH
        print(
            json.dumps(
                {
                    "phase": "same_caller_alias_contract",
                    "duplicate_accepted": 200 <= status < 300,
                    "original_proof_remains_valid": _proof(
                        after, sid, self.users[0][0], earliest, latest
                    ),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        # The other principal has not created this alias: it must not expose/cancel A.
        for method in ("GET", "DELETE"):
            status, _ = self._request(
                1, method, JOB_PATH + urllib.parse.quote(sid, safe="")
            )
            _metadata("other_caller_before_creation_" + method.lower(), status, None)
            self.assertFalse(
                200 <= status < 300, "Other caller accessed the original dispatch"
            )
            self.assertIsNotNone(
                self._observe(
                    0,
                    sid,
                    earliest,
                    latest,
                    "original_after_denied_other_caller",
                    search=active,
                )
            )
        other = SEARCH + " | eval collision_probe=2"
        self.__class__.last_dispatch = time.monotonic()
        status, body = self._request(
            1, "POST", CREATE_PATH, self._payload(sid, earliest, latest, other)
        )
        _metadata("other_caller_duplicate", status, body)
        # A per-caller alias may coexist; it must never clobber the first caller.
        self.assertIsNotNone(
            self._observe(
                0,
                sid,
                earliest,
                latest,
                "first_caller_after_other_creation",
                search=active,
            ),
            "Cross-caller overwrite changed original dispatch",
        )
        if 200 <= status < 300:
            self.assertIsNotNone(
                self._observe(
                    1, sid, earliest, latest, "second_caller_own_alias", search=other
                )
            )
            deleted, _ = self._request(
                1, "DELETE", JOB_PATH + urllib.parse.quote(sid, safe="")
            )
            _metadata("second_caller_own_alias_delete", deleted, None)
            self.assertTrue(200 <= deleted < 300)
            self.assertIsNotNone(
                self._observe(
                    0,
                    sid,
                    earliest,
                    latest,
                    "first_caller_after_second_delete",
                    search=active,
                )
            )
        # This is an intentional race on disposable fixture jobs, not the production cleanup algorithm.
        proven = self._observe(
            0, sid, earliest, latest, "before_delete_race", search=active
        )
        self.assertIsNotNone(proven)
        newer = SEARCH + " | eval collision_probe=3"
        self.__class__.last_dispatch = time.monotonic()
        replaced, _ = self._request(
            0, "POST", CREATE_PATH, self._payload(sid, earliest, latest, newer)
        )
        if 200 <= replaced < 300:
            self.assertIsNotNone(
                self._observe(
                    0, sid, earliest, latest, "newer_before_old_delete", search=newer
                )
            )
            deleted, _ = self._request(
                0, "DELETE", JOB_PATH + urllib.parse.quote(sid, safe="")
            )
            now, _ = self._status(0, sid)
            print(
                json.dumps(
                    {
                        "phase": "proof_delete_race",
                        "delete_status": deleted,
                        "after_status": now,
                        "delete_is_generation_conditional": not (
                            200 <= deleted < 300 and now == 404
                        ),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        lost_sid = "adm-sid-" + secrets.token_hex(16)
        self.candidates[lost_sid] = (0, earliest, latest, SEARCH)
        self.__class__.last_dispatch = time.monotonic()
        self._lost_response(lost_sid, earliest, latest)
        self.assertIsNotNone(
            self._observe(0, lost_sid, earliest, latest, "lost_response")
        )
