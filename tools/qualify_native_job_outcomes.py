#!/usr/bin/env python3
"""Bounded installed-library rehearsal for lost native job acknowledgements.

No runtime, role, index, or global-ledger mutations; caller owns outer lifecycle.
"""

import argparse
import copy
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from contextlib import closing
from urllib.parse import quote, unquote

ROOT = Path("/opt/splunk/var/atlas-job-outcomes-20261118")
BIN = Path("/opt/splunk/etc/apps/splunk_adm/bin")
GUID_HASH = "8c003a4afae8d1197dd165a6ed76e66090d73f1ea9ddcd1723991a5143de6ca3"
CA = "/opt/splunk/etc/auth/cacert.pem"
MAX_INPUT = 65536


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def journal(stage, event):
    fd = os.open(
        stage / "events.jsonl",
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
        0o600,
    )
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600,
            "unsafe journal",
        )
        with os.fdopen(fd, "ab", closefd=False) as stream:
            stream.write(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    syncdir(stage)


def verify_retained_metadata(proofs, principal, record):
    """Validate retained observations without weakening the native verifier.

    The first observation may be a PARSING response whose top-level search is
    not yet populated. Every other identity field must satisfy the installed
    native verifier, and a later, complete unmodified proof is mandatory.
    Original observations are never changed or discarded.
    """
    from adm_cases_lib.native import NativeComparisonSearch

    require(isinstance(proofs, list) and bool(proofs), "metadata missing")
    partial = []
    complete = []
    for index, event in enumerate(proofs):
        require(
            isinstance(event, dict)
            and event.get("observer") in {"caller", "admin"}
            and isinstance(event.get("response_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", event["response_sha256"]),
            "invalid observation provenance",
        )
        proof = event.get("proof")
        try:
            entries = proof["entry"]
            require(isinstance(entries, list) and len(entries) == 1, "ambiguous entry")
            content = entries[0]["content"]
            state, done = content.get("dispatchState"), content.get("isDone")
            require(
                (state in {"PARSING", "RUNNING"} and done is False)
                or (state == "DONE" and done is True),
                "inconsistent job state",
            )
        except Exception:
            raise RuntimeError("invalid job state") from None
        try:
            NativeComparisonSearch._verify_metadata(
                principal, record, proof, require_complete=False
            )
            complete.append(index)
            continue
        except Exception:
            pass
        try:
            entries = proof["entry"]
            require(isinstance(entries, list) and len(entries) == 1, "ambiguous entry")
            content = entries[0]["content"]
            request = content["request"]
            require(
                index == 0
                and content.get("dispatchState") == "PARSING"
                and content.get("isDone") is False
                and content.get("search") is None
                and isinstance(request.get("search"), str)
                and bool(request["search"]),
                "unsupported incomplete observation",
            )
            candidate = copy.deepcopy(proof)
            candidate["entry"][0]["content"]["search"] = request["search"]
            NativeComparisonSearch._verify_metadata(
                principal, record, candidate, require_complete=False
            )
        except Exception:
            raise RuntimeError(
                "metadata contradiction or unsupported partial"
            ) from None
        partial.append(index)
    require(
        bool(complete) and (not partial or max(complete) > max(partial)),
        "later full metadata proof missing",
    )
    return {"partial": len(partial), "full": len(complete)}


class AdminObserver:
    """Fixed read-only role metadata adapter; all other calls use the transport."""

    def __init__(self, transport, token):
        require(
            isinstance(token, str)
            and token
            and len(token) <= 16384
            and all(33 <= ord(c) <= 126 for c in token),
            "invalid observer token",
        )
        self.transport = transport
        self._token = token
        self.ca_bytes = transport.ca_bytes
        self.trust_digest = transport.trust_digest
        self._roles = set()

    def __call__(self, method, path, data, timeout):
        prefix = "/services/authorization/roles/"
        if path.startswith(prefix):
            require(
                method == "GET"
                and data is None
                and type(timeout) in (int, float)
                and 0 < timeout <= 3,
                "invalid role request",
            )
            encoded = path[len(prefix) :]
            role = unquote(encoded)
            require(
                role in self._roles
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", role) is not None
                and quote(role, safe="") == encoded,
                "unexpected role",
            )
            return self._read_role(encoded, float(timeout))
        fixed = path in (
            "/services/authentication/current-context",
            "/services/server/info",
        )
        job = re.fullmatch(r"/services/search/jobs/([A-Za-z0-9_.%:-]{1,765})", path)
        if job:
            sid = unquote(job.group(1))
            require(
                re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid) is not None
                and quote(sid, safe="") == job.group(1),
                "invalid job path",
            )
        require(
            method == "GET" and data is None and (fixed or job is not None),
            "invalid observer request",
        )
        result = self.transport(method, path, data, timeout)
        if path == "/services/authentication/current-context":
            entries = result.get("entry")
            require(
                isinstance(entries, list)
                and len(entries) == 1
                and isinstance(entries[0].get("content"), dict),
                "invalid context",
            )
            roles = entries[0]["content"].get("roles")
            require(
                isinstance(roles, list)
                and all(
                    isinstance(role, str)
                    and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", role)
                    for role in roles
                ),
                "invalid roles",
            )
            self._roles = set(roles)
        return result

    def _read_role(self, encoded, timeout):
        from adm_cases_lib.transport import _read_ca

        require(_read_ca(CA) == self.ca_bytes, "observer CA changed")
        ca = (
            self.ca_bytes.decode("ascii")
            if b"-----BEGIN" in self.ca_bytes
            else self.ca_bytes
        )
        context = ssl.create_default_context(cadata=ca)
        deadline = time.monotonic() + timeout
        raw = socket.create_connection(("127.0.0.1", 8089), timeout=timeout)
        connection = None
        active = [raw]

        def expire():
            try:
                active[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        remaining = deadline - time.monotonic()
        require(remaining > 0, "role request timed out")
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        try:
            connection = context.wrap_socket(
                raw, server_hostname="127.0.0.1", do_handshake_on_connect=False
            )
            active[0] = connection
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.do_handshake()
            authorization = (
                "Bearer "
                if self._token.startswith("eyJ") and self._token.count(".") == 2
                else "Splunk "
            ) + self._token
            request = (
                "GET /services/authorization/roles/"
                + encoded
                + "?output_mode=json HTTP/1.1\r\nHost: 127.0.0.1:8089\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nAuthorization: "
                + authorization
                + "\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            require(response.status == 200, "role metadata unavailable")
            content = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "role request timed out")
                connection.settimeout(remaining)
                chunk = response.read1(min(65536, 1024 * 1024 + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                require(len(content) <= 1024 * 1024, "role response too large")
            require(time.monotonic() < deadline, "role request timed out")
            value = json.loads(bytes(content))
            require(isinstance(value, dict), "invalid role response")
            return value
        finally:
            timer.cancel()
            timer.join()
            if connection is not None:
                connection.close()
            else:
                raw.close()


def service_identity():
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "Splunkd.service",
            "--property=MainPID",
            "--property=ActiveState",
        ],
        capture_output=True,
        check=True,
        timeout=3,
        text=True,
    )
    values = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    require(
        values.get("ActiveState") == "active" and values.get("MainPID", "").isdigit(),
        "service unavailable",
    )
    pid = int(values["MainPID"])
    require(pid > 1, "invalid service pid")
    proc = Path("/proc") / str(pid)
    executable = os.readlink(proc / "exe")
    require(Path(executable).name == "splunkd", "unexpected service process")
    text = (proc / "stat").read_text()
    fields = text[text.rfind(")") + 2 :].split()
    require(len(fields) > 19 and fields[19].isdigit(), "missing process start")
    return {"pid": pid, "start_ticks": fields[19], "exe": executable}


def observer_snapshot(observer, admin_principal, marker):
    from adm_cases_lib.transport import _read_ca

    require(_read_ca(CA) == observer.ca_bytes, "observer CA changed")
    info = observer("GET", "/services/server/info", None, 3)["entry"][0]["content"]
    require(
        hashlib.sha256(info["guid"].encode()).hexdigest() == GUID_HASH
        and info.get("version") == "10.6.0.5"
        and info.get("activeLicenseGroup") == "Enterprise",
        "observer host mismatch",
    )
    context = observer("GET", "/services/authentication/current-context", None, 3)[
        "entry"
    ][0]["content"]
    roles = context.get("roles")
    caps = context.get("capabilities")
    require(
        context.get("username") == admin_principal
        and isinstance(roles, list)
        and roles
        and len(set(roles)) == len(roles)
        and isinstance(caps, list)
        and {"search", "admin_all_objects"}.issubset(caps),
        "observer capability unavailable",
    )
    definitions = {}
    for role in sorted(roles):
        require(isinstance(role, str) and role, "invalid observer role")
        response = observer(
            "GET", "/services/authorization/roles/" + quote(role, safe=""), None, 3
        )
        entries = response.get("entry")
        require(
            isinstance(entries, list)
            and len(entries) == 1
            and entries[0].get("name") == role
            and isinstance(entries[0].get("content"), dict),
            "observer role unavailable",
        )
        canonical = json.dumps(
            entries[0]["content"],
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        definitions[role] = hashlib.sha256(canonical).hexdigest()
    return {
        "guid_hash": hashlib.sha256(info["guid"].encode()).hexdigest(),
        "transport_hash": hashlib.sha256(
            (observer.trust_digest + "\0" + info["guid"]).encode()
        ).hexdigest(),
        "admin_principal": admin_principal,
        "roles": sorted(roles),
        "capabilities": sorted(caps),
        "role_hashes": definitions,
        "service": marker(),
    }


def operator_clear_bound(
    stage,
    ledger,
    principal,
    original,
    observer,
    admin_principal,
    marker,
    before,
    lease_owner,
):
    """Clear only one bound isolated record after fresh authoritative proof."""
    from adm_cases_lib.transport import TransportError

    require(
        original["state"] == "cleanup_unknown"
        and original.get("server_sid")
        and original.get("transport_hash") == before["transport_hash"],
        "not eligible",
    )
    fd = os.open(stage / "events.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 1024 * 1024,
            "unsafe proof journal",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            events = [json.loads(line) for line in stream]
    finally:
        os.close(fd)
    proofs = [
        e
        for e in events
        if e.get("state") == "operator_predelete_proof"
        and e.get("sid") == original["sid"]
    ]
    acks = [
        e
        for e in events
        if e.get("state") == "native_ack_hidden"
        and e.get("method") == "DELETE"
        and e.get("sid") == original["server_sid"]
    ]
    require(
        len(proofs) == 1
        and len(acks) == 1
        and events.index(proofs[0]) < events.index(acks[0]),
        "missing durable predelete/ack evidence",
    )
    proof = proofs[0]
    require(
        proof.get("observer") == before
        and proof.get("principal") == principal
        and proof.get("server_sid") == original["server_sid"]
        and proof.get("query_sha256") == original["query_hash"]
        and proof.get("window") == [original["window_start"], original["window_end"]]
        and re.fullmatch(r"[0-9a-f]{64}", proof.get("native_metadata_sha256", "")),
        "predelete proof mismatch",
    )
    current = observer_snapshot(observer, admin_principal, marker)
    require(current == before, "observer changed before absence check")
    path = "/services/search/jobs/" + quote(original["server_sid"], safe="")
    try:
        observer("GET", path, None, 3)
        raise AssertionError("job remains visible")
    except TransportError as exc:
        require(
            exc.status == 404 and not exc.uncertain,
            "observer absence not authoritative",
        )
    after = observer_snapshot(observer, admin_principal, marker)
    require(after == before, "observer changed after absence check")
    records = [r for r in ledger.outstanding(principal) if r["sid"] == original["sid"]]
    require(len(records) == 1, "record missing")
    record = records[0]
    for field in (
        "sid",
        "server_sid",
        "principal",
        "query_hash",
        "window_start",
        "window_end",
        "transport_hash",
        "state",
    ):
        require(record[field] == original[field], "ledger identity changed")
    if record["lease_owner"] is not None:
        require(
            record["lease_owner"] == lease_owner, "lease owned by another operation"
        )
    journal(
        stage,
        {
            "state": "operator_absence_proof",
            "sid": record["sid"],
            "server_sid": record["server_sid"],
            "revision": record["revision"],
            "observer": after,
        },
    )
    claimed = ledger.claim(
        principal, record["sid"], lease_owner, expected_revision=record["revision"]
    )
    require(
        claimed["state"] == "cleanup_unknown"
        and claimed["server_sid"] == original["server_sid"],
        "claimed record changed",
    )
    terminal = ledger.transition(
        principal,
        claimed["sid"],
        lease_owner,
        "deleted",
        expected_revision=claimed["revision"],
    )
    journal(
        stage,
        {
            "state": "operator_terminal",
            "sid": terminal["sid"],
            "server_sid": terminal["server_sid"],
            "revision": terminal["revision"],
        },
    )
    return terminal


def run_fixture(
    stage,
    principal,
    token,
    transport,
    query,
    start,
    end,
    mode,
    transport_hash,
    *,
    observer=None,
    admin_principal=None,
    marker=service_identity,
):
    """Use actual runtime classes; caller provides a verified supervised transport."""
    from adm_cases_lib.job_ledger import JobLedger, Conflict, NotFound, QuotaExceeded
    from adm_cases_lib.native import NativeComparisonSearch, CaptureUnavailable
    from adm_cases_lib.store import CaseStore, Forbidden, SourceUnavailable

    require(mode in ("create", "delete"), "unknown fault")
    require(stage.is_absolute() and not stage.exists(), "fresh private stage required")
    parent = stage.parent.lstat()
    require(
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.getuid()
        and stat.S_IMODE(parent.st_mode) == 0o700,
        "unsafe parent",
    )
    stage.mkdir(mode=0o700)
    syncdir(stage.parent)
    info = stage.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "unsafe stage",
    )
    ledger = JobLedger(stage / "capture_jobs.sqlite")
    permitted = {principal}
    hidden = []
    trace = []
    injected = [False]
    start_ns = time.time_ns()
    observer_before = []
    runners = []
    convergence_active = [False]
    convergence_jobs = []
    intent_id = "adm-capture-" + secrets.token_hex(16)
    next_intent = [intent_id]
    key = "atlas_job_" + secrets.token_hex(16)
    request_body = {
        "expected_revision": 1,
        "reference": "synthetic-native-job-outcome",
        "label": "Synthetic acknowledgement loss",
    }
    raw_body = json.dumps(request_body, sort_keys=True, separators=(",", ":")).encode()
    journal(
        stage,
        {
            "state": "prepared",
            "mode": mode,
            "principal": principal,
            "intent_id": intent_id,
            "request_key": key,
            "method": "POST",
            "body": raw_body.decode(),
            "body_sha256": hashlib.sha256(raw_body).hexdigest(),
            "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
            "window": [start, end],
            "transport_hash": transport_hash,
            "started_ns": start_ns,
        },
    )

    def injected_request(method, path, data, timeout):
        trace.append(method)
        # Before the mutating native request, persist its identity and intent.
        if (mode == "create" and method == "POST" and not injected[0]) or (
            mode == "delete" and method == "DELETE" and not injected[0]
        ):
            if method == "DELETE":
                bound = ledger.outstanding(principal)
                require(
                    len(bound) == 1
                    and bound[0]["server_sid"] == unquote(path.rsplit("/", 1)[-1]),
                    "delete SID not bound",
                )
                proof = transport("GET", path, None, timeout)
                NativeComparisonSearch._verify_metadata(
                    principal, bound[0], proof, require_complete=False
                )
                if observer is not None:
                    before = observer_snapshot(observer, admin_principal, marker)
                    require(
                        before["transport_hash"] == transport_hash,
                        "observer transport mismatch",
                    )
                    admin_proof = observer("GET", path, None, 3)
                    NativeComparisonSearch._verify_metadata(
                        principal, bound[0], admin_proof, require_complete=False
                    )
                    require(
                        observer_snapshot(observer, admin_principal, marker) == before,
                        "observer changed during job proof",
                    )
                    journal(
                        stage,
                        {
                            "state": "operator_predelete_proof",
                            "observer": before,
                            "principal": principal,
                            "native_metadata_sha256": hashlib.sha256(
                                json.dumps(
                                    admin_proof,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                    allow_nan=False,
                                ).encode()
                            ).hexdigest(),
                            "sid": bound[0]["sid"],
                            "server_sid": bound[0]["server_sid"],
                            "query_sha256": bound[0]["query_hash"],
                            "window": [
                                bound[0]["window_start"],
                                bound[0]["window_end"],
                            ],
                        },
                    )
                    observer_before.append(before)
                journal(
                    stage,
                    {
                        "state": "independent_predelete_identity_verified",
                        "sid": bound[0]["server_sid"],
                        "query_sha256": bound[0]["query_hash"],
                        "principal": principal,
                    },
                )
            journal(
                stage,
                {
                    "state": "native_dispatch",
                    "method": method,
                    "path": path,
                    "data_sha256": hashlib.sha256(
                        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                },
            )
            result = transport(method, path, data, timeout)
            sid = (
                result.get("sid")
                if method == "POST"
                else unquote(path.rsplit("/", 1)[-1])
            )
            require(
                isinstance(sid, str)
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid) is not None,
                "invalid native identity",
            )
            # This journal is fixture-only. The returned creation SID is never
            # delivered to NativeComparisonSearch on the lost-ack path.
            journal(stage, {"state": "native_ack_hidden", "method": method, "sid": sid})
            hidden.append(sid)
            injected[0] = True
            raise TimeoutError("injected lost acknowledgement")
        if convergence_active[0] and method in ("POST", "DELETE"):
            journal(
                stage,
                {
                    "state": "convergence_native_dispatch",
                    "method": method,
                    "path": path,
                },
            )
            result = transport(method, path, data, timeout)
            actual_sid = (
                result.get("sid")
                if method == "POST"
                else unquote(path.rsplit("/", 1)[-1])
            )
            require(
                isinstance(actual_sid, str)
                and re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", actual_sid) is not None,
                "invalid convergence SID",
            )
            journal(
                stage,
                {
                    "state": "convergence_native_ack",
                    "method": method,
                    "sid": actual_sid,
                },
            )
            if method == "POST":
                convergence_jobs.append(actual_sid)
            return result
        return transport(method, path, data, timeout)

    def runner(current_hash=transport_hash):
        return NativeComparisonSearch(
            token,
            request=injected_request,
            ledger=ledger,
            transport_hash=current_hash,
            sid_factory=lambda: next_intent[0],
        )

    def resolve(_principal, reference):
        current = runner()
        runners.append(current)
        current.run(principal, query, start, end)
        return {
            "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "data": {"synthetic": True},
            "source": {"reference": reference},
        }

    store = CaseStore(
        stage / "cases.sqlite",
        lambda p, *_: p in permitted,
        capture_resolver=resolve,
        source_entitlement=lambda *_: True,
    )
    case = store.create(
        principal,
        "case-" + secrets.token_hex(16),
        {
            "schema_version": 1,
            "title": "Synthetic job outcome",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        },
    )
    case_id = case["id"]
    journal(
        stage,
        {
            "state": "case_ready",
            "case_id": case_id,
            "path": "/cases/" + case_id + "/captures",
            "method": "POST",
            "request_key": key,
            "body_sha256": hashlib.sha256(raw_body).hexdigest(),
            "principal": principal,
        },
    )

    def exact_capture():
        body = json.loads(raw_body)
        return store.append_capture(
            principal,
            key,
            case_id,
            body["expected_revision"],
            body["reference"],
            body["label"],
        )

    try:
        exact_capture()
        raise AssertionError("lost acknowledgement was not observed")
    except SourceUnavailable:
        pass
    require(injected[0] and len(hidden) == 1, "native acknowledgement not proven")
    records = ledger.outstanding(principal)
    require(
        len(records) == 1 and records[0]["sid"] == intent_id,
        "unexpected ledger identity",
    )
    record = records[0]
    expected_state = "creation_unknown" if mode == "create" else "cleanup_unknown"
    require(record["state"] == expected_state, "unexpected uncertainty state")
    require(
        (record["server_sid"] is None)
        if mode == "create"
        else (record["server_sid"] == hidden[0]),
        "invalid bound SID",
    )
    require(
        record["query_hash"] == hashlib.sha256(query.encode()).hexdigest()
        and record["transport_hash"] == transport_hash
        and record["principal"] == principal,
        "ledger provenance mismatch",
    )
    with closing(sqlite3.connect(stage / "cases.sqlite")) as db:
        count = db.execute(
            "SELECT count(*) FROM requests WHERE principal=? AND request_id=?",
            (principal, key),
        ).fetchone()[0]
    require(count == 0, "uncertain capture receipt unexpectedly committed")
    journal(
        stage,
        {"state": "uncertainty_observed", "ledger": record, "capture_receipts": count},
    )

    posts_before = trace.count("POST")
    try:
        exact_capture()
        raise AssertionError("unresolved retry unexpectedly succeeded")
    except SourceUnavailable:
        pass
    require(trace.count("POST") == posts_before, "retry dispatched replacement job")
    permitted.clear()
    try:
        exact_capture()
        raise AssertionError("revoked library entitlement succeeded")
    except Forbidden:
        pass
    permitted.add(principal)
    try:
        runner("0" * 64).run(principal, query, start, end)
        raise AssertionError("changed transport accepted")
    except CaptureUnavailable:
        pass
    require(trace.count("POST") == posts_before, "changed context dispatched job")
    try:
        ledger.claim(
            principal + "-other",
            intent_id,
            "e" * 32,
            expected_revision=record["revision"],
        )
        raise AssertionError("other principal claimed job")
    except NotFound:
        pass

    current = ledger.outstanding(principal)[0]
    if current["lease_owner"] is None:
        current = ledger.claim(
            principal, intent_id, "c" * 32, expected_revision=current["revision"]
        )
    try:
        ledger.claim(
            principal, intent_id, "d" * 32, expected_revision=current["revision"]
        )
        raise AssertionError("held lease was stolen")
    except Conflict:
        pass

    # Fill only the private fixture ledger to exercise its unchanged global quota.
    for i in range(2):
        ledger.reserve(
            "fixture-quota-fill",
            "adm-capture-" + ("%032x" % (i + 1)),
            "a" * 64,
            1,
            2,
            "b" * 32,
            transport_hash=transport_hash,
        )
    try:
        ledger.reserve(
            principal,
            "adm-capture-" + "f" * 32,
            "a" * 64,
            1,
            2,
            "b" * 32,
            transport_hash=transport_hash,
        )
        raise AssertionError("unknown slot was not charged")
    except QuotaExceeded:
        pass
    journal(
        stage,
        {
            "state": "retry_and_quota_verified",
            "same_body_sha256": hashlib.sha256(raw_body).hexdigest(),
            "principal": principal,
            "request_key": key,
            "post_count_unchanged": True,
            "fixture_entitlement_denied": True,
            "changed_transport_denied": True,
            "other_principal_denied": True,
            "held_lease_protected": True,
            "private_quota_full": True,
        },
    )

    # Only the fixture observer sees the hidden SID, and can never bind it to
    # the runtime ledger. For creation, require exact native metadata before a
    # separately journalled deletion. For deletion, a 404 is observed only.
    sid = hidden[0]
    path = "/services/search/jobs/" + quote(sid, safe="")
    if mode == "create":
        status = transport("GET", path, None, 3)
        proof = dict(record, server_sid=sid)
        NativeComparisonSearch._verify_metadata(
            principal, proof, status, require_complete=False
        )
        journal(
            stage,
            {
                "state": "owned_cleanup_intent",
                "sid": sid,
                "query_sha256": record["query_hash"],
                "principal": principal,
            },
        )
        transport("DELETE", path, None, 3)
        journal(stage, {"state": "owned_cleanup_acknowledged", "sid": sid})
    from adm_cases_lib.transport import TransportError

    try:
        transport("GET", path, None, 3)
        raise AssertionError("native job remains")
    except TransportError as exc:
        require(exc.status == 404, "native absence uncertain")
    require(
        ledger.outstanding(principal)[0]["state"] == expected_state,
        "uncertain ledger state erased",
    )
    journal(
        stage,
        {
            "state": "caller_sid_404_observed",
            "sid": sid,
            "ledger_state_retained": expected_state,
        },
    )
    cleared = False
    if observer is not None:
        require(
            mode == "delete" and len(observer_before) == 1 and runners,
            "operator proof unavailable",
        )
        current = ledger.outstanding(principal)[0]
        require(
            current["lease_owner"] == runners[-1].lease_owner,
            "retry lease ownership changed",
        )
        terminal = operator_clear_bound(
            stage,
            ledger,
            principal,
            record,
            observer,
            admin_principal,
            marker,
            observer_before[0],
            runners[-1].lease_owner,
        )
        require(
            terminal["state"] == "deleted" and terminal["server_sid"] == sid,
            "terminal transition mismatch",
        )
        cleared = True
        next_intent[0] = "adm-capture-" + secrets.token_hex(16)
        require(next_intent[0] != intent_id, "convergence identity collision")
        journal(
            stage,
            {
                "state": "convergence_intent",
                "principal": principal,
                "request_key": key,
                "body_sha256": hashlib.sha256(raw_body).hexdigest(),
                "new_job_intent": next_intent[0],
            },
        )
        convergence_active[0] = True
        captured = exact_capture()
        require(
            len(captured["captures"]) == 1
            and len(captured["capture_ids"]) == 1
            and captured["revision"] == 2,
            "exact retry did not converge",
        )
        capture_id = captured["capture_ids"][0]
        require(
            len(convergence_jobs) == 1 and convergence_jobs[0] != sid,
            "convergence job identity invalid",
        )
        with closing(sqlite3.connect(stage / "cases.sqlite")) as db:
            count = db.execute(
                "SELECT count(*) FROM requests WHERE principal=? AND request_id=?",
                (principal, key),
            ).fetchone()[0]
        require(
            count == 1 and ledger.outstanding(principal) == [],
            "convergence receipt or ledger unresolved",
        )
        before_posts = trace.count("POST")
        replay = exact_capture()
        require(
            replay["capture_ids"] == [capture_id]
            and replay["revision"] == captured["revision"]
            and trace.count("POST") == before_posts,
            "convergence replay changed identity",
        )
        require(
            observer_snapshot(observer, admin_principal, marker) == observer_before[0],
            "observer changed before convergence check",
        )
        new_path = "/services/search/jobs/" + quote(convergence_jobs[0], safe="")
        try:
            observer("GET", new_path, None, 3)
            raise AssertionError("convergence job remains")
        except TransportError as exc:
            require(
                exc.status == 404 and not exc.uncertain, "convergence absence uncertain"
            )
        require(
            observer_snapshot(observer, admin_principal, marker) == observer_before[0],
            "observer changed after convergence check",
        )
        journal(
            stage,
            {
                "state": "convergence_verified",
                "principal": principal,
                "request_key": key,
                "body_sha256": hashlib.sha256(raw_body).hexdigest(),
                "receipt_count": count,
                "capture_id": capture_id,
                "revision": captured["revision"],
                "server_sid": convergence_jobs[0],
                "admin_sid_404": True,
            },
        )
    return {
        "status": "passed_fixture_checks",
        "mode": mode,
        "uncertain_state": expected_state,
        "caller_sid_404": True,
        "authoritative_absence_unverified": not cleared,
        "isolated_ledger_retained": True,
        "operator_bound_cleanup_cleared": cleared,
        "exact_capture_converged": cleared,
        "fixture_permission_only": True,
        "stage": str(stage),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed", action="store_true", required=True)
    parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        require(len(raw) <= MAX_INPUT, "input too large")
        config = json.loads(raw)
        base_keys = {"principal", "token", "query", "start", "end", "mode"}
        require(
            set(config) in (base_keys, base_keys | {"admin_principal", "admin_token"}),
            "invalid input fields",
        )
        import pwd

        require(
            os.uname().machine == "x86_64"
            and os.getuid() == pwd.getpwnam("splunk").pw_uid,
            "unsupported runtime",
        )
        sys.path.insert(0, str(BIN))
        from adm_cases_lib.transport import SupervisedTransport

        transport = SupervisedTransport(config["token"], "https://127.0.0.1:8089", CA)
        require(transport.preflight(), "transport unavailable")
        info = transport("GET", "/services/server/info", None, 3)["entry"][0]["content"]
        require(
            hashlib.sha256(info["guid"].encode()).hexdigest() == GUID_HASH
            and info.get("version") == "10.6.0.5"
            and info.get("activeLicenseGroup") == "Enterprise",
            "unexpected host",
        )
        context = transport("GET", "/services/authentication/current-context", None, 3)[
            "entry"
        ][0]["content"]
        require(
            context.get("username") == config["principal"]
            and "search" in context.get("capabilities", []),
            "principal context mismatch",
        )
        transport_hash = hashlib.sha256(
            (transport.trust_digest + "\0" + info["guid"]).encode()
        ).hexdigest()
        observer = None
        if "admin_token" in config:
            require(
                config["mode"] == "delete",
                "observer only supported for bound delete uncertainty",
            )
            admin_transport = SupervisedTransport(
                config["admin_token"], "https://127.0.0.1:8089", CA
            )
            require(admin_transport.preflight(), "observer transport unavailable")
            observer = AdminObserver(admin_transport, config["admin_token"])
        result = run_fixture(
            ROOT / config["mode"],
            config["principal"],
            config["token"],
            transport,
            config["query"],
            config["start"],
            config["end"],
            config["mode"],
            transport_hash,
            observer=observer,
            admin_principal=config.get("admin_principal"),
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed_or_uncertain", "error_type": type(exc).__name__}
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
