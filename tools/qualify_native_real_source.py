#!/usr/bin/env python3
"""Check the shape and consistency of a private real-source evidence summary.

This does not connect to Splunk or independently verify the summary's claims.
"""

import argparse
import hashlib
import json
import re
import sys
import base64
import fcntl
import http.client
import os
import pathlib
import ssl
import stat
import uuid
from datetime import datetime, timezone

MAX_INPUT = 256 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
PHASES = (
    "allowed",
    "permission_revoked",
    "permission_restored",
    "config_changed",
    "config_restored",
)


def check_summary(data):
    """Return named gaps only; never echo private input or declare qualification."""
    gaps = []

    def need(condition, name):
        if not condition:
            gaps.append(name)

    def digest(value):
        return isinstance(value, str) and DIGEST.fullmatch(value) is not None

    def text(value):
        return isinstance(value, str) and 0 < len(value) <= 512 and bool(value.strip())

    def timestamp(value):
        try:
            if not isinstance(value, str) or not value.endswith("Z"):
                return None
            return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(
                timezone.utc
            )
        except ValueError:
            return None

    if not isinstance(data, dict):
        return ["summary_object"]
    source = data.get("source")
    source = source if isinstance(source, dict) else {}
    for key in (
        "product",
        "version",
        "index",
        "sourcetype",
        "source",
        "authority",
        "scope",
    ):
        need(text(source.get(key)), "source." + key)
    need(source.get("real") is True, "source.real")
    for key in (
        "schema_evidence_sha256",
        "provenance_sha256",
        "config_revision_sha256",
    ):
        need(digest(source.get(key)), "source." + key)

    entitlement = data.get("entitlement")
    entitlement = entitlement if isinstance(entitlement, dict) else {}
    for key in ("principal", "effective_roles", "index_access", "search_filter"):
        need(text(entitlement.get(key)), "entitlement." + key)
    need(digest(entitlement.get("evidence_sha256")), "entitlement.evidence_sha256")
    need(entitlement.get("current_verified") is True, "entitlement.current_verified")

    coverage = data.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    for key in (
        "historical_scope",
        "loss_limit",
        "lateness_limit",
        "clock_uncertainty",
    ):
        need(text(coverage.get(key)), "coverage." + key)
    need(digest(coverage.get("evidence_sha256")), "coverage.evidence_sha256")
    windows = data.get("windows")
    valid_windows = isinstance(windows, list) and 2 <= len(windows) <= 3
    durations = []
    previous_end = None
    if valid_windows:
        for item in windows:
            if not isinstance(item, dict):
                valid_windows = False
                break
            start, end = timestamp(item.get("start")), timestamp(item.get("end"))
            if (
                start is None
                or end is None
                or not (0 < (end - start).total_seconds() <= 300)
            ):
                valid_windows = False
                break
            if previous_end is not None and start < previous_end:
                valid_windows = False
                break
            previous_end = end
            durations.append((end - start).total_seconds())
        valid_windows = valid_windows and len(set(durations)) == 1
    need(valid_windows, "windows.comparable")

    capture = data.get("capture")
    capture = capture if isinstance(capture, dict) else {}
    for key in (
        "request_body_sha256",
        "request_key_sha256",
        "path_sha256",
        "caller_sha256",
        "capture_id_sha256",
        "evidence_sha256",
        "config_revision_sha256",
    ):
        need(digest(capture.get(key)), "capture." + key)
    need(capture.get("dispatch") == "completed", "capture.dispatch")
    need(
        capture.get("supervised_transport_verified") is True,
        "capture.supervised_transport_verified",
    )
    need(
        capture.get("config_revision_sha256") == source.get("config_revision_sha256")
        and digest(capture.get("config_revision_sha256")),
        "capture.source_revision_match",
    )

    phases = data.get("phases")
    phases = phases if isinstance(phases, dict) else {}
    for phase in PHASES:
        item = phases.get(phase)
        item = item if isinstance(item, dict) else {}
        expected = (
            "visible"
            if phase in ("allowed", "permission_restored", "config_restored")
            else "withheld"
        )
        need(
            item.get("effective_state_verified") is True,
            phase + ".effective_state_verified",
        )
        need(
            digest(item.get("state_evidence_sha256")), phase + ".state_evidence_sha256"
        )
        for operation in ("stored_read", "selected_export", "original_retry"):
            observation = item.get(operation)
            observation = observation if isinstance(observation, dict) else {}
            need(
                observation.get("dispatch") == "completed",
                phase + "." + operation + ".dispatch",
            )
            need(
                observation.get("result") == expected,
                phase + "." + operation + ".result",
            )
            need(
                digest(observation.get("response_evidence_sha256")),
                phase + "." + operation + ".response_evidence_sha256",
            )
            if operation == "original_retry":
                for key in (
                    "request_body_sha256",
                    "request_key_sha256",
                    "path_sha256",
                    "caller_sha256",
                ):
                    need(
                        digest(capture.get(key))
                        and observation.get(key) == capture.get(key),
                        phase + ".original_retry." + key,
                    )
            else:
                need(
                    digest(capture.get("capture_id_sha256"))
                    and observation.get("capture_id_sha256")
                    == capture.get("capture_id_sha256"),
                    phase + "." + operation + ".selection",
                )
    return gaps


# Only the authorized native target uses this entry point.  It deliberately
# changes neither roles nor app configuration; a separate reviewed lifecycle
# must enable and restore the gates and account for cases and source jobs.
STAGE = pathlib.Path("/opt/splunk/var/atlas-real-source-20261118")
API = "/servicesNS/nobody/splunk_adm/adm/investigations"
SERVER_GUID_SHA256 = "8c003a4afae8d1197dd165a6ed76e66090d73f1ea9ddcd1723991a5143de6ca3"
PACKAGE_SHA256 = "0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e"
UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def checked_journal(fd):
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or info.st_size > 16 * 1024 * 1024
    ):
        raise ValueError("unsafe journal")


def journal_events(directory):
    """Recover only an incomplete final record; never accept corrupt interior data."""
    try:
        fd = os.open(
            directory / "operations.jsonl", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        )
    except FileNotFoundError:
        return []
    try:
        checked_journal(fd)
        with os.fdopen(fd, "r+b", closefd=False) as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError("journal too large")
            split = raw.rfind(b"\n") + 1
            complete, tail = raw[:split], raw[split:]
            events = []
            for line in complete.splitlines():
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("invalid journal event")
                events.append(event)
            if tail:
                # Quarantine and sync exact bytes before truncating the journal.
                # Each quarantine filename is a durable marker of the repair.
                name = "journal-tail-" + uuid.uuid4().hex
                tail_fd = os.open(
                    directory / name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK,
                    0o600,
                )
                try:
                    with os.fdopen(tail_fd, "wb", closefd=False) as saved:
                        saved.write(tail)
                        saved.flush()
                        os.fsync(tail_fd)
                finally:
                    os.close(tail_fd)
                sync_directory(directory)
                stream.seek(split)
                stream.truncate()
                stream.flush()
                os.fsync(fd)
                marker = {
                    "state": "tail_quarantined",
                    "file": name,
                    "sha256": hashlib.sha256(tail).hexdigest(),
                }
                stream.seek(0, os.SEEK_END)
                stream.write(
                    json.dumps(marker, sort_keys=True, separators=(",", ":")).encode()
                    + b"\n"
                )
                stream.flush()
                os.fsync(fd)
                events.append(marker)
        return events
    finally:
        os.close(fd)


def journal_append(directory, event):
    # Recover a prior interrupted append before adding any new record.
    journal_events(directory)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(directory / "operations.jsonl", flags, 0o600)
    try:
        checked_journal(fd)
        with os.fdopen(fd, "ab", closefd=False) as stream:
            stream.write(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(directory)


def operation_spec(command, prior=None):
    """Build a narrowly bounded request; retries use the retained original bytes."""
    action = command.get("action")
    if action == "retry":
        if (
            not isinstance(prior, dict)
            or prior.get("action") not in ("capture", "create")
            or prior.get("state") != "dispatching"
        ):
            raise ValueError("missing original write intent")
        if prior.get("caller") != command.get("username"):
            raise ValueError("caller differs")
        return {k: prior[k] for k in ("method", "path", "body", "key")}
    if action == "create":
        body = command.get("body")
        if not isinstance(body, dict) or set(body) != {
            "schema_version",
            "title",
            "window",
        }:
            raise ValueError("invalid case body")
        return {
            "method": "POST",
            "path": "/cases",
            "body": json.dumps(body, separators=(",", ":")),
            "key": str(uuid.uuid4()),
        }
    case_id = command.get("case_id")
    if not isinstance(case_id, str) or not UUID.fullmatch(case_id):
        raise ValueError("invalid case identity")
    path = "/cases/" + case_id
    if action == "capture":
        body = command.get("body")
        if not isinstance(body, dict) or set(body) != {
            "expected_revision",
            "reference",
            "label",
        }:
            raise ValueError("invalid capture body")
        return {
            "method": "POST",
            "path": path + "/captures",
            "body": json.dumps(body, separators=(",", ":")),
            "key": str(uuid.uuid4()),
        }
    if action in ("read", "export"):
        capture_id = command.get("capture_id")
        if not isinstance(capture_id, str) or not UUID.fullmatch(capture_id):
            raise ValueError("invalid capture identity")
        return {
            "method": "GET",
            "path": path
            + ("/export" if action == "export" else "")
            + "?capture_id="
            + capture_id,
            "body": None,
            "key": None,
        }
    raise ValueError("invalid action")


def installed_request(command, stage=STAGE):
    """Dispatch one private, durably journalled request to the local search head."""
    if not isinstance(command, dict) or not all(
        isinstance(command.get(k), str) and command[k]
        for k in ("username", "password", "action")
    ):
        raise ValueError("invalid input")
    os.umask(0o077)
    try:
        os.mkdir(stage, 0o700)
        parent_fd = os.open(stage.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except FileExistsError:
        pass
    info = os.lstat(stage)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("unsafe evidence directory")
    lock = os.open(
        stage / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise ValueError("unsafe lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        events = journal_events(stage)
        prior = None
        if command["action"] == "retry":
            original = command.get("original_operation")
            if not isinstance(original, str) or not UUID.fullmatch(original):
                raise ValueError("invalid original identity")
            matches = [
                event
                for event in events
                if event.get("operation") == original
                and event.get("state") == "dispatching"
            ]
            if len(matches) != 1:
                raise ValueError("ambiguous original identity")
            prior = matches[0]
        if command["action"] in ("create", "capture"):
            successful = {
                e.get("operation")
                for e in events
                if e.get("state") == "response" and 200 <= e.get("status", 0) < 300
            }
            resolved = {
                e.get("original_operation")
                for e in events
                if e.get("state") == "dispatching"
                and e.get("action") == "retry"
                and e.get("operation") in successful
            }
            unresolved = [
                e
                for e in events
                if e.get("state") == "dispatching"
                and e.get("action") in ("create", "capture")
                and e.get("operation") not in successful | resolved
            ]
            if unresolved:
                raise ValueError("unresolved prior write")
        spec = operation_spec(command, prior)
        # Verify this is the recorded host and platform before any case dispatch.
        context = ssl.create_default_context(cafile="/opt/splunk/etc/auth/cacert.pem")
        connection = http.client.HTTPSConnection(
            "127.0.0.1", 8089, context=context, timeout=15
        )
        authorization = (
            "Basic "
            + base64.b64encode(
                (command["username"] + ":" + command["password"]).encode()
            ).decode()
        )
        try:
            connection.request(
                "GET",
                "/services/server/info?output_mode=json",
                headers={"Authorization": authorization, "Connection": "close"},
            )
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 1024 * 1024:
                raise ValueError("host attestation failed")
            info = json.loads(raw)["entry"][0]["content"]
            if (
                hashlib.sha256(info["guid"].encode()).hexdigest() != SERVER_GUID_SHA256
                or info.get("version") != "10.6.0.5"
                or info.get("activeLicenseGroup") != "Enterprise"
            ):
                raise ValueError("unexpected host")
        finally:
            connection.close()
        operation = str(uuid.uuid4())
        # This record is durable before the socket is opened; a missing response
        # remains uncertain and must never be replaced by a fresh capture key.
        journal_append(
            stage,
            {
                "state": "dispatching",
                "operation": operation,
                "action": command["action"],
                "caller": command["username"],
                "original_operation": command.get("original_operation"),
                **spec,
            },
        )
        try:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", 8089, context=context, timeout=100
            )
            headers = {"Authorization": authorization, "Connection": "close"}
            if spec["key"]:
                headers["Idempotency-Key"] = spec["key"]
            if spec["body"] is not None:
                headers["Content-Type"] = "application/json"
            path = (
                API
                + spec["path"]
                + ("&" if "?" in spec["path"] else "?")
                + "output_mode=json"
            )
            try:
                connection.request(
                    spec["method"], path, body=spec["body"], headers=headers
                )
                response = connection.getresponse()
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError("response limit")
                result = json.loads(raw) if raw else {}
                journal_append(
                    stage,
                    {
                        "state": "response",
                        "operation": operation,
                        "status": response.status,
                        "result": result,
                    },
                )
            finally:
                connection.close()
        except Exception:
            # Do not log exception text, which can contain sensitive data.
            journal_append(stage, {"state": "uncertain", "operation": operation})
            return {"operation": operation, "state": "uncertain"}
        return {"operation": operation, "state": "response", "status": response.status}
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--installed",
        action="store_true",
        help="run one private installed request from bounded stdin",
    )
    parser.add_argument(
        "summary",
        nargs="?",
        help="private JSON evidence summary (not source rows or credentials)",
    )
    args = parser.parse_args()
    if args.installed:
        try:
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
            if len(raw) > MAX_INPUT:
                raise ValueError("input too large")
            result = installed_request(json.loads(raw))
        except Exception:
            print(json.dumps({"state": "refused"}))
            return 2
        print(json.dumps(result))
        return 0 if result["state"] == "response" else 1
    if not args.summary:
        parser.error("summary required")
    try:
        with open(args.summary, "rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("input too large")
        data = json.loads(
            raw,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except (OSError, ValueError, UnicodeError):
        print(json.dumps({"status": "invalid_input"}))
        return 2
    gaps = check_summary(data)
    print(
        json.dumps(
            {
                "status": "incomplete" if gaps else "structurally_complete_unverified",
                "gaps": gaps,
                "summary_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    )
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
