#!/usr/bin/env python3
"""Capture tiny private Cloud samples; they do not establish complete coverage."""

from __future__ import annotations

import argparse
import datetime as dt
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from urllib.parse import quote

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.discover_feature_sources import Refused, cloud_client, indexes, wall_deadline

SPECS = {
    "hubble": ("adm_index_hubble", "cilium:hubble:flow"),
    "pods": ("adm_index_k8s", "kube:object:pods"),
}
FIELDS = {"_raw", "_time", "_indextime", "source", "sourcetype", "index"}
OPTIONAL_FIELDS = {"host", "k8s.cluster.name", "_bkt", "_cd"}
SID = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")


def _true(value):
    return value is True or (type(value) is int and value == 1) or value == "1"


def _false(value):
    return value is False or (type(value) is int and value == 0) or value == "0"


def _time(value):
    if type(value) not in (str, int, float):
        raise Refused("invalid_time")
    try:
        text = str(value)
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", text):
            number = Decimal(text)
        elif isinstance(value, str):
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError()
            number = Decimal(str(parsed.timestamp()))
        else:
            raise ValueError()
        if not number.is_finite() or number < 0:
            raise ValueError()
        return number
    except (ValueError, OverflowError, InvalidOperation):
        raise Refused("invalid_time") from None


def _query(family, index, end):
    if family not in SPECS or not re.fullmatch(
        r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", index
    ):
        raise Refused("invalid_selection")
    sourcetype = SPECS[family][1]
    return (
        f'search index="{index}" sourcetype="{sourcetype}" '
        f"| where _indextime < {end} | head 4 "
        "| table _raw _time _indextime source sourcetype index host k8s.cluster.name _bkt _cd"
    )


def _private_directory(path):
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.name in ("", ".", "..")
    ):
        raise Refused("invalid_destination")
    parent = path.parent
    try:
        for ancestor in (parent, *parent.parents):
            info = ancestor.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or os.path.lexists(ancestor / ".git")
            ):
                raise Refused("invalid_destination")
        info = parent.lstat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise Refused("invalid_destination")
        os.mkdir(path, 0o700)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise Refused("invalid_destination")
    except OSError:
        raise Refused("invalid_destination") from None


def _write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise Refused("output_unavailable")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if fd is not None:
            os.close(fd)


def _save_manifest(destination, manifest):
    data = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
    temporary = destination / ".manifest-next"
    _write(temporary, data)
    os.replace(temporary, destination / "manifest.json")
    descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _call(client, method, path, data, timeout):
    if timeout <= 0:
        raise Refused("deadline")
    with wall_deadline(timeout):
        return client.call(method, path, data, timeout=timeout)


def _entry(payload, sid, principal, query, start, end):
    entries = payload.get("entry") if isinstance(payload, dict) else None
    if (
        not isinstance(entries, list)
        or len(entries) != 1
        or not isinstance(entries[0], dict)
    ):
        raise Refused("job_proof_unavailable")
    item = entries[0]
    content, acl = item.get("content"), item.get("acl")
    if not isinstance(content, dict) or not isinstance(acl, dict):
        raise Refused("job_proof_unavailable")
    job_request = content.get("request")
    if (
        not isinstance(job_request, dict)
        or content.get("sid") != sid
        or job_request.get("id") not in (None, "")
        or acl.get("owner") != principal
        or acl.get("app") != "splunk_adm"
        or job_request.get("search") != query
        or content.get("search") != query
        or _time(job_request.get("earliest_time")) != start
        or _time(job_request.get("latest_time")) != end
    ):
        raise Refused("job_proof_unavailable")
    return content


def _remaining(deadline):
    return max(0, deadline - time.monotonic())


def capture(client, destination, start, end, *, now=None):
    """Run at most two fixed searches; never expose raw values in return/errors."""
    if (
        type(start) is not int
        or type(end) is not int
        or start < 0
        or not 0 < end - start <= 300
        or end > (int(time.time()) if now is None else now)
    ):
        raise Refused("invalid_window")
    if not isinstance(destination, Path):
        raise Refused("invalid_destination")
    _private_directory(destination)
    deadline = time.monotonic() + 25
    cleanup_budget = 3.0
    collected = {}
    manifest = {
        "schema_version": 1,
        "window": {"start": start, "end": end},
        "complete": False,
        "qualification": "head_sample_only",
        "status": "in_progress",
        "attempts": [],
        "families": {},
    }
    _save_manifest(destination, manifest)
    try:
        identity = _call(
            client,
            "GET",
            "/services/authentication/current-context?output_mode=json",
            None,
            _remaining(deadline),
        )
        entries = identity.get("entry")
        if (
            not isinstance(entries, list)
            or len(entries) != 1
            or not isinstance(entries[0], dict)
        ):
            raise Refused("identity_unavailable")
        content = entries[0].get("content")
        principal = content.get("username") if isinstance(content, dict) else None
        if not isinstance(principal, str) or not principal or principal == "nobody":
            raise Refused("identity_unavailable")
        selected = {}
        for family, (macro, _) in SPECS.items():
            with wall_deadline(_remaining(deadline)):
                values = indexes(client, (macro,))
            if len(values) != 1:
                raise Refused("index_unavailable")
            selected[family] = values[0]
        for family, index in selected.items():
            query = _query(family, index, end)
            sid = None
            failure = None
            attempt = {"family": family, "status": "creation_pending"}
            manifest["attempts"].append(attempt)
            _save_manifest(destination, manifest)
            try:
                created = _call(
                    client,
                    "POST",
                    "/servicesNS/nobody/splunk_adm/search/jobs?output_mode=json",
                    {
                        "search": query,
                        "earliest_time": str(start),
                        "latest_time": str(end),
                        "max_time": "5",
                        "ttl": "30",
                        "auto_cancel": "10",
                        "exec_mode": "normal",
                        "status_buckets": "0",
                    },
                    _remaining(deadline),
                )
                value = created.get("sid") if isinstance(created, dict) else None
                if not isinstance(value, str) or not SID.fullmatch(value):
                    raise Refused("creation_unconfirmed")
                sid = value
                path = "/services/search/jobs/" + quote(sid, safe="")
                attempt.update(status="created", server_sid=sid)
                _save_manifest(destination, manifest)
                while True:
                    payload = _call(
                        client,
                        "GET",
                        path + "?output_mode=json",
                        None,
                        _remaining(deadline),
                    )
                    info = _entry(payload, sid, principal, query, start, end)
                    if (
                        payload.get("messages")
                        or info.get("messages")
                        or info.get("dispatchState")
                        in ("FAILED", "CANCELED", "FINALIZED")
                    ):
                        raise Refused("incomplete")
                    done = info.get("isDone")
                    if not _true(done) and not _false(done):
                        raise Refused("incomplete")
                    if _true(done):
                        break
                    if _remaining(deadline) <= 0:
                        raise Refused("deadline")
                    time.sleep(min(0.1, _remaining(deadline)))
                count = info.get("resultCount")
                if (
                    info.get("dispatchState") != "DONE"
                    or not _false(info.get("isFinalized"))
                    or not _false(info.get("eventIsTruncated"))
                    or not _false(info.get("resultIsTruncated", False))
                    or str(info.get("dropCount")) != "0"
                    or type(count) not in (int, str)
                    or not re.fullmatch(r"[0-4]", str(count))
                ):
                    raise Refused("incomplete")
                response = _call(
                    client,
                    "GET",
                    path + "/results?output_mode=json&count=4&offset=0",
                    None,
                    _remaining(deadline),
                )
                rows = response.get("results") if isinstance(response, dict) else None
                if (
                    not _false(response.get("preview"))
                    or response.get("messages")
                    or not isinstance(rows, list)
                    or len(rows) != int(count)
                ):
                    raise Refused("incomplete")
                for row in rows:
                    if (
                        not isinstance(row, dict)
                        or not FIELDS <= set(row)
                        or set(row) - FIELDS - OPTIONAL_FIELDS
                        or any(
                            not isinstance(row[key], str)
                            or not 0 < len(row[key]) <= 4096
                            for key in OPTIONAL_FIELDS & set(row)
                        )
                        or not isinstance(row["_raw"], str)
                        or not row["_raw"]
                        or len(row["_raw"].encode("utf-8")) > 32 * 1024
                        or not isinstance(row["source"], str)
                        or not 0 < len(row["source"]) <= 4096
                        or row["index"] != index
                        or row["sourcetype"] != SPECS[family][1]
                        or not start <= _time(row["_time"]) < end
                        or _time(row["_indextime"]) >= end
                    ):
                        raise Refused("invalid_sample")
                collected[family] = rows
            except Exception:
                failure = (
                    "creation_unconfirmed" if sid is None else "capture_unavailable"
                )
            finally:
                if sid is not None:
                    started = time.monotonic()
                    try:
                        if cleanup_budget <= 0:
                            raise Refused("cleanup_unconfirmed")
                        metadata = _call(
                            client,
                            "GET",
                            path + "?output_mode=json",
                            None,
                            cleanup_budget,
                        )
                        _entry(metadata, sid, principal, query, start, end)
                        remaining = cleanup_budget - (time.monotonic() - started)
                        _call(
                            client,
                            "DELETE",
                            path + "?output_mode=json",
                            None,
                            remaining,
                        )
                        attempt["status"] = "deleted"
                    except Exception:
                        failure = "cleanup_unconfirmed"
                        attempt["status"] = "cleanup_unconfirmed"
                    finally:
                        cleanup_budget = max(
                            0, cleanup_budget - (time.monotonic() - started)
                        )
            if sid is None:
                attempt["status"] = "creation_unconfirmed"
            _save_manifest(destination, manifest)
            if failure is not None or cleanup_budget <= 0:
                raise Refused(failure or "cleanup_unconfirmed")
        for family, rows in collected.items():
            data = (
                "\n".join(
                    json.dumps(
                        row, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                    )
                    for row in rows
                )
                + ("\n" if rows else "")
            ).encode("utf-8")
            _write(destination / (family + ".jsonl"), data)
            manifest["families"][family] = {
                "file": family + ".jsonl",
                "count": len(rows),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        manifest["status"] = "captured"
        _save_manifest(destination, manifest)
        return {
            "status": "ok",
            "samples": {family: len(rows) for family, rows in collected.items()},
        }
    except Exception as exc:
        reason = (
            str(exc)
            if isinstance(exc, Refused)
            and str(exc) in ("creation_unconfirmed", "cleanup_unconfirmed")
            else "capture_unavailable"
        )
        try:
            manifest["status"] = reason
            _save_manifest(destination, manifest)
        except Exception:
            pass
        raise Refused(reason) from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--profile", required=True, choices=["cloud"])
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--start", required=True, type=int)
    parser.add_argument("--end", required=True, type=int)
    args = parser.parse_args()
    try:
        result = capture(
            cloud_client(args.credentials, args.profile),
            args.destination,
            args.start,
            args.end,
        )
    except Exception as exc:
        reason = (
            str(exc)
            if isinstance(exc, Refused)
            and str(exc) in ("creation_unconfirmed", "cleanup_unconfirmed")
            else "capture_unavailable"
        )
        result = {"status": "error", "reason": reason}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
