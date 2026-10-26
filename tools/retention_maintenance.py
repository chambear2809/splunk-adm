#!/usr/bin/env python3
"""Bounded, explicit Atlas retention maintenance without collection rewrites."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time
from urllib.parse import quote, urlencode
import uuid

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "splunk_app/splunk_adm/bin"
sys.path[:0] = [str(BIN), str(BIN / "lib")]
from adm_recovery_lib.core import Recovery  # noqa: E402
from adm_recovery_lib.rest import ResponseTooLarge, Rest  # noqa: E402

APP = "/servicesNS/nobody/splunk_adm"
CLIFF, PAGE_SIZE = 200_000, 1000
MAX_ROWS, MAX_BYTES, MAX_SECONDS = 1_000_000, 512 * 1024 * 1024, 900
COLLECTIONS = {
    "adm_ip_identity": ("valid_end",),
    "adm_service_workload": ("last_seen",),
    "adm_service_backends": ("valid_to",),
    "adm_service_routes": ("valid_to",),
    "adm_aci_policy": ("last_seen",),
    "adm_network_client_history": ("received_time", "latest_received_time"),
}


class MaintenanceError(RuntimeError):
    """Fixed reason codes only; never include API payloads or row identities."""


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def number(value):
    try:
        value = (
            float(value) if value is not None and not isinstance(value, bool) else -1
        )
        return value if math.isfinite(value) and value >= 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def flag(value):
    if value in (True, 1, "1", "true"):
        return True
    if value in (False, 0, "0", "false"):
        return False
    return None


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_json(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        os.fchmod(stream.fileno(), 0o600)
        temporary = Path(stream.name)
        try:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
            sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def backup_directory(value):
    directory = Path(os.path.abspath(Path(value).expanduser()))
    if directory == ROOT or ROOT in directory.parents:
        raise MaintenanceError("backup_inside_repository")
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise MaintenanceError("backup_symlink")
    if directory.exists() or not directory.parent.is_dir():
        raise MaintenanceError("backup_requires_new_directory")
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    sync_directory(directory.parent)
    return directory


class RetentionMaintenance:
    def __init__(
        self,
        api,
        *,
        now=time.time,
        clock=time.monotonic,
        max_rows=MAX_ROWS,
        max_bytes=MAX_BYTES,
        max_seconds=MAX_SECONDS,
        page_size=PAGE_SIZE,
        max_deletes=1000,
    ):
        for value, ceiling in (
            (max_rows, MAX_ROWS),
            (max_bytes, MAX_BYTES),
            (max_seconds, MAX_SECONDS),
            (page_size, PAGE_SIZE),
            (max_deletes, 10_000),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise MaintenanceError("invalid_budget")
        self.api, self.now, self.clock = api, now, clock
        self.max_rows, self.max_bytes = max_rows, max_bytes
        self.page_size, self.max_deletes = page_size, max_deletes
        self.deadline = clock() + max_seconds

    def request(self, method, path, data=None, **kwargs):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise MaintenanceError("deadline")
        kwargs["timeout"] = min(30, remaining, kwargs.get("timeout", 30))
        kwargs["max_response_bytes"] = 16 * 1024 * 1024
        return self.api.request(method, path, data=data, **kwargs)

    @staticmethod
    def path(collection, key=None):
        if collection not in COLLECTIONS:
            raise MaintenanceError("unknown_collection")
        path = APP + "/storage/collections/data/" + collection
        return path if key is None else path + "/" + quote(key, safe="")

    @staticmethod
    def expiry(collection, row):
        values = [number(row.get(name)) for name in COLLECTIONS[collection]]
        return None if any(value is None for value in values) else max(values)

    def content(self, path):
        response = self.request("GET", path)
        entries = response.get("entry") if isinstance(response, dict) else None
        if (
            not isinstance(entries, list)
            or len(entries) != 1
            or not isinstance(entries[0], dict)
        ):
            raise MaintenanceError("configuration_incomplete")
        content = entries[0].get("content")
        if not isinstance(content, dict):
            raise MaintenanceError("configuration_incomplete")
        return content, entries[0].get("acl", {})

    def effective_retention(self, requested=None):
        content, _ = self.content(APP + "/configs/conf-macros/adm_identity_retention")
        value = number(content.get("definition"))
        if value is None or value <= 0 or not value.is_integer():
            raise MaintenanceError("invalid_retention")
        if requested is not None and (type(requested) is not int or requested != value):
            raise MaintenanceError("retention_mismatch")
        return int(value)

    def scan(self, collection, *, threshold, sink=None):
        result = dict(
            collection=collection,
            rows_read=0,
            rows_expired=0,
            malformed_expiry=0,
            bytes_read=0,
            oldest_expiry=None,
            complete=False,
            warnings=[],
        )
        last_key = None
        try:
            while True:
                limit = min(self.page_size, self.max_rows - result["rows_read"] + 1)
                params = {
                    "limit": limit,
                    "sort": "_key:1",
                    "query": json.dumps(
                        {"_key": {"$gt": last_key}} if last_key is not None else {}
                    ),
                }
                page = self.request(
                    "GET", self.path(collection) + "?" + urlencode(params)
                )
                if not isinstance(page, list) or len(page) > limit:
                    raise MaintenanceError("invalid_collection_page")
                if not page:
                    result["complete"] = True
                    break
                keys = [
                    row.get("_key") if isinstance(row, dict) else None for row in page
                ]
                if (
                    any(not isinstance(key, str) or not key for key in keys)
                    or keys != sorted(set(keys))
                    or (last_key is not None and keys[0] <= last_key)
                ):
                    raise MaintenanceError("invalid_cursor_progress")
                for row in page:
                    encoded = canonical(row) + b"\n"
                    if (
                        result["rows_read"] >= self.max_rows
                        or result["bytes_read"] + len(encoded) > self.max_bytes
                    ):
                        raise MaintenanceError("scan_ceiling")
                    if sink:
                        sink(encoded)
                    result["rows_read"] += 1
                    result["bytes_read"] += len(encoded)
                    expiry = self.expiry(collection, row)
                    if expiry is None:
                        result["malformed_expiry"] += 1
                    else:
                        oldest = result["oldest_expiry"]
                        result["oldest_expiry"] = (
                            min(oldest, expiry) if oldest is not None else expiry
                        )
                        result["rows_expired"] += int(expiry < threshold)
                last_key = keys[-1]
        except MaintenanceError as exc:
            result["warnings"].append(str(exc))
        except Exception:
            result["warnings"].append("scan_unavailable")
        result["remaining_before_cliff"] = max(0, CLIFF - result["rows_read"])
        if result["rows_read"] >= CLIFF * 0.8:
            result["warnings"].append("spl_reader_capacity")
        if result["malformed_expiry"]:
            result["warnings"].append("malformed_expiry_retained")
        return result

    def status(self, collection, retention_seconds=None):
        period = self.effective_retention(retention_seconds)
        result = self.scan(collection, threshold=self.now() - period)
        return {
            **result,
            "status": "observed",
            "observational": True,
            "retention_seconds": period,
        }

    def listing(self, path):
        entries, expected, count, inventory_bytes = [], None, 1000, 0
        while True:
            try:
                response = self.request(
                    "GET",
                    path + "?" + urlencode({"count": count, "offset": len(entries)}),
                )
            except ResponseTooLarge:
                if count == 1:
                    raise
                count = max(1, count // 2)
                continue
            page = response.get("entry") if isinstance(response, dict) else None
            paging = response.get("paging", {}) if isinstance(response, dict) else {}
            total, offset = number(paging.get("total")), number(paging.get("offset"))
            if (
                not isinstance(page, list)
                or len(page) > count
                or total is None
                or not total.is_integer()
                or total > 10_000
                or offset != len(entries)
                or (expected is not None and total != expected)
            ):
                raise MaintenanceError("inventory_incomplete")
            expected = int(total)
            if len(entries) + len(page) > expected or (
                not page and len(entries) < expected
            ):
                raise MaintenanceError("inventory_incomplete")
            page_bytes = sum(len(canonical(entry)) + 1 for entry in page)
            if inventory_bytes + page_bytes > self.max_bytes:
                raise MaintenanceError("inventory_incomplete")
            entries.extend(page)
            inventory_bytes += page_bytes
            if len(entries) == expected:
                return entries

    def target_identity(self):
        content, _ = self.content("/services/server/info")
        identity = [
            content.get(key) for key in ("guid", "version", "build", "product_type")
        ]
        if any(
            not isinstance(value, str) or not value or len(value) > 128
            for value in identity
        ):
            raise MaintenanceError("target_identity_incomplete")
        return hashlib.sha256(canonical(identity)).hexdigest()

    def quiescent(self, target):
        if self.target_identity() != target:
            raise MaintenanceError("target_changed")
        context, _ = self.content("/services/authentication/current-context")
        if not set(context.get("roles", [])) & {
            "admin",
            "sc_admin",
        } or "admin_all_objects" not in context.get("capabilities", []):
            raise MaintenanceError("administrator_required")
        macro, _ = self.content(APP + "/configs/conf-macros/adm_prune_maintenance")
        if str(macro.get("definition")).strip() != "1":
            raise MaintenanceError("maintenance_disabled")
        names = set()
        for entry in self.listing(APP + "/saved/searches"):
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise MaintenanceError("inventory_incomplete")
            if not entry["name"].startswith("ADM - "):
                continue
            names.add(entry["name"])
            content = entry.get("content", {})
            if (
                flag(content.get("disabled")) is not True
                and flag(content.get("is_scheduled")) is not False
            ):
                raise MaintenanceError("schedules_active")
        if (
            not {
                "ADM - Identity builder",
                "ADM - Service binding",
                "ADM - Conversation rollup",
            }
            <= names
        ):
            raise MaintenanceError("inventory_incomplete")
        for entry in self.listing("/services/search/v2/jobs"):
            content = entry.get("content", {}) if isinstance(entry, dict) else {}
            if flag(content.get("isDone")) is not True or content.get(
                "dispatchState"
            ) not in ("DONE", "FAILED"):
                raise MaintenanceError("jobs_active_or_unknown")

    def prune(
        self,
        collection,
        retention_seconds=None,
        backup_dir=None,
        confirm=False,
        batch_size=100,
    ):
        if not confirm or not backup_dir:
            raise MaintenanceError("confirmation_and_backup_required")
        if type(batch_size) is not int or not 1 <= batch_size <= 1000:
            raise MaintenanceError("invalid_budget")
        self.path(collection)
        period = self.effective_retention(retention_seconds)
        Recovery(self).qualify_deployment()
        target = self.target_identity()
        _, acl = self.content(APP + "/storage/collections/config/" + collection)
        writers = acl.get("perms", {}).get("write", []) if isinstance(acl, dict) else []
        if (
            not isinstance(writers, list)
            or not writers
            or not set(writers) <= {"admin", "sc_admin"}
            or flag(acl.get("can_write")) is not True
        ):
            raise MaintenanceError("collection_write_not_authorized")
        self.quiescent(target)
        directory = backup_directory(backup_dir)
        journal_path, backup = (
            directory / "manifest.json",
            directory / (collection + ".ndjson"),
        )
        cutoff = self.now() - period
        journal = {
            "schemaVersion": 1,
            "journal_id": uuid.uuid4().hex,
            "collection": collection,
            "target_sha256": target,
            "cutoff": cutoff,
            "retention_seconds": period,
            "backup": backup.name,
            "status": "snapshotting",
            "rows_deleted": 0,
            "pending_key": None,
        }
        private_json(journal_path, journal)
        digest = hashlib.sha256()
        with backup.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)

            def sink(data):
                stream.write(data)
                digest.update(data)

            snapshot = self.scan(collection, threshold=cutoff, sink=sink)
            stream.flush()
            os.fsync(stream.fileno())
        journal.update(
            snapshot=snapshot,
            backup_sha256=digest.hexdigest(),
            status="backed_up" if snapshot["complete"] else "incomplete",
        )
        private_json(journal_path, journal)
        result = {
            **snapshot,
            "journal_id": journal["journal_id"],
            "rows_deleted": 0,
            "observational": False,
        }
        if not snapshot["complete"]:
            return {**result, "status": "incomplete"}
        try:
            with backup.open("rb") as stream:
                observed = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    observed.update(block)
                if observed.hexdigest() != journal["backup_sha256"]:
                    raise MaintenanceError("backup_changed")
                identity = backup.stat()
                stream.seek(0)
                for line in stream:
                    row = json.loads(line)
                    expiry = self.expiry(collection, row)
                    if expiry is None or expiry >= cutoff:
                        continue
                    if result["rows_deleted"] >= self.max_deletes:
                        journal["status"] = "partial"
                        break
                    if result["rows_deleted"] % batch_size == 0:
                        current_identity = backup.stat()
                        if (
                            current_identity.st_ino,
                            current_identity.st_size,
                            current_identity.st_mtime_ns,
                        ) != (identity.st_ino, identity.st_size, identity.st_mtime_ns):
                            raise MaintenanceError("backup_changed")
                        self.quiescent(target)
                        if self.effective_retention() != period:
                            raise MaintenanceError("retention_changed")
                    current = self.request("GET", self.path(collection, row["_key"]))
                    if current != row:
                        raise MaintenanceError("row_changed")
                    journal.update(status="deleting", pending_key=row["_key"])
                    private_json(journal_path, journal)
                    try:
                        self.request("DELETE", self.path(collection, row["_key"]))
                    except Exception:
                        journal["status"] = "uncertain"
                        break
                    result["rows_deleted"] += 1
                    journal.update(
                        rows_deleted=result["rows_deleted"], pending_key=None
                    )
                    private_json(journal_path, journal)
                else:
                    journal["status"] = "complete"
        except Exception:
            journal["status"] = (
                "uncertain"
                if journal["pending_key"] is not None or result["rows_deleted"]
                else "stopped"
            )
        try:
            private_json(journal_path, journal)
        except Exception:
            # A durable pending key may be the last surviving record. Never
            # describe a failure after dispatch as a harmless refusal.
            return {
                **result,
                "status": "uncertain",
                "complete": False,
                "warnings": [*result["warnings"], "journal_unavailable"],
            }
        return {
            **result,
            "status": journal["status"],
            "complete": journal["status"] == "complete",
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--management-uri", default="https://localhost:8089")
    parser.add_argument("--ca-file")
    parser.add_argument("--session-key-stdin", action="store_true")
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("status", "prune"):
        command = sub.add_parser(name)
        command.add_argument("collection", choices=sorted(COLLECTIONS))
        command.add_argument("--retention-seconds", type=int)
        command.add_argument("--max-rows", type=int, default=MAX_ROWS)
        command.add_argument("--max-bytes", type=int, default=MAX_BYTES)
        command.add_argument("--max-seconds", type=int, default=MAX_SECONDS)
        if name == "prune":
            command.add_argument("--backup-dir", type=Path, required=True)
            command.add_argument("--confirm-maintenance", action="store_true")
            command.add_argument("--max-deletes", type=int, default=1000)
    args = parser.parse_args(argv)
    try:
        token = (
            sys.stdin.readline().strip()
            if args.session_key_stdin
            else getpass.getpass("Splunk session key: ")
        )
        tool = RetentionMaintenance(
            Rest(token, uri=args.management_uri, ca_file=args.ca_file),
            max_rows=args.max_rows,
            max_bytes=args.max_bytes,
            max_seconds=args.max_seconds,
            max_deletes=getattr(args, "max_deletes", 1000),
        )
        result = (
            tool.status(args.collection, args.retention_seconds)
            if args.operation == "status"
            else tool.prune(
                args.collection,
                args.retention_seconds,
                args.backup_dir,
                args.confirm_maintenance,
            )
        )
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0 if result["complete"] or result["status"] == "partial" else 2
    except MaintenanceError as exc:
        print(json.dumps({"status": "refused", "code": str(exc)}))
        return 2
    except Exception:
        print(json.dumps({"status": "refused", "code": "maintenance_unavailable"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
