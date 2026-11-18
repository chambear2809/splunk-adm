#!/usr/bin/env python3
"""Isolated synthetic same-build case/ledger recovery using installed libraries.

Not an endpoint, platform, production backup, or job-reconciliation test.
"""

import argparse
import datetime as dt
import hashlib
import json
import inspect
import os
from pathlib import Path
import shutil
import stat
import sys

import case_recovery_snapshot as snapshot

NATIVE_ROOT = Path("/opt/splunk/var/atlas-recovery-isolated-20261118")
NATIVE_BIN = Path("/opt/splunk/etc/apps/splunk_adm/bin")
PACKAGE = "0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e"
OWNER = "a" * 32
HASH = "c" * 64
REFERENCE = json.dumps(
    {
        "schema": 1,
        "scope": {
            "service": "checkout",
            "environment": "lab",
            "cluster": "cluster-a",
            "namespace": "shop",
        },
        "windows": [{"start": 100, "end": 200}, {"start": 200, "end": 300}],
    },
    sort_keys=True,
    separators=(",", ":"),
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fixture_graph(start, end):
    return [
        {
            "row_type": "node",
            "id": "service:cluster-a/shop/checkout/lab",
            "label": "checkout",
            "kind": "service",
            "cluster": "cluster-a",
            "namespace": "shop",
            "attr_environment": "lab",
        },
        {
            "row_type": "meta",
            "window_start": str(start),
            "window_end": str(end),
            "generated_at": str(end),
            "warnings": ["partial synthetic"],
        },
    ]


def run_rehearsal(root, runtime_bin, *, runtime_label):
    """Create a brand-new private fixture tree and retain all synthetic artifacts."""
    previous_mask = os.umask(0o077)
    try:
        return _run_rehearsal(root, runtime_bin, runtime_label=runtime_label)
    finally:
        os.umask(previous_mask)


def _run_rehearsal(root, runtime_bin, *, runtime_label):
    root, runtime_bin = Path(root), Path(runtime_bin)
    require(root.is_absolute() and runtime_bin.is_absolute(), "absolute paths required")
    # Never adopt, overwrite or remove an existing tree.
    root.mkdir(mode=0o700)
    info = root.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "unsafe root",
    )
    parent_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    sys.path.insert(0, str(runtime_bin))
    from adm_cases_lib.source import ComparisonSource
    from adm_cases_lib.store import CaseStore, Forbidden
    from adm_cases_lib.job_ledger import JobLedger, QuotaExceeded

    runtime_hashes = {}
    for cls, filename in (
        (ComparisonSource, "source.py"),
        (CaseStore, "store.py"),
        (JobLedger, "job_ledger.py"),
    ):
        path = runtime_bin / "adm_cases_lib" / filename
        require(
            Path(inspect.getfile(cls)).resolve() == path.resolve(),
            "unexpected imported runtime",
        )
        runtime_hashes[filename] = hashlib.sha256(path.read_bytes()).hexdigest()

    for name in ("source", "schemas"):
        (root / name).mkdir(mode=0o700)
    denied = set()
    config = ["synthetic-config-v1"]
    calls = []

    def run(principal, query, start, end):
        calls.append((principal, query, start, end))
        if principal in denied:
            raise PermissionError("synthetic revoked")
        return fixture_graph(start, end)

    source = ComparisonSource(
        run, lambda: config[0], lambda: dt.datetime.fromtimestamp(400, dt.timezone.utc)
    )

    def store(directory):
        return CaseStore(
            directory / "cases.sqlite",
            lambda *_: True,
            capture_resolver=source.resolve,
            source_entitlement=source.entitled,
        )

    # Derive schemas independently from fresh installed-runtime instances.
    store(root / "schemas")
    JobLedger(root / "schemas/capture_jobs.sqlite")
    schemas = {
        name: snapshot.schema_descriptor(root / "schemas" / name)
        for name in snapshot.ALLOWLIST
    }
    case = store(root / "source")
    case_id = case.create(
        "alice",
        "create",
        {
            "schema_version": 1,
            "title": "Synthetic recovery",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        },
    )["id"]
    note = case.append(
        "alice", "note", case_id, 1, "entry", {"type": "note", "text": "original"}
    )["entries"][0]
    case.append(
        "alice",
        "revise",
        case_id,
        2,
        "entry",
        {"type": "note", "text": "revised", "supersedes_entry_id": note["id"]},
    )
    saved = case.append_capture("alice", "capture", case_id, 3, REFERENCE)
    capture_id = saved["capture_ids"][0]
    case.attach_capture_reference("alice", "attach", case_id, 4, note["id"], capture_id)
    case.share("alice", "share", case_id, 5, "bob", True)
    before = case.get("bob", case_id, capture_id=capture_id)
    audit = case.audit("alice", case_id)
    require(
        len(before["captures"]) == 1 and len(before["entries"]) == 2,
        "source fixture not saved",
    )
    require(len(calls) >= 4, "source resolution was not exercised")

    ledger = JobLedger(root / "source/capture_jobs.sqlite", clock=lambda: 100)
    ids = ["adm-capture-" + f"{i:032x}" for i in range(3)]
    for ident in ids:
        ledger.reserve("alice", ident, HASH, 1, 301, OWNER, transport_hash=HASH)
    ledger.transition("alice", ids[0], OWNER, "creation_unknown", expected_revision=1)
    ledger.bind_created("alice", ids[1], OWNER, "1700000000.1", expected_revision=1)
    ledger.transition("alice", ids[1], OWNER, "cleanup_unknown", expected_revision=2)
    outstanding = ledger.outstanding("alice")
    require(
        {item["state"] for item in outstanding}
        == {"creating", "creation_unknown", "cleanup_unknown"},
        "ledger fixtures missing",
    )
    provenance = {
        "scope": "isolated-synthetic-libraries",
        "runtime": runtime_label,
        "package_sha256_claim": PACKAGE,
        "runtime_hashes": runtime_hashes,
    }
    manifest_sha = snapshot.create_snapshot(
        root / "source",
        root / "bundle",
        expected_schemas=schemas,
        provenance=provenance,
    )
    kwargs = {
        "expected_manifest_sha256": manifest_sha,
        "expected_schemas": schemas,
        "expected_provenance": provenance,
    }
    sealed = snapshot.validate_snapshot(root / "bundle", **kwargs)

    occupied = root / "occupied"
    occupied.mkdir(mode=0o700)
    sentinel = occupied / "sentinel"
    sentinel.write_bytes(b"preserve")
    try:
        snapshot.prepare_restore(root / "bundle", occupied, **kwargs)
        raise AssertionError("occupied target accepted")
    except snapshot.SnapshotError:
        require(sentinel.read_bytes() == b"preserve", "occupied target changed")

    shutil.copytree(root / "bundle", root / "corrupt")
    damaged = root / "corrupt/cases.sqlite"
    with damaged.open("r+b") as f:
        byte = f.read(1)
        f.seek(0)
        f.write(bytes([byte[0] ^ 1]))
    try:
        snapshot.prepare_restore(root / "corrupt", root / "corrupt-target", **kwargs)
        raise AssertionError("corrupt bundle accepted")
    except snapshot.SnapshotError:
        require(not (root / "corrupt-target").exists(), "corrupt target created")

    # Force failure while copying the second DB, after the first was copied.
    original_copy = snapshot.shutil.copyfileobj
    count = [0]

    def fail_second(inp, out, *args, **kwargs):
        count[0] += 1
        if count[0] == 2:
            raise OSError("injected partial copy")
        return original_copy(inp, out, *args, **kwargs)

    snapshot.shutil.copyfileobj = fail_second
    try:
        try:
            snapshot.prepare_restore(root / "bundle", root / "partial-target", **kwargs)
            raise AssertionError("injected failure did not stop restore")
        except OSError:
            require(
                count[0] == 2 and not (root / "partial-target").exists(),
                "partial target retained",
            )
    finally:
        snapshot.shutil.copyfileobj = original_copy
    require(
        snapshot.validate_snapshot(root / "bundle", **kwargs) == sealed,
        "bundle changed after failed restore",
    )
    snapshot.prepare_restore(root / "bundle", root / "restored", **kwargs)
    for name in snapshot.ALLOWLIST:
        require(
            snapshot.inspect_database(root / "source" / name, schemas[name])
            == snapshot.inspect_database(root / "restored" / name, schemas[name]),
            "logical database mismatch",
        )
    restored = store(root / "restored")
    restored_ledger = JobLedger(
        root / "restored/capture_jobs.sqlite", clock=lambda: 100000
    )
    require(
        restored_ledger.outstanding("alice") == outstanding, "unresolved jobs changed"
    )
    try:
        restored_ledger.reserve(
            "bob", "adm-capture-" + "f" * 32, HASH, 1, 301, OWNER, transport_hash=HASH
        )
        raise AssertionError("unresolved quota released")
    except QuotaExceeded:
        pass
    require(restored.audit("alice", case_id) == audit, "audit changed")
    require(
        restored.get("bob", case_id, capture_id=capture_id) == before,
        "case or ACL changed",
    )
    try:
        restored.get("outsider", case_id)
        raise AssertionError("outsider admitted")
    except Forbidden:
        pass
    retried = restored.append_capture("alice", "capture", case_id, 3, REFERENCE)
    require(
        retried["capture_ids"] == saved["capture_ids"]
        and retried["revision"] == saved["revision"],
        "retry changed identity",
    )
    denied.update(("alice", "bob"))
    for result in (
        restored.get("bob", case_id, capture_id=capture_id),
        restored.export("bob", case_id, capture_id=capture_id),
        restored.append_capture("alice", "capture", case_id, 3, REFERENCE),
    ):
        require(
            not result["captures"]
            and result["redactions"]["captures"] == 1
            and len(result["entries"]) == 2,
            "revocation failed to redact",
        )
    denied.clear()
    config[0] = "synthetic-config-v2"
    for result in (
        restored.get("bob", case_id, capture_id=capture_id),
        restored.export("bob", case_id, capture_id=capture_id),
        restored.append_capture("alice", "capture", case_id, 3, REFERENCE),
    ):
        require(
            not result["captures"]
            and result["redactions"]["captures"] == 1
            and len(result["entries"]) == 2,
            "config change did not withhold",
        )
    config[0] = "synthetic-config-v1"
    require(
        len(restored.export("bob", case_id, capture_id=capture_id)["captures"]) == 1,
        "source not restored",
    )
    receipt = {
        "scope": provenance["scope"],
        "runtime": runtime_label,
        "manifest_sha256": manifest_sha,
        "schemas": schemas,
        "runtime_hashes": runtime_hashes,
        "checks": {
            "logical_tables_equal": True,
            "source_capture_rechecked": True,
            "notes_revisions_acl_audit_retry": True,
            "revocation_and_config_redacted": True,
            "unresolved_slots_retained": True,
            "occupied_rejected": True,
            "corrupt_rejected": True,
            "partial_restore_removed": True,
        },
        "source_search_calls": len(calls),
        "retained_private_tree": True,
    }
    receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(
        root / "receipt.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "wb") as f:
        f.write(receipt_bytes)
        f.flush()
        os.fsync(f.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {
        "status": "passed",
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "manifest_sha256": manifest_sha,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed", action="store_true", required=True)
    parser.parse_args()
    try:
        result = run_rehearsal(
            NATIVE_ROOT, NATIVE_BIN, runtime_label="installed-runtime-unattested"
        )
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed_or_uncertain", "error_type": type(exc).__name__}
            )
        )
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
