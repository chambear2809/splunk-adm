"""Test-only adapters for a future isolated native restore rehearsal.

Callers must independently verify task-owned instance identities, transport,
process retirement and quiescence. These helpers do not authorize a platform
operation and cannot certify a full-platform backup or restore.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

COLLECTIONS = (
    "adm_deployment_settings",
    "adm_multicast_profiles",
    "adm_protocol_profiles",
    "adm_observer_scope",
    "adm_network_source_scope",
    "adm_network_client_history",
    "adm_cilium_cluster_settings",
    "adm_ip_identity",
    "adm_service_workload",
    "adm_interfaces",
    "adm_service_backends",
    "adm_service_routes",
    "adm_aci_policy",
    "adm_recovery_state",
    "adm_recovery_audit",
    "adm_app_catalog",
    "adm_saved_views",
    "adm_business_ownership",
    "adm_change_assertions",
    "adm_app_catalog_v2",
)
PAGE_SIZE = 500
MAX_ROWS = 100_000
MAX_BYTES = 64 * 1024 * 1024
KV_ARCHIVE = "atlas_platform_fixture"


class RestoreError(ValueError):
    """The task-only evidence or operation is unsafe or incomplete."""


def require(value, reason):
    if not value:
        raise RestoreError(reason)


def canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise RestoreError("non-JSON collection row") from exc


def discover_collections(entries):
    """Require exact installed app collection definitions, including empty ones."""
    require(isinstance(entries, list), "collection discovery unavailable")
    names = [item.get("name") for item in entries if isinstance(item, dict)]
    require(
        len(names) == len(entries) and all(isinstance(x, str) for x in names),
        "invalid collection discovery",
    )
    require(
        len(set(names)) == len(names) and set(names) == set(COLLECTIONS),
        "installed collection set differs",
    )
    return tuple(sorted(names))


def discover_pages(fetch):
    """Consume all installed definition pages with stable bounded totals."""
    entries = []
    total = None
    while True:
        response = fetch(len(entries), PAGE_SIZE)
        require(
            isinstance(response, dict)
            and isinstance(response.get("paging"), dict)
            and isinstance(response.get("entry"), list),
            "collection page unavailable",
        )
        expected = response["paging"].get("total")
        require(
            type(expected) is int
            and 0 <= expected <= 1000
            and (total is None or total == expected),
            "collection total changed",
        )
        total = expected
        page = response["entry"]
        require(
            len(page) <= PAGE_SIZE and len(entries) + len(page) <= total,
            "invalid collection page size",
        )
        entries.extend(page)
        if len(entries) == total:
            return discover_collections(entries)
        require(bool(page), "collection paging stalled")


def read_collection(fetch, name):
    """Read strictly advancing keyset pages, including a final empty page."""
    require(name in COLLECTIONS, "unapproved collection")
    last = ""
    rows = []
    total_bytes = 0
    while True:
        page = fetch(name, last, PAGE_SIZE)
        require(isinstance(page, list) and len(page) <= PAGE_SIZE, "invalid KV page")
        if not page:
            return rows
        keys = [item.get("_key") if isinstance(item, dict) else None for item in page]
        require(
            all(isinstance(key, str) and key and key > last for key in keys),
            "KV page did not advance",
        )
        require(keys == sorted(set(keys)), "KV keys duplicate or out of order")
        for item in page:
            # Preserve every field. A field is not dropped just to make comparison pass.
            encoded = canonical(item)
            total_bytes += len(encoded)
            require(total_bytes <= MAX_BYTES, "collection bytes exceed bound")
            rows.append(json.loads(encoded))
            require(len(rows) <= MAX_ROWS, "collection rows exceed bound")
        last = keys[-1]


def read_all(fetch):
    return {name: read_collection(fetch, name) for name in COLLECTIONS}


def stable_kv_snapshot(fetch, writer_barrier):
    """Capture two identical complete views while the caller verifies a barrier.

    A successful barrier callback and two equal views are not independent proof
    that platform-wide writers are quiesced; the orchestrator must establish it.
    """
    require(writer_barrier() is True, "writer barrier unavailable")
    before = read_all(fetch)
    require(writer_barrier() is True, "writer barrier changed")
    after = read_all(fetch)
    require(
        writer_barrier() is True and before == after, "KV data changed during capture"
    )
    payload = canonical(before)
    require(len(payload) <= MAX_BYTES, "aggregate KV snapshot exceeds bound")
    return {"rows": before, "sha256": hashlib.sha256(payload).hexdigest()}


def native_dispatches_clear(events):
    """Check one task journal for complete, ordered native KV operations.

    Only the fixed one-backup/one-restore fixture is supported. The journal
    reader and durability must be independently enforced by the caller.
    """
    if not isinstance(events, list) or not all(
        isinstance(event, dict) for event in events
    ):
        return False
    for event in events:
        state = event.get("state")
        if (
            isinstance(state, str)
            and state.startswith(("kv_backup_", "kv_restore_", "kv_archive_transfer_"))
            and state
            not in {
                "kv_backup_intent",
                "kv_backup_ack",
                "kv_backup_verified",
                "kv_restore_intent",
                "kv_restore_ack",
                "kv_restore_verified",
                "kv_archive_transfer_intent",
                "kv_archive_transfer_verified",
            }
        ):
            return False
    backup = ["kv_backup_intent", "kv_backup_ack", "kv_backup_verified"]
    restore = ["kv_restore_intent", "kv_restore_ack", "kv_restore_verified"]
    transfer = ["kv_archive_transfer_intent", "kv_archive_transfer_verified"]
    relevant = [
        event
        for event in events
        if event.get("state") in set(backup + transfer + restore)
    ]
    states = [event["state"] for event in relevant]
    if states not in (
        [],
        backup,
        transfer,
        restore,
        backup + transfer,
        backup + restore,
        transfer + restore,
        backup + transfer + restore,
    ):
        return False
    for event in relevant:
        state = event["state"]
        if state.startswith("kv_archive_transfer_"):
            expected_fields = (
                {"state", "sha256"}
                if state.endswith("_intent")
                else {"state", "sha256", "size"}
            )
            value = event.get("sha256")
            if (
                set(event) != expected_fields
                or not isinstance(value, str)
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                return False
            if state.endswith("_verified") and not _archive_valid(
                {"sha256": value, "size": event["size"]}
            ):
                return False
            continue
        if event.get("archive") != KV_ARCHIVE:
            return False
        if state == "kv_backup_verified":
            if set(event) != {
                "state",
                "archive",
                "sha256",
                "size",
            } or not _archive_valid({"sha256": event["sha256"], "size": event["size"]}):
                return False
        elif state == "kv_restore_verified":
            value = event.get("sha256")
            if (
                set(event) != {"state", "archive", "sha256"}
                or not isinstance(value, str)
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                return False
        elif set(event) != {"state", "archive"}:
            return False
    if transfer:
        transfer_events = [event for event in relevant if event["state"] in transfer]
        if transfer_events and (
            transfer_events[0]["sha256"] != transfer_events[1]["sha256"]
            or (
                backup[2] in states
                and (
                    transfer_events[0]["sha256"]
                    != next(
                        event["sha256"]
                        for event in relevant
                        if event["state"] == backup[2]
                    )
                    or transfer_events[1]["size"]
                    != next(
                        event["size"]
                        for event in relevant
                        if event["state"] == backup[2]
                    )
                )
            )
        ):
            return False
    return True


def _ready(status):
    require(
        isinstance(status, dict) and status.get("type") == "Pdl",
        "unqualified KV engine",
    )
    require(
        status.get("status") == "ready"
        and status.get("backupRestoreStatus") == "ready",
        "KV not ready",
    )


def _archive_valid(archive):
    return (
        isinstance(archive, dict)
        and set(archive) == {"sha256", "size"}
        and type(archive["size"]) is int
        and 0 < archive["size"] <= MAX_BYTES
        and isinstance(archive["sha256"], str)
        and len(archive["sha256"]) == 64
        and all(c in "0123456789abcdef" for c in archive["sha256"])
    )


def _snapshot_valid(snapshot):
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != {"rows", "sha256"}
        or not isinstance(snapshot["rows"], dict)
        or set(snapshot["rows"]) != set(COLLECTIONS)
    ):
        return False
    for rows in snapshot["rows"].values():
        if not isinstance(rows, list) or len(rows) > MAX_ROWS:
            return False
        keys = [row.get("_key") if isinstance(row, dict) else None for row in rows]
        if not all(isinstance(k, str) and k for k in keys) or keys != sorted(set(keys)):
            return False
    data = canonical(snapshot["rows"])
    return (
        len(data) <= MAX_BYTES
        and snapshot["sha256"] == hashlib.sha256(data).hexdigest()
    )


def pdl_parallel_backup(
    *, cli, status, writer_barrier, fetch, archive_info, journal, dispatch_clear
):
    """Execute the documented parallel backup on a caller-owned native instance.

    `cli(argv)` is a prebound, task-owned Splunk CLI adapter; `journal` must
    durably sync before returning. The native archive is a whole-KV backup,
    not an app-only export. On error or unknown command outcome leave the
    archive and operation unresolved for explicit reconciliation.
    """
    require(dispatch_clear() is True, "prior native dispatch unresolved")
    _ready(status())
    require(archive_info() is None, "backup archive already occupied")
    snapshot = stable_kv_snapshot(fetch, writer_barrier)
    journal({"state": "kv_backup_intent", "archive": KV_ARCHIVE})
    cli(
        ["backup", "kvstore", "-archiveName", KV_ARCHIVE, "-backupParallelJobs", "true"]
    )
    journal({"state": "kv_backup_ack", "archive": KV_ARCHIVE})
    _ready(status())
    require(writer_barrier() is True, "writer barrier changed after backup")
    after = stable_kv_snapshot(fetch, writer_barrier)
    require(after == snapshot, "KV changed across native backup")
    archive = archive_info()
    require(_archive_valid(archive), "native backup archive unverified")
    journal(
        {
            "state": "kv_backup_verified",
            "archive": KV_ARCHIVE,
            "sha256": archive["sha256"],
            "size": archive["size"],
        }
    )
    return {
        "engine": "Pdl",
        "mode": "parallel",
        "point_in_time": False,
        "snapshot": snapshot,
        "archive": archive,
    }


def pdl_parallel_restore(
    *,
    cli,
    status,
    writer_barrier,
    fetch,
    expected_snapshot,
    archive_info,
    expected_archive,
    journal,
    fresh_instance_verified,
    dispatch_clear,
):
    """Restore whole-KV backup only to an independently proven fresh fixture.

    This native command can overwrite KV contents beyond the 19 app collections.
    It is never safe on a shared or live installation. Callers must independently
    prove target identity, complete prior-state absence and exclusive ownership.
    """
    require(
        _snapshot_valid(expected_snapshot) and _archive_valid(expected_archive),
        "backup evidence differs",
    )
    expected_snapshot = json.loads(canonical(expected_snapshot))
    expected_archive = json.loads(canonical(expected_archive))
    require(dispatch_clear() is True, "prior native dispatch unresolved")
    require(
        fresh_instance_verified() is True,
        "fresh destination not independently verified",
    )
    _ready(status())
    empty = stable_kv_snapshot(fetch, writer_barrier)
    require(
        all(not rows for rows in empty["rows"].values()),
        "target app collections occupied",
    )
    require(
        _archive_valid(expected_archive)
        and archive_info() == expected_archive
        and _snapshot_valid(expected_snapshot),
        "backup evidence differs",
    )
    journal({"state": "kv_restore_intent", "archive": KV_ARCHIVE})
    cli(
        [
            "restore",
            "kvstore",
            "-archiveName",
            KV_ARCHIVE + ".tar.gz",
            "-restoreParallelJobs",
            "true",
        ]
    )
    journal({"state": "kv_restore_ack", "archive": KV_ARCHIVE})
    _ready(status())
    actual = stable_kv_snapshot(fetch, writer_barrier)
    require(actual == expected_snapshot, "restored KV rows differ")
    journal(
        {
            "state": "kv_restore_verified",
            "archive": KV_ARCHIVE,
            "sha256": actual["sha256"],
        }
    )
    return actual


def source_home_rebase(value, source_home, destination_home):
    """Translate only an exact old-home prefix; reject unrelated absolute paths."""
    source, destination = Path(source_home), Path(destination_home)
    require(
        source.is_absolute()
        and destination.is_absolute()
        and source != destination
        and source not in destination.parents
        and destination not in source.parents
        and ".." not in source.parts
        and ".." not in destination.parts,
        "invalid home mapping",
    )
    require(isinstance(value, str) and value.startswith("/"), "path must be absolute")
    path = Path(value)
    require(
        ".." not in path.parts and (path == source or source in path.parents),
        "path not owned by source home",
    )
    return str(destination / path.relative_to(source))


# Fixed task-only indexes; no caller-selected production index is accepted.
FIXTURE_INDEXES = (
    "atlas_restore_identity",
    "atlas_restore_spans",
    "atlas_restore_summary",
)
MAX_BUCKET_FILES = 20_000
MAX_BUCKET_DIRS = 20_000
MAX_BUCKET_BYTES = 2 * 1024 * 1024 * 1024


def _private_directory(path):
    import os
    import stat

    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "invalid fixture directory")
    for current in (path, *path.parents):
        require(stat.S_ISDIR(current.lstat().st_mode), "linked fixture directory")
    info = path.lstat()
    require(
        info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
        "fixture directory not private",
    )
    return path


def _walk_error(_error):
    raise RestoreError("bucket enumeration failed")


def _bucket_tree(root):
    """Read an exact stopped index export; reject hot buckets and unknown paths."""
    import os
    import stat

    root = _private_directory(root)
    require(
        {x.name for x in root.iterdir()} == set(FIXTURE_INDEXES),
        "fixture index set differs",
    )
    files = {}
    total = 0
    directory_count = 0

    for index in FIXTURE_INDEXES:
        index_root = root / index
        info = index_root.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and not stat.S_IMODE(info.st_mode) & 0o022,
            "unsafe index directory",
        )
        # The exporter supplies rolled warm/cold buckets, not index internals.
        buckets = list(index_root.iterdir())
        require(bool(buckets), "fixture index has no cold buckets")
        for bucket in buckets:
            require(
                bucket.name.startswith("db_") and len(bucket.name) <= 255,
                "hot or unrecognized bucket",
            )
            bucket_info = bucket.lstat()
            require(
                stat.S_ISDIR(bucket_info.st_mode)
                and bucket_info.st_uid == os.getuid()
                and not stat.S_IMODE(bucket_info.st_mode) & 0o022,
                "unsafe bucket root",
            )
            for current, dirs, names in os.walk(
                bucket, followlinks=False, onerror=_walk_error
            ):
                directory_count += 1
                require(
                    directory_count <= MAX_BUCKET_DIRS and bool(dirs or names),
                    "empty or excessive bucket directories",
                )
                directory = Path(current)
                meta = directory.lstat()
                require(
                    stat.S_ISDIR(meta.st_mode)
                    and meta.st_uid == os.getuid()
                    and not stat.S_IMODE(meta.st_mode) & 0o022,
                    "unsafe bucket directory",
                )
                for name in dirs:
                    meta = (directory / name).lstat()
                    require(
                        stat.S_ISDIR(meta.st_mode)
                        and meta.st_uid == os.getuid()
                        and not stat.S_IMODE(meta.st_mode) & 0o022,
                        "unsafe nested directory",
                    )
                for name in names:
                    path = directory / name
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        before = os.fstat(fd)
                        entry = path.lstat()
                        require(
                            stat.S_ISREG(before.st_mode)
                            and before.st_uid == os.getuid()
                            and before.st_nlink == 1
                            and not stat.S_IMODE(before.st_mode) & 0o022
                            and (before.st_dev, before.st_ino)
                            == (entry.st_dev, entry.st_ino),
                            "unsafe bucket file",
                        )
                        total += before.st_size
                        require(
                            total <= MAX_BUCKET_BYTES and len(files) < MAX_BUCKET_FILES,
                            "fixture bucket bound exceeded",
                        )
                        digest = hashlib.sha256()
                        size = 0
                        while True:
                            chunk = os.read(fd, 1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            require(size <= before.st_size, "bucket changed")
                            digest.update(chunk)
                        after = os.fstat(fd)
                        require(
                            size == before.st_size
                            and (
                                before.st_dev,
                                before.st_ino,
                                before.st_size,
                                before.st_mtime_ns,
                                before.st_ctime_ns,
                            )
                            == (
                                after.st_dev,
                                after.st_ino,
                                after.st_size,
                                after.st_mtime_ns,
                                after.st_ctime_ns,
                            ),
                            "bucket changed during read",
                        )
                        files[path.relative_to(root).as_posix()] = {
                            "sha256": digest.hexdigest(),
                            "size": size,
                            "mtime_ns": before.st_mtime_ns,
                        }
                    finally:
                        os.close(fd)
    return files


def capture_cold_buckets(source, target, *, processes_stopped, journal):
    """Copy only three task fixture index exports to an absent private target.

    The caller must independently prove the source service and its indexers are
    stopped and that hot buckets were rolled. Partial target contents are kept.
    """
    import os

    source = _private_directory(source)
    target = Path(target)
    require(
        target.is_absolute()
        and ".." not in target.parts
        and source not in target.parents
        and target != source,
        "invalid bucket destination",
    )
    _private_directory(target.parent)
    require(processes_stopped() is True, "source process retirement unavailable")
    inventory = _bucket_tree(source)
    require(processes_stopped() is True, "source restarted during inventory")
    journal({"state": "bucket_copy_intent", "files": len(inventory)})
    target.mkdir(mode=0o700)
    parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    for relative, expected in sorted(inventory.items()):
        src = source / relative
        dst = target / relative
        dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        srcfd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        dstfd = os.open(
            dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            digest = hashlib.sha256()
            count = 0
            while True:
                chunk = os.read(srcfd, 1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= expected["size"], "bucket changed during copy")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(dstfd, view)
                    require(written > 0, "bucket write failed")
                    view = view[written:]
            require(
                count == expected["size"] and digest.hexdigest() == expected["sha256"],
                "bucket changed during copy",
            )
            os.utime(dstfd, ns=(expected["mtime_ns"], expected["mtime_ns"]))
            os.fsync(dstfd)
        finally:
            os.close(srcfd)
            os.close(dstfd)
    for current, _, _ in os.walk(
        target,
        topdown=False,
        followlinks=False,
        onerror=_walk_error,
    ):
        fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    require(
        processes_stopped() is True
        and _bucket_tree(source) == inventory
        and _bucket_tree(target) == inventory,
        "bucket capture differs",
    )
    journal(
        {
            "state": "bucket_copy_verified",
            "files": len(inventory),
            "sha256": hashlib.sha256(canonical(inventory)).hexdigest(),
        }
    )
    return inventory


def snapshot_fixture_databases(
    source,
    target,
    *,
    expected_schemas,
    processes_stopped,
    unsettled_dispatches,
    journal,
):
    """Back up all four cold SQLite fixtures without clearing ledger records.

    The accepted quiescence receipt is supplied by an independently verified
    task-only orchestrator. Known uncertain ledger rows are copied as data;
    only unresolved *dispatch outcomes* prevent creating a recovery snapshot.
    """
    from tools import qualify_platform_recovery

    require(
        type(unsettled_dispatches) is int and unsettled_dispatches == 0,
        "dispatch outcome unresolved",
    )
    require(processes_stopped() is True, "source process retirement unavailable")
    journal({"state": "sqlite_backup_intent"})
    evidence = qualify_platform_recovery.snapshot_cold_databases(
        source, target, expected_schemas
    )
    require(processes_stopped() is True, "source restarted during snapshot")
    journal(
        {
            "state": "sqlite_backup_verified",
            "sha256": hashlib.sha256(canonical(evidence)).hexdigest(),
        }
    )
    return evidence


# Root-only custody locations for the proposed future task fixture. They are not
# under the existing Splunk home and cannot be selected from an HTTP request.
CUSTODY_STATE = Path("/var/lib/private/atlas-platform-recovery-20261118")
CUSTODY_ROOT = Path("/var/lib/atlas-platform-recovery-outer-20261118")
CUSTODY_DESTINATIONS = {"home": "sealed-source", "tls": "sealed-tls"}
CUSTODY_PATHS = {"home": CUSTODY_STATE / "source/splunk", "tls": CUSTODY_STATE / "tls"}
CUSTODY_OWNER = 0
MAX_CUSTODY_FILES = 100_000
MAX_CUSTODY_BYTES = 16 * 1024 * 1024 * 1024
OFFICIAL_LINKS_SHA256 = (
    "da6b3b757fb1c06d78bb672ef9919338ac50d5df216c2d7f4e21a50174fd755e"
)
OFFICIAL_LINKS_COUNT = 42


def _open_directory_chain(path):
    """Open every absolute directory component without following links."""
    import os
    import stat

    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "invalid custody path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            require(stat.S_ISDIR(os.fstat(child).st_mode), "unsafe custody ancestor")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_descendant(parent_fd, components):
    import os

    fd = os.dup(parent_fd)
    try:
        for component in components:
            require(
                isinstance(component, str)
                and component not in ("", ".", "..")
                and "/" not in component,
                "invalid custody component",
            )
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _same_directory_path(path, pinned_fd):
    import os

    current = _open_directory_chain(path)
    try:
        first, second = os.fstat(current), os.fstat(pinned_fd)
        return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
    finally:
        os.close(current)


def _rename_noreplace(source_fd, source_name, destination_fd, destination_name):
    """Atomically rename pinned directory entries without replacement."""
    import ctypes
    import os

    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    require(function is not None, "atomic no-replace rename unavailable")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if (
        function(
            source_fd,
            os.fsencode(source_name),
            destination_fd,
            os.fsencode(destination_name),
            1,
        )
        != 0
    ):
        raise OSError(ctypes.get_errno(), "atomic no-replace rename failed")


def _validated_official_links(value):
    """Validate the independently sealed link list from the pinned archive."""
    from pathlib import PurePosixPath

    require(
        isinstance(value, dict)
        and len(value) == OFFICIAL_LINKS_COUNT
        and hashlib.sha256(canonical(value)).hexdigest() == OFFICIAL_LINKS_SHA256,
        "official link manifest differs",
    )
    for name, target in value.items():
        require(
            isinstance(name, str)
            and isinstance(target, str)
            and name
            and target
            and "\\" not in name
            and "\\" not in target,
            "invalid official link",
        )
        link, reference = PurePosixPath(name), PurePosixPath(target)
        require(
            not link.is_absolute()
            and ".." not in link.parts
            and not reference.is_absolute(),
            "invalid official link path",
        )
        stack = list(link.parent.parts)
        for part in reference.parts:
            if part == "..":
                require(bool(stack), "official link escapes home")
                stack.pop()
            elif part not in ("", "."):
                stack.append(part)
        require(bool(stack), "official link resolves outside home")
    return value


def _custody_inventory(root_fd, permitted_uid, allowed_links):
    """Inventory a pinned directory tree through no-follow directory FDs."""
    import os
    import stat

    result = {}
    seen_links = {}
    count = 0
    total = 0

    def walk(fd, relative, depth):
        nonlocal count, total
        require(depth <= 64, "custody nesting too deep")
        info = os.fstat(fd)
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == permitted_uid,
            "unsafe custody directory",
        )
        result[relative] = {
            "kind": "directory",
            "device": info.st_dev,
            "inode": info.st_ino,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
            "mtime_ns": info.st_mtime_ns,
        }
        count += 1
        require(count <= MAX_CUSTODY_FILES, "custody entry bound exceeded")
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                require(
                    len(entries) + count < MAX_CUSTODY_FILES,
                    "custody entry bound exceeded",
                )
                entries.append(entry)
        for entry in entries:
            name = entry.name
            path = name if relative == "." else relative + "/" + name
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(before.st_uid == permitted_uid, "unsafe custody owner")
            if stat.S_ISLNK(before.st_mode):
                require(
                    path in allowed_links and before.st_nlink == 1,
                    "unapproved custody link",
                )
                target = os.readlink(name, dir_fd=fd)
                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(
                    target == allowed_links[path]
                    and after.st_nlink == 1
                    and (
                        before.st_dev,
                        before.st_ino,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    )
                    == (
                        after.st_dev,
                        after.st_ino,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ),
                    "custody link changed",
                )
                seen_links[path] = target
                result[path] = {
                    "kind": "symlink",
                    "device": before.st_dev,
                    "inode": before.st_ino,
                    "uid": before.st_uid,
                    "gid": before.st_gid,
                    "mode": stat.S_IMODE(before.st_mode),
                    "mtime_ns": before.st_mtime_ns,
                    "target": target,
                }
                count += 1
                require(count <= MAX_CUSTODY_FILES, "custody entry bound exceeded")
            elif stat.S_ISDIR(before.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                try:
                    opened = os.fstat(child)
                    require(
                        (before.st_dev, before.st_ino)
                        == (opened.st_dev, opened.st_ino),
                        "custody directory changed",
                    )
                    walk(child, path, depth + 1)
                    after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(
                        (opened.st_dev, opened.st_ino) == (after.st_dev, after.st_ino),
                        "custody directory replaced",
                    )
                finally:
                    os.close(child)
            else:
                require(
                    stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    "linked or unsafe custody file",
                )
                child = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
                )
                try:
                    opened = os.fstat(child)
                    require(
                        (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)
                        and opened.st_nlink == 1,
                        "custody file replaced",
                    )
                    count += 1
                    total += opened.st_size
                    require(
                        count <= MAX_CUSTODY_FILES and total <= MAX_CUSTODY_BYTES,
                        "custody bound exceeded",
                    )
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        data = os.read(child, 1024 * 1024)
                        if not data:
                            break
                        size += len(data)
                        require(size <= opened.st_size, "custody file changed")
                        digest.update(data)
                    after = os.fstat(child)
                    entry_after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    require(
                        size == opened.st_size
                        and (
                            opened.st_dev,
                            opened.st_ino,
                            opened.st_size,
                            opened.st_mtime_ns,
                            opened.st_ctime_ns,
                        )
                        == (
                            after.st_dev,
                            after.st_ino,
                            after.st_size,
                            after.st_mtime_ns,
                            after.st_ctime_ns,
                        )
                        and (after.st_dev, after.st_ino)
                        == (entry_after.st_dev, entry_after.st_ino)
                        and after.st_nlink == entry_after.st_nlink == 1,
                        "custody file changed",
                    )
                    result[path] = {
                        "kind": "file",
                        "device": opened.st_dev,
                        "inode": opened.st_ino,
                        "uid": opened.st_uid,
                        "gid": opened.st_gid,
                        "mode": stat.S_IMODE(opened.st_mode),
                        "mtime_ns": opened.st_mtime_ns,
                        "size": size,
                        "sha256": digest.hexdigest(),
                    }
                finally:
                    os.close(child)
        final_directory = os.fstat(fd)
        require(
            (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
            == (
                final_directory.st_dev,
                final_directory.st_ino,
                final_directory.st_mtime_ns,
                final_directory.st_ctime_ns,
            ),
            "custody directory changed during inventory",
        )

    walk(root_fd, ".", 0)
    require(seen_links == allowed_links, "custody links differ")
    return result


def reconcile_custody_identity(component, identity):
    """Classify a move only through pinned, no-follow parent directories."""
    import os
    import stat

    require(
        component in CUSTODY_PATHS
        and isinstance(identity, dict)
        and set(identity) == {"device", "inode"},
        "invalid custody identity",
    )
    matches = []
    for label, path in (
        ("source", CUSTODY_PATHS[component]),
        ("custody", CUSTODY_ROOT / CUSTODY_DESTINATIONS[component]),
    ):
        parent = _open_directory_chain(path.parent)
        try:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            require(
                stat.S_ISDIR(info.st_mode)
                and (info.st_dev, info.st_ino)
                == (identity["device"], identity["inode"]),
                "custody identity uncertain",
            )
            matches.append(label)
        finally:
            os.close(parent)
    require(len(matches) == 1, "custody identity ambiguous")
    return matches[0]


def _retirement_receipt(value):
    import re

    fields = {
        "unit_retired",
        "cgroup_empty",
        "processes_retired",
        "sids_terminal_absent",
        "source_pid",
        "source_start_ticks",
        "source_guid_sha256",
        "tls_ca_sha256",
        "license_group",
        "native_sids",
        "state_host_uid",
        "idmap_evidence_sha256",
        "retirement_evidence_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    if not all(
        value[name] is True
        for name in (
            "unit_retired",
            "cgroup_empty",
            "processes_retired",
            "sids_terminal_absent",
        )
    ):
        return False
    if (
        type(value["source_pid"]) is not int
        or value["source_pid"] <= 1
        or type(value["source_start_ticks"]) is not int
        or value["source_start_ticks"] <= 0
    ):
        return False
    if not all(
        isinstance(value[name], str) and re.fullmatch(r"[0-9a-f]{64}", value[name])
        for name in (
            "source_guid_sha256",
            "tls_ca_sha256",
            "idmap_evidence_sha256",
            "retirement_evidence_sha256",
        )
    ):
        return False
    sids = value["native_sids"]
    return (
        value["license_group"] in ("Enterprise", "Free", "Trial", "Forwarder")
        and isinstance(sids, list)
        and type(value["state_host_uid"]) is int
        and value["state_host_uid"] not in (0, 1000)
        and len(sids) <= 256
        and all(
            isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid)
            for sid in sids
        )
        and len(set(sids)) == len(sids)
    )


def seal_fixture_custody(
    *, source_uid, retirement_verified, unsettled_dispatches, official_links, journal
):
    """Move two exact retired fixture roots into root-protected custody.

    No source deletion, rollback, or automatic interrupted-move replay occurs.
    Independent process/SID retirement and journal durability are caller gates.
    Only the exact sealed official archive links are allowed and never followed.
    """
    import os
    import stat

    require(
        os.geteuid() == 0 and type(source_uid) is int and source_uid not in (0, 1000),
        "unsafe custody identity",
    )
    observed_retirement = retirement_verified()
    retirement = json.loads(canonical(observed_retirement))
    require(
        type(unsettled_dispatches) is int
        and unsettled_dispatches == 0
        and _retirement_receipt(retirement)
        and retirement["state_host_uid"] == source_uid,
        "fixture operations unresolved",
    )
    from contextlib import ExitStack

    def identity(fd):
        info = os.fstat(fd)
        return info.st_dev, info.st_ino

    def entry_matches(parent, name, expected):
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == expected

    def still_at_path(path, pinned):
        current = _open_directory_chain(path)
        try:
            return identity(current) == identity(pinned)
        finally:
            os.close(current)

    with ExitStack() as opened:
        custody = _open_directory_chain(CUSTODY_ROOT)
        opened.callback(os.close, custody)
        info = os.fstat(custody)
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == CUSTODY_OWNER
            and stat.S_IMODE(info.st_mode) == 0o700,
            "custody root unsafe",
        )
        for destination in CUSTODY_DESTINATIONS.values():
            try:
                os.stat(destination, dir_fd=custody, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RestoreError("custody destination occupied")
        links = _validated_official_links(official_links)
        roots = {}
        for name, path in CUSTODY_PATHS.items():
            parent = _open_directory_chain(path.parent)
            opened.callback(os.close, parent)
            leaf = os.open(
                path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            opened.callback(os.close, leaf)
            require(
                identity(parent) != identity(custody)
                and entry_matches(parent, path.name, identity(leaf)),
                "custody source replaced",
            )
            roots[name] = (parent, leaf)
        require(
            identity(roots["home"][1]) != identity(roots["tls"][1]),
            "custody roots alias",
        )
        before = {
            name: _custody_inventory(leaf, source_uid, links if name == "home" else {})
            for name, (_, leaf) in roots.items()
        }
        require(
            before["tls"].get("ca.pem", {}).get("sha256")
            == retirement["tls_ca_sha256"],
            "TLS identity differs from retirement evidence",
        )
        require(retirement_verified() == retirement, "source retirement changed")
        journal(
            {
                "state": "custody_seal_intent",
                "retirement": retirement,
                "official_links_sha256": OFFICIAL_LINKS_SHA256,
            }
        )
        for name, source in CUSTODY_PATHS.items():
            parent, leaf = roots[name]
            dev, ino = identity(leaf)
            require(
                still_at_path(source.parent, parent)
                and still_at_path(CUSTODY_ROOT, custody)
                and entry_matches(parent, source.name, (dev, ino)),
                "custody parent or source replaced",
            )
            journal(
                {
                    "state": "custody_move_intent",
                    "component": name,
                    "device": dev,
                    "inode": ino,
                }
            )
            _rename_noreplace(parent, source.name, custody, CUSTODY_DESTINATIONS[name])
            os.fsync(parent)
            os.fsync(custody)
            require(
                still_at_path(source.parent, parent)
                and still_at_path(CUSTODY_ROOT, custody)
                and not entry_matches(parent, source.name, (dev, ino))
                and entry_matches(custody, CUSTODY_DESTINATIONS[name], (dev, ino)),
                "custody move uncertain",
            )
            require(
                _custody_inventory(leaf, source_uid, links if name == "home" else {})
                == before[name],
                "custody contents changed",
            )
            journal(
                {
                    "state": "custody_move_ack",
                    "component": name,
                    "device": dev,
                    "inode": ino,
                }
            )
        require(
            retirement_verified() == retirement
            and all(
                not entry_matches(parent, CUSTODY_PATHS[name].name, identity(leaf))
                for name, (parent, leaf) in roots.items()
            ),
            "fixture not retired or canonical destination occupied",
        )
        # Any replacement at the canonical destination is unsafe, even with a different inode.
        for name, (parent, _) in roots.items():
            try:
                os.stat(CUSTODY_PATHS[name].name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise RestoreError("canonical destination occupied")
        digest = hashlib.sha256(canonical(before)).hexdigest()
        journal({"state": "custody_sealed", "sha256": digest})
        return {
            "sha256": digest,
            "components": len(before),
            "canonical_home_absent": True,
        }


def assess_restored_identity(source_retirement, restored_observation):
    """Compare independently observed identities without rewriting old receipts.

    This records compatibility evidence only. Matching identity does not prove
    restored endpoints, authorization, native jobs or source visibility.
    """
    import re

    require(_retirement_receipt(source_retirement), "invalid source retirement")
    fields = {
        "pid",
        "start_ticks",
        "guid_sha256",
        "tls_ca_sha256",
        "license_group",
        "source_custody_inaccessible",
        "observation_sha256",
    }
    require(
        isinstance(restored_observation, dict) and set(restored_observation) == fields,
        "invalid restored observation",
    )
    require(
        type(restored_observation["pid"]) is int
        and restored_observation["pid"] > 1
        and type(restored_observation["start_ticks"]) is int
        and restored_observation["start_ticks"] > 0
        and (restored_observation["pid"], restored_observation["start_ticks"])
        != (source_retirement["source_pid"], source_retirement["source_start_ticks"]),
        "restored process identity invalid",
    )
    require(
        all(
            isinstance(restored_observation[name], str)
            and re.fullmatch(r"[0-9a-f]{64}", restored_observation[name])
            for name in ("guid_sha256", "tls_ca_sha256", "observation_sha256")
        )
        and restored_observation["license_group"]
        in ("Enterprise", "Free", "Trial", "Forwarder")
        and restored_observation["source_custody_inaccessible"] is True,
        "restored identity evidence incomplete",
    )
    matches = {
        "guid": source_retirement["source_guid_sha256"]
        == restored_observation["guid_sha256"],
        "tls_ca": source_retirement["tls_ca_sha256"]
        == restored_observation["tls_ca_sha256"],
        "license_group": source_retirement["license_group"]
        == restored_observation["license_group"],
    }
    return {
        "matches": matches,
        "source": {
            "guid_sha256": source_retirement["source_guid_sha256"],
            "tls_ca_sha256": source_retirement["tls_ca_sha256"],
            "license_group": source_retirement["license_group"],
        },
        "restored": dict(restored_observation),
        "identity_compatible": all(matches.values()),
        "endpoint_restore_qualified": False,
    }


def observe_fixture_retirement(
    provenance,
    *,
    read_unit,
    read_cgroup,
    read_process_start,
    verify_prior_native_evidence,
    verify_stop_intent,
    read_tls_ca_sha256,
):
    """Build the custody receipt from fixed-identity read-only observations.

    Each callback must be implemented by a separately reviewed native observer.
    Terminal metadata and an authenticated 404 must already be sealed before
    the source stop intent, from the same GUID, transport and authority. The
    callback independently verifies each retained record and journal order.
    Callbacks must raise on permission, transport or enumeration uncertainty:
    a None PID means confirmed absence, and an empty cgroup means confirmed
    emptiness or confirmed absence, never an inaccessible observation.
    This function does not itself connect to or stop a service.
    """
    import re

    provenance = json.loads(canonical(provenance))
    fields = {
        "unit",
        "cgroup",
        "source_pid",
        "source_start_ticks",
        "source_guid_sha256",
        "tls_ca_sha256",
        "license_group",
        "native_jobs",
        "stop_intent_sequence",
        "transport_sha256",
        "authority_sha256",
        "state_host_uid",
        "idmap_evidence_sha256",
        "live_provenance_sha256",
    }
    require(
        isinstance(provenance, dict) and set(provenance) == fields,
        "invalid source provenance",
    )
    require(
        provenance["unit"] == "atlas-platform-recovery-20261118.service"
        and provenance["cgroup"]
        == "/system.slice/atlas-platform-recovery-20261118.service",
        "unexpected source unit",
    )
    require(
        type(provenance["source_pid"]) is int
        and provenance["source_pid"] > 1
        and type(provenance["source_start_ticks"]) is int
        and provenance["source_start_ticks"] > 0,
        "invalid source process",
    )
    require(
        type(provenance["state_host_uid"]) is int
        and provenance["state_host_uid"] not in (0, 1000)
        and provenance["state_host_uid"] > 0,
        "invalid state owner",
    )
    require(
        all(
            isinstance(provenance[name], str)
            and re.fullmatch(r"[0-9a-f]{64}", provenance[name])
            for name in (
                "source_guid_sha256",
                "tls_ca_sha256",
                "idmap_evidence_sha256",
                "live_provenance_sha256",
                "transport_sha256",
                "authority_sha256",
            )
        ),
        "invalid source evidence digest",
    )
    jobs = provenance["native_jobs"]
    stop_sequence = provenance["stop_intent_sequence"]
    require(
        isinstance(jobs, list)
        and len(jobs) <= 256
        and type(stop_sequence) is int
        and stop_sequence > 0,
        "invalid retained native jobs",
    )
    sids = []
    sequences = []
    job_fields = {
        "sid",
        "terminal_sequence",
        "absence_sequence",
        "terminal_evidence_sha256",
        "absence_evidence_sha256",
        "principal_sha256",
        "query_sha256",
        "source_guid_sha256",
        "transport_sha256",
        "authority_sha256",
    }
    for job in jobs:
        require(
            isinstance(job, dict) and set(job) == job_fields,
            "invalid retained native job",
        )
        sid = job["sid"]
        require(
            isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid),
            "invalid native SID",
        )
        require(
            type(job["terminal_sequence"]) is int
            and type(job["absence_sequence"]) is int
            and 0 < job["terminal_sequence"] < job["absence_sequence"] < stop_sequence,
            "native evidence was not sealed before stop",
        )
        require(
            all(
                isinstance(job[name], str) and re.fullmatch(r"[0-9a-f]{64}", job[name])
                for name in job_fields
                - {"sid", "terminal_sequence", "absence_sequence"}
            ),
            "invalid native evidence digest",
        )
        require(
            all(
                job[name] == provenance[name]
                for name in (
                    "source_guid_sha256",
                    "transport_sha256",
                    "authority_sha256",
                )
            ),
            "native evidence provenance differs",
        )
        sids.append(sid)
        sequences.extend([job["terminal_sequence"], job["absence_sequence"]])
    require(
        len(sids) == len(set(sids)) and len(sequences) == len(set(sequences)),
        "duplicate native evidence",
    )
    require(
        provenance["license_group"] in ("Enterprise", "Free", "Trial", "Forwarder"),
        "invalid source license",
    )
    require(
        verify_stop_intent(json.loads(canonical(provenance))) is True,
        "source stop intent unverified",
    )
    for job in jobs:
        require(
            verify_prior_native_evidence(
                json.loads(canonical(job)), json.loads(canonical(provenance))
            )
            is True,
            "retained native evidence unverified",
        )
    unit = read_unit(provenance["unit"])
    require(
        isinstance(unit, dict) and unit == {"state": "inactive", "main_pid": 0},
        "source unit not retired",
    )
    require(read_cgroup(provenance["cgroup"]) == [], "source cgroup not empty")
    observed_start = read_process_start(provenance["source_pid"])
    require(
        observed_start is None
        or (
            type(observed_start) is int
            and observed_start != provenance["source_start_ticks"]
        ),
        "source process still exists",
    )
    require(
        read_tls_ca_sha256() == provenance["tls_ca_sha256"],
        "source TLS identity changed",
    )
    evidence = {
        "unit": provenance["unit"],
        "cgroup": provenance["cgroup"],
        "process": [
            provenance["source_pid"],
            provenance["source_start_ticks"],
            observed_start,
        ],
        "native_jobs": jobs,
        "stop_intent_sequence": stop_sequence,
        "live_provenance_sha256": provenance["live_provenance_sha256"],
    }
    return {
        "unit_retired": True,
        "cgroup_empty": True,
        "processes_retired": True,
        "sids_terminal_absent": True,
        "source_pid": provenance["source_pid"],
        "source_start_ticks": provenance["source_start_ticks"],
        "source_guid_sha256": provenance["source_guid_sha256"],
        "tls_ca_sha256": provenance["tls_ca_sha256"],
        "license_group": provenance["license_group"],
        "native_sids": list(sids),
        "state_host_uid": provenance["state_host_uid"],
        "idmap_evidence_sha256": provenance["idmap_evidence_sha256"],
        "retirement_evidence_sha256": hashlib.sha256(canonical(evidence)).hexdigest(),
    }


def collection_population_report(snapshot):
    """Report populated and empty collections from a validated complete view.

    Counts do not establish that any row is a valid application-domain record.
    """
    require(_snapshot_valid(snapshot), "invalid KV snapshot")
    counts = {name: len(snapshot["rows"][name]) for name in COLLECTIONS}
    return {
        "snapshot_sha256": snapshot["sha256"],
        "counts": counts,
        "populated": [name for name in COLLECTIONS if counts[name]],
        "empty": [name for name in COLLECTIONS if not counts[name]],
        "domain_validity_qualified": False,
    }


SEALED_KV_NAME = "sealed-kv.tar.gz"
NATIVE_KV_NAME = KV_ARCHIVE + ".tar.gz"


def _checked_archive_fd(parent, name, expected, owner):
    import os
    import stat

    require(_archive_valid(expected), "invalid sealed archive evidence")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == owner
            and before.st_nlink == 1
            and not stat.S_IMODE(before.st_mode) & 0o077
            and before.st_size == expected["size"]
            and (before.st_dev, before.st_ino) == (entry.st_dev, entry.st_ino),
            "unsafe archive source",
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            require(total <= before.st_size, "archive changed")
            digest.update(chunk)
        after = os.fstat(fd)
        final = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(
            total == expected["size"]
            and digest.hexdigest() == expected["sha256"]
            and (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and (after.st_dev, after.st_ino) == (final.st_dev, final.st_ino),
            "archive changed or corrupt",
        )
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _copy_archive(source_fd, target_parent, target_name, expected, uid, gid):
    import os

    fd = os.open(
        target_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=target_parent,
    )
    try:
        os.fchown(fd, uid, gid)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            require(total <= expected["size"], "archive changed during copy")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                require(written > 0, "archive write failed")
                view = view[written:]
        require(
            total == expected["size"] and digest.hexdigest() == expected["sha256"],
            "archive changed during copy",
        )
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(target_parent)
    check = _checked_archive_fd(target_parent, target_name, expected, uid)
    os.close(check)


def seal_kv_archive(*, expected, source_retirement, retirement_verified, journal):
    """Copy the exact native archive from sealed source custody to root custody.

    The previously sealed whole source is retained; this operation never deletes
    or modifies it. Its caller must independently validate the supplied receipt.
    """
    import os
    import stat

    require(_archive_valid(expected), "invalid archive evidence")
    expected = json.loads(canonical(expected))
    source_retirement = json.loads(canonical(source_retirement))
    require(
        os.geteuid() == 0
        and _retirement_receipt(source_retirement)
        and retirement_verified() == source_retirement,
        "source retirement unavailable",
    )
    root = _open_directory_chain(CUSTODY_ROOT)
    source = None
    try:
        root_info = os.fstat(root)
        require(
            root_info.st_uid == CUSTODY_OWNER
            and stat.S_IMODE(root_info.st_mode) == 0o700,
            "unsafe outer custody",
        )
        source = _open_descendant(
            root,
            (CUSTODY_DESTINATIONS["home"], "var", "lib", "splunk", "kvstorebackup"),
        )
        source_fd = _checked_archive_fd(
            source, NATIVE_KV_NAME, expected, source_retirement["state_host_uid"]
        )
        try:
            require(
                retirement_verified() == source_retirement
                and _same_directory_path(CUSTODY_ROOT, root)
                and _same_directory_path(
                    CUSTODY_ROOT
                    / CUSTODY_DESTINATIONS["home"]
                    / "var/lib/splunk/kvstorebackup",
                    source,
                ),
                "source retirement or custody path changed",
            )
            journal(
                {
                    "state": "sealed_kv_copy_intent",
                    "sha256": expected["sha256"],
                    "size": expected["size"],
                }
            )
            _copy_archive(
                source_fd,
                root,
                SEALED_KV_NAME,
                expected,
                CUSTODY_OWNER,
                root_info.st_gid,
            )
        finally:
            os.close(source_fd)
        require(
            retirement_verified() == source_retirement
            and _same_directory_path(CUSTODY_ROOT, root)
            and _same_directory_path(
                CUSTODY_ROOT
                / CUSTODY_DESTINATIONS["home"]
                / "var/lib/splunk/kvstorebackup",
                source,
            ),
            "source retirement or custody path changed",
        )
        journal(
            {
                "state": "sealed_kv_copy_verified",
                "sha256": expected["sha256"],
                "size": expected["size"],
            }
        )
        return dict(expected)
    finally:
        if source is not None:
            os.close(source)
        os.close(root)


def install_sealed_kv_archive(
    *, expected, source_identity, target_proof, target_verified, journal
):
    """Install sealed archive only into an independently verified fresh task home.

    The target service must be stopped. A failed copy remains for reconciliation;
    no existing target is overwritten or removed. Native restore is separate.
    """
    import os
    import re
    import stat

    require(_archive_valid(expected), "invalid archive evidence")
    expected = json.loads(canonical(expected))
    source_identity = json.loads(canonical(source_identity))
    target_proof = json.loads(canonical(target_proof))
    fields = {
        "unit_retired",
        "cgroup_empty",
        "processes_retired",
        "target_home_device",
        "target_home_inode",
        "target_host_uid",
        "target_host_gid",
        "target_guid_sha256",
        "fresh_evidence_sha256",
        "retirement_evidence_sha256",
    }
    require(
        os.geteuid() == 0
        and isinstance(target_proof, dict)
        and set(target_proof) == fields,
        "target proof unavailable",
    )
    require(
        all(
            target_proof[name] is True
            for name in ("unit_retired", "cgroup_empty", "processes_retired")
        )
        and all(
            type(target_proof[name]) is int and target_proof[name] > 0
            for name in (
                "target_home_device",
                "target_home_inode",
                "target_host_uid",
                "target_host_gid",
            )
        )
        and target_proof["target_host_uid"] not in (0, 1000)
        and target_proof["target_host_gid"] not in (0, 1000),
        "unsafe target state",
    )
    require(
        all(
            isinstance(target_proof[name], str)
            and re.fullmatch(r"[0-9a-f]{64}", target_proof[name])
            for name in (
                "target_guid_sha256",
                "fresh_evidence_sha256",
                "retirement_evidence_sha256",
            )
        ),
        "invalid target evidence",
    )
    require(
        isinstance(source_identity, dict)
        and set(source_identity) == {"device", "inode"}
        and (target_proof["target_home_device"], target_proof["target_home_inode"])
        != (source_identity["device"], source_identity["inode"]),
        "target aliases retained source",
    )
    require(target_verified() == target_proof, "target proof unavailable")
    outer = _open_directory_chain(CUSTODY_ROOT)
    source_home = target_home = target_dir = None
    try:
        outer_info = os.fstat(outer)
        require(
            outer_info.st_uid == CUSTODY_OWNER
            and stat.S_IMODE(outer_info.st_mode) == 0o700,
            "unsafe outer custody",
        )
        source_home = os.open(
            CUSTODY_DESTINATIONS["home"],
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=outer,
        )
        source_info = os.fstat(source_home)
        require(
            (source_info.st_dev, source_info.st_ino)
            == (source_identity["device"], source_identity["inode"]),
            "retained source identity differs",
        )
        target_home = _open_directory_chain(CUSTODY_PATHS["home"])
        target_info = os.fstat(target_home)
        require(
            (
                target_info.st_dev,
                target_info.st_ino,
                target_info.st_uid,
                target_info.st_gid,
            )
            == (
                target_proof["target_home_device"],
                target_proof["target_home_inode"],
                target_proof["target_host_uid"],
                target_proof["target_host_gid"],
            ),
            "fresh target identity differs",
        )
        target_dir = _open_descendant(
            target_home, ("var", "lib", "splunk", "kvstorebackup")
        )
        target_dir_info = os.fstat(target_dir)
        require(
            target_dir_info.st_uid == target_proof["target_host_uid"]
            and not stat.S_IMODE(target_dir_info.st_mode) & 0o022,
            "unsafe target KV directory",
        )
        try:
            os.stat(NATIVE_KV_NAME, dir_fd=target_dir, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RestoreError("target KV archive occupied")
        sealed_fd = _checked_archive_fd(outer, SEALED_KV_NAME, expected, CUSTODY_OWNER)
        try:
            require(
                target_verified() == target_proof
                and _same_directory_path(CUSTODY_ROOT, outer)
                and _same_directory_path(CUSTODY_PATHS["home"], target_home)
                and _same_directory_path(
                    CUSTODY_PATHS["home"] / "var/lib/splunk/kvstorebackup", target_dir
                ),
                "target proof or path changed",
            )
            journal(
                {
                    "state": "target_kv_copy_intent",
                    "sha256": expected["sha256"],
                    "size": expected["size"],
                }
            )
            _copy_archive(
                sealed_fd,
                target_dir,
                NATIVE_KV_NAME,
                expected,
                target_proof["target_host_uid"],
                target_proof["target_host_gid"],
            )
        finally:
            os.close(sealed_fd)
        require(
            target_verified() == target_proof
            and _same_directory_path(CUSTODY_ROOT, outer)
            and _same_directory_path(CUSTODY_PATHS["home"], target_home)
            and _same_directory_path(
                CUSTODY_PATHS["home"] / "var/lib/splunk/kvstorebackup", target_dir
            ),
            "target proof or path changed",
        )
        journal(
            {
                "state": "target_kv_copy_verified",
                "sha256": expected["sha256"],
                "size": expected["size"],
            }
        )
        return dict(expected)
    finally:
        for fd in (target_dir, target_home, source_home, outer):
            if fd is not None:
                os.close(fd)
