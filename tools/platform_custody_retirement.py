"""Experimental exact-tree retirement primitive; not an execution entrypoint.

Correct operation requires externally proven exclusive namespace control, a
lifecycle lock and a live guard. Linux unlink cannot atomically condition on an
inode, so this module alone cannot safely authorize a native removal.
"""

import json
import os
import re
import stat
from contextlib import nullcontext

from tools import platform_custody_archive_verifier as verifier


class RetirementError(ValueError):
    pass


def _require(value, message):
    if not value:
        raise RetirementError(message)


def _event(state, path, item):
    return {
        "state": state,
        "path": path,
        "device": item["device"],
        "inode": item["inode"],
    }


def _line(event):
    return (
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _write(fd, data):
    while data:
        written = os.write(fd, data)
        _require(written > 0, "journal write failed")
        data = data[written:]
    os.fsync(fd)


def retire_tree(
    *,
    source_fd,
    source_parent_fd,
    source_name,
    archive_fd,
    manifest_fd,
    archive_parent_fd,
    archive_receipt,
    manifest_receipt,
    independent_receipt,
    expected_source,
    expected_source_parent,
    expected_archive_parent,
    expected_journal_parent,
    trusted_archive_sha256,
    trusted_manifest_sha256,
    journal_fd,
    journal_parent_fd,
    journal_name,
    run_nonce,
    journal_limit,
    guard,
    transition_lock=None,
    on_root_removed=None,
):
    """Fresh-verify and retire a tree; failures preserve its remainder and journal.

    Receipts, identities, nonce, guard implementation, journal ownership, lock,
    all executable bytes and exclusive namespace custody must be independently
    trusted. This function has no CLI and does not provide those assurances.
    """
    _require(
        (transition_lock is None and on_root_removed is None)
        or (transition_lock is not None and callable(on_root_removed)),
        "transition lock and callback must be paired",
    )
    _require(callable(guard) and guard() is True, "guard refused")
    _require(
        isinstance(run_nonce, str) and re.fullmatch(r"[0-9a-f]{32}", run_nonce),
        "invalid nonce",
    )
    _require(
        type(journal_limit) is int and 0 < journal_limit <= 64 * 1024 * 1024,
        "journal limit",
    )
    _require(
        isinstance(source_name, str)
        and source_name not in ("", ".", "..")
        and "/" not in source_name
        and "\0" not in source_name,
        "source name",
    )
    source = os.fstat(source_fd)
    source_parent = os.fstat(source_parent_fd)
    _require(
        stat.S_ISDIR(source_parent.st_mode)
        and (source_parent.st_dev, source_parent.st_ino) == expected_source_parent,
        "source parent identity",
    )
    parent = os.fstat(archive_parent_fd)
    _require(
        (source.st_dev, source.st_ino, source.st_uid, stat.S_IMODE(source.st_mode))
        == expected_source
        and stat.S_ISDIR(source.st_mode),
        "source identity",
    )
    _require(
        (parent.st_dev, parent.st_ino) == expected_archive_parent
        and stat.S_ISDIR(parent.st_mode),
        "custody identity",
    )
    j = os.fstat(journal_fd)
    _require(
        stat.S_ISREG(j.st_mode)
        and j.st_uid == os.getuid()
        and j.st_nlink == 1
        and stat.S_IMODE(j.st_mode) == 0o600
        and j.st_size == 0
        and os.lseek(journal_fd, 0, os.SEEK_CUR) == 0,
        "unsafe journal",
    )
    _require(
        isinstance(journal_name, str)
        and journal_name not in ("", ".", "..")
        and "/" not in journal_name
        and "\0" not in journal_name,
        "journal name",
    )
    jp = os.fstat(journal_parent_fd)
    jn = os.stat(journal_name, dir_fd=journal_parent_fd, follow_symlinks=False)
    _require(
        stat.S_ISDIR(jp.st_mode)
        and (jp.st_dev, jp.st_ino) == expected_journal_parent
        and jp.st_uid == os.getuid()
        and stat.S_IMODE(jp.st_mode) == 0o700
        and (j.st_dev, j.st_ino) == (jn.st_dev, jn.st_ino),
        "journal custody",
    )
    _require(
        archive_receipt["sha256"] == trusted_archive_sha256
        and manifest_receipt["sha256"] == trusted_manifest_sha256,
        "trusted digests differ",
    )
    expected = {
        "status": "verified",
        "archive_sha256": archive_receipt["sha256"],
        "manifest_sha256": manifest_receipt["sha256"],
        "source_device": source.st_dev,
        "source_inode": source.st_ino,
    }
    _require(independent_receipt == expected, "independent verifier prerequisite")
    _require(guard() is True, "guard refused")
    fresh = verifier.verify_contents(
        source_fd=source_fd,
        source_parent_fd=source_parent_fd,
        source_name=source_name,
        archive_fd=archive_fd,
        manifest_fd=manifest_fd,
        archive_parent_fd=archive_parent_fd,
        archive_receipt=archive_receipt,
        manifest_receipt=manifest_receipt,
    )
    _require(fresh == expected and guard() is True, "fresh verification failed")
    manifest = verifier._manifest(manifest_fd, manifest_receipt)
    # The verifier validated canonical paths, metadata, content, and full tree.
    # Ensure the manifest is an unambiguous rooted tree before any mutation.
    children = {p: [] for p, item in manifest.items() if item["kind"] == "directory"}
    for path, item in manifest.items():
        if not path:
            continue
        _require("\0" not in path, "invalid name")
        prefix, _, name = path.rpartition("/")
        _require(prefix in children and name not in ("", ".", ".."), "orphan or alias")
        children[prefix].append(name)
    for names in children.values():
        names.sort()
    root_item = manifest[""]
    events = [
        _event(state, path, item)
        for path, item in manifest.items()
        for state in ("entry_remove_intent", "entry_remove_complete")
    ]
    # Root has distinct event names and a binding record.
    events = [e for e in events if e["path"]]
    events += [
        _event("root_remove_intent", "", root_item),
        _event("root_remove_complete", "", root_item),
    ]
    start = {
        "state": "retirement_intent",
        "nonce": run_nonce,
        "source_name": source_name,
        "archive_sha256": archive_receipt["sha256"],
        "manifest_sha256": manifest_receipt["sha256"],
    }
    needed = len(_line(start)) + sum(len(_line(e)) for e in events)
    _require(needed <= journal_limit, "journal reservation insufficient")
    mount = verifier._mount_id(source_fd)
    _require(guard() is True, "guard refused")
    os.fsync(journal_parent_fd)
    _write(journal_fd, _line(start))

    def step(fd, prefix):
        _require(
            guard() is True and sorted(os.listdir(fd)) == children[prefix],
            "inventory changed",
        )
        for name in children[prefix]:
            _require(guard() is True, "guard refused")
            path = f"{prefix}/{name}" if prefix else name
            item = manifest[path]
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _require(verifier._same_source(st, item), "entry changed")
            verifier._check_named_mount(fd, name, st, item["kind"], mount)
            child = None
            if item["kind"] == "directory":
                child = verifier._open(fd, name, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    _require(
                        verifier._same_source(os.fstat(child), item)
                        and verifier._mount_id(child) == mount,
                        "directory changed",
                    )
                    verifier._no_xattrs(child)
                    step(child, path)
                    _require(
                        not os.listdir(child) and guard() is True, "directory not empty"
                    )
                finally:
                    os.close(child)
            elif item["kind"] == "file":
                child = verifier._open(fd, name, os.O_RDONLY)
                try:
                    _require(
                        verifier._same_source(os.fstat(child), item)
                        and verifier._mount_id(child) == mount,
                        "file changed",
                    )
                    verifier._no_xattrs(child)
                finally:
                    os.close(child)
            else:
                verifier._no_xattrs(fd, name)
                _require(
                    os.readlink(name, dir_fd=fd) == item["target"], "symlink changed"
                )
            _write(journal_fd, _line(_event("entry_remove_intent", path, item)))
            _require(guard() is True, "guard refused")
            now = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if item["kind"] == "directory":
                _require(
                    stat.S_ISDIR(now.st_mode)
                    and (
                        now.st_dev,
                        now.st_ino,
                        now.st_uid,
                        now.st_gid,
                        stat.S_IMODE(now.st_mode),
                    )
                    == (
                        item["device"],
                        item["inode"],
                        item["uid"],
                        item["gid"],
                        item["mode"],
                    ),
                    "directory changed",
                )
            else:
                _require(verifier._same_source(now, item), "entry changed")
            verifier._check_named_mount(fd, name, now, item["kind"], mount)
            if item["kind"] == "directory":
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)
            os.fsync(fd)
            _write(journal_fd, _line(_event("entry_remove_complete", path, item)))

    step(source_fd, "")
    _require(guard() is True and not os.listdir(source_fd), "root changed")
    _write(journal_fd, _line(_event("root_remove_intent", "", root_item)))
    with transition_lock if transition_lock is not None else nullcontext():
        _require(guard() is True, "guard refused")
        named = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
        _require(
            stat.S_ISDIR(named.st_mode)
            and (named.st_dev, named.st_ino, named.st_uid, stat.S_IMODE(named.st_mode))
            == expected_source,
            "root identity changed",
        )
        verifier._check_named_mount(
            source_parent_fd, source_name, named, "directory", mount
        )
        verifier._no_xattrs(source_fd)
        os.rmdir(source_name, dir_fd=source_parent_fd)
        if on_root_removed is not None:
            on_root_removed()
        os.fsync(source_parent_fd)
    _write(journal_fd, _line(_event("root_remove_complete", "", root_item)))
    return {"status": "retired", "journal_bytes": needed}
