"""Offline admission building blocks; these functions never launch or remove resources.

Callers must hold their own trusted, exclusive lifecycle lock and keep the opened
inputs immutable until use. This module is not wired into the private launcher.
"""

import fcntl
import hashlib
import os
import re
import stat
from dataclasses import dataclass


class AdmissionError(ValueError):
    """An observation was incomplete, changed, or outside the approved boundary."""


def _require(condition, message):
    if not condition:
        raise AdmissionError(message)


def _identity(st):
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_uid,
        st.st_gid,
        st.st_nlink,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
        st.st_blocks,
    )


def _name(name):
    _require(
        isinstance(name, str)
        and name not in ("", ".", "..")
        and "/" not in name
        and "\0" not in name,
        "invalid entry name",
    )


def admit_packet(directory_fd, expected, *, owner_uid, max_file_bytes=8 * 1024 * 1024):
    """Verify an exact, externally trusted map of every executable/input byte.

    The open directory is supplied by the caller. Return identities for later
    revalidation; hashes do not protect against subsequent replacement or imports
    from another path. No manifest within this directory is trusted implicitly.
    """
    _require(type(max_file_bytes) is int and max_file_bytes >= 0, "invalid file limit")
    directory = os.fstat(directory_fd)
    _require(
        stat.S_ISDIR(directory.st_mode)
        and directory.st_uid == owner_uid
        and stat.S_IMODE(directory.st_mode) == 0o700,
        "unsafe packet directory",
    )
    _require(
        bool(expected)
        and all(
            isinstance(d, str) and re.fullmatch(r"[0-9a-f]{64}", d)
            for d in expected.values()
        ),
        "invalid trusted digests",
    )
    for name in expected:
        _name(name)
    _require(set(os.listdir(directory_fd)) == set(expected), "packet inventory differs")
    identities = {}
    for name, digest in expected.items():
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
        )
        try:
            before = os.fstat(fd)
            _require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid == owner_uid
                and stat.S_IMODE(before.st_mode) == 0o444
                and before.st_nlink == 1
                and 0 <= before.st_size <= max_file_bytes,
                "unsafe packet file",
            )
            h = hashlib.sha256()
            read_bytes = 0
            while True:
                block = os.read(fd, min(65536, before.st_size - read_bytes + 1))
                if not block:
                    break
                read_bytes += len(block)
                _require(
                    read_bytes <= before.st_size and read_bytes <= max_file_bytes,
                    "packet file grew during read",
                )
                h.update(block)
            _require(read_bytes == before.st_size, "packet file shortened during read")
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            _require(
                _identity(before) == _identity(after) == _identity(named)
                and h.hexdigest() == digest,
                "packet file changed or digest differs",
            )
            identities[name] = _identity(after)
        finally:
            os.close(fd)
    _require(
        _identity(os.fstat(directory_fd)) == _identity(directory)
        and set(os.listdir(directory_fd)) == set(expected),
        "packet directory changed",
    )
    return identities


def _mount_id(fd):
    """Read the Linux mount ID attached to this open descriptor, or refuse."""
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        values = [
            line.split(":", 1)[1].strip()
            for line in stream
            if line.startswith("mnt_id:")
        ]
    _require(len(values) == 1 and values[0].isdigit(), "mount identity unavailable")
    return int(values[0])


def charge_tree(directory_fd, *, max_entries=100000, require_mount_identity=True):
    """Conservatively charge apparent or allocated bytes, whichever is greater.

    Scan every file, including SQLite databases, WALs, auxiliaries and stale
    copies. Refuse links, special files, device crossings and observed changes.
    With mount identity required, also refuse Linux same-device bind mounts;
    missing procfs mount identity is an error. Portable opt-out is not admission.
    This is an observation, not a quota or a substitute for writer retirement.
    """
    root = os.fstat(directory_fd)
    _require(stat.S_ISDIR(root.st_mode), "not a directory")
    _require(type(require_mount_identity) is bool, "invalid mount policy")
    root_mount = _mount_id(directory_fd) if require_mount_identity else None
    count = 0

    def walk(fd):
        nonlocal count
        before = os.fstat(fd)
        total = max(before.st_size, before.st_blocks * 512)
        names = os.listdir(fd)
        for name in names:
            _name(name)
            count += 1
            _require(count <= max_entries, "inventory limit exceeded")
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _require(st.st_dev == root.st_dev, "filesystem boundary")
            _require(
                stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode),
                "unsupported entry",
            )
            _require(not stat.S_ISREG(st.st_mode) or st.st_nlink == 1, "hard link")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if stat.S_ISDIR(st.st_mode):
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=fd)
            try:
                _require(_identity(os.fstat(child)) == _identity(st), "entry changed")
                if require_mount_identity:
                    _require(_mount_id(child) == root_mount, "mount boundary")
                total += (
                    walk(child)
                    if stat.S_ISDIR(st.st_mode)
                    else max(st.st_size, st.st_blocks * 512)
                )
                _require(
                    _identity(os.fstat(child)) == _identity(st)
                    and _identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
                    == _identity(st),
                    "entry changed",
                )
            finally:
                os.close(child)
        _require(
            _identity(os.fstat(fd)) == _identity(before)
            and set(os.listdir(fd)) == set(names),
            "directory changed",
        )
        return total

    return walk(directory_fd)


@dataclass
class Capacity:
    budget: int
    high_water: int = 0

    def observe(self, charged, reservation, free_bytes, free_floor):
        values = (
            self.budget,
            self.high_water,
            charged,
            reservation,
            free_bytes,
            free_floor,
        )
        _require(all(type(v) is int and v >= 0 for v in values), "invalid capacity")
        self.high_water = max(self.high_water, charged)
        _require(self.high_water + reservation <= self.budget, "task budget exceeded")
        _require(free_bytes >= free_floor + reservation, "filesystem reserve exceeded")
        return self.high_water


@dataclass
class Lease:
    """Single-use, in-memory transition guard, using caller's monotonic clock."""

    nonce: str
    deadline_ns: int
    state: str = "new"

    def transition(self, expected, target, now_ns):
        _require(
            bool(re.fullmatch(r"[0-9a-f]{32}", self.nonce))
            and type(now_ns) is int
            and type(self.deadline_ns) is int
            and 0 <= now_ns < self.deadline_ns,
            "invalid or expired lease",
        )
        _require(
            (expected, target)
            in {("new", "admitted"), ("admitted", "active"), ("active", "retired")}
            and self.state == expected,
            "invalid lease transition",
        )
        self.state = target


def verify_inherited_lock(
    lock_fd, parent_fd, parent_pid, parent_start_ticks, lock_path
):
    """Linux-only direct-parent and inherited inode/contended flock observation."""

    def start(pid):
        with open(f"/proc/{pid}/stat", encoding="ascii") as stream:
            row = stream.read()
        end = row.rfind(")")
        _require(end >= 0, "invalid process stat")
        return int(row[end + 2 :].split()[19])

    _require(
        os.getppid() == parent_pid and start(parent_pid) == parent_start_ticks,
        "parent identity changed",
    )
    local = os.fstat(lock_fd)
    named = os.stat(lock_path, follow_symlinks=False)
    parent = os.stat(f"/proc/{parent_pid}/fd/{parent_fd}")
    _require(
        stat.S_ISREG(local.st_mode)
        and local.st_nlink == 1
        and not stat.S_IMODE(local.st_mode) & 0o022
        and (local.st_dev, local.st_ino)
        == (named.st_dev, named.st_ino)
        == (parent.st_dev, parent.st_ino),
        "lock identity differs",
    )

    def lock_records(pid, fd):
        with open(f"/proc/{pid}/fdinfo/{fd}", encoding="ascii") as stream:
            return {line.strip() for line in stream if line.startswith("lock:")}

    own_records = lock_records(os.getpid(), lock_fd)
    parent_records = lock_records(parent_pid, parent_fd)
    _require(
        bool(own_records & parent_records)
        and all(
            "FLOCK" in row and "WRITE" in row for row in own_records & parent_records
        ),
        "inherited exclusive flock not observed",
    )
    probe = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _require(
            (os.fstat(probe).st_dev, os.fstat(probe).st_ino)
            == (local.st_dev, local.st_ino),
            "lock path changed",
        )
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(probe, fcntl.LOCK_UN)
            raise AdmissionError("lock is not held")
    finally:
        os.close(probe)
    _require(
        os.getppid() == parent_pid and start(parent_pid) == parent_start_ticks,
        "parent identity changed",
    )
