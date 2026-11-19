"""Independent read-only archive/source comparison for task custody.

No extraction, cleanup or process-retirement assertion occurs here. The caller
must bind inherited lock and independently observed host/unit retirement before
using the returned content receipt. Credentials and file contents are not logged.
Linux O_NOATIME, O_PATH, listxattr and /proc/self/fdinfo mount IDs are required;
unsupported platforms fail closed.
"""

import fcntl
import gzip
import hashlib
import json
import os
import stat
import tarfile

MAX_MANIFEST = 64 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_EXPANDED = 16 * 1024 * 1024 * 1024
BLOCK = 1024 * 1024
NOATIME = getattr(os, "O_NOATIME", None)


def require(value):
    if not value:
        raise ValueError("independent archive evidence unavailable")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def _meta(st):
    birth = getattr(st, "st_birthtime_ns", None)
    if birth is None and hasattr(st, "st_birthtime"):
        birth = int(st.st_birthtime * 1000000000)
    return {
        "device": st.st_dev,
        "inode": st.st_ino,
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "atime_ns": st.st_atime_ns,
        "ctime_ns": st.st_ctime_ns,
        "birthtime_ns": birth,
        "nlink": st.st_nlink,
    }


def _stable(st):
    value = _meta(st)
    value.pop("atime_ns")
    return value


def _same_source(st, item):
    meta = _meta(st)
    return all(meta[key] == item.get(key) for key in meta if key != "atime_ns")


def _no_xattrs(fd, name=None):
    require(hasattr(os, "listxattr"))
    if name is None:
        attrs = os.listxattr(fd)
    else:
        attrs = os.listxattr(
            "/proc/self/fd/" + str(fd) + "/" + name, follow_symlinks=False
        )
    require(attrs == [])


def _open(parent, name, flags):
    require(NOATIME is not None and name not in ("", ".", "..") and "/" not in name)
    return os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | NOATIME, dir_fd=parent)


def _read_checked(fd, receipt, limit):
    require(
        isinstance(receipt, dict)
        and set(receipt) == {"name", "size", "sha256"}
        and isinstance(receipt["name"], str)
        and "/" not in receipt["name"]
        and type(receipt["size"]) is int
        and 0 < receipt["size"] <= limit
        and isinstance(receipt["sha256"], str)
        and len(receipt["sha256"]) == 64
        and all(c in "0123456789abcdef" for c in receipt["sha256"])
    )
    st = os.fstat(fd)
    require(
        stat.S_ISREG(st.st_mode)
        and st.st_uid == os.getuid()
        and st.st_nlink == 1
        and stat.S_IMODE(st.st_mode) == 0o600
        and st.st_size == receipt["size"]
    )
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while True:
        data = os.read(fd, BLOCK)
        if not data:
            break
        count += len(data)
        require(count <= receipt["size"])
        digest.update(data)
    require(
        count == receipt["size"]
        and digest.hexdigest() == receipt["sha256"]
        and _stable(os.fstat(fd)) == _stable(st)
    )
    return st


def _manifest(fd, receipt):
    _read_checked(fd, receipt, MAX_MANIFEST)
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) < receipt["size"]:
        chunk = os.read(fd, min(BLOCK, receipt["size"] - len(data)))
        require(chunk)
        data.extend(chunk)
    require(hashlib.sha256(data).hexdigest() == receipt["sha256"])
    value = json.loads(data, object_pairs_hook=_unique)
    require(isinstance(value, dict) and "" in value and len(value) <= MAX_ENTRIES)
    require(
        data
        == (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode()
    )
    base = {
        "device",
        "inode",
        "mode",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "atime_ns",
        "ctime_ns",
        "birthtime_ns",
        "nlink",
        "kind",
    }
    for path, item in value.items():
        require(
            isinstance(path, str)
            and len(path.encode("utf-8")) <= 4096
            and (
                not path or all(part not in ("", ".", "..") for part in path.split("/"))
            )
            and isinstance(item, dict)
        )
        kind = item.get("kind")
        require(kind in ("file", "directory", "symlink"))
        require(
            set(item)
            == base
            | (
                {"sha256"}
                if kind == "file"
                else {"target"}
                if kind == "symlink"
                else set()
            )
        )
        for key in base - {"birthtime_ns", "kind"}:
            require(type(item[key]) is int and item[key] >= 0)
        require(
            item["birthtime_ns"] is None
            or type(item["birthtime_ns"]) is int
            and item["birthtime_ns"] >= 0
        )
        if kind == "file":
            require(
                item["nlink"] == 1
                and isinstance(item["sha256"], str)
                and len(item["sha256"]) == 64
                and all(c in "0123456789abcdef" for c in item["sha256"])
            )
        if kind == "symlink":
            require(
                isinstance(item["target"], str) and len(item["target"].encode()) <= 4096
            )
    require(value[""]["kind"] == "directory")
    return value


def _mount_id(fd):
    path = "/proc/self/fdinfo/" + str(fd)
    with open(path, "rb") as stream:
        data = stream.read(8193)
    require(len(data) <= 8192)
    values = [
        line.split(b":", 1)[1].strip()
        for line in data.splitlines()
        if line.startswith(b"mnt_id:")
    ]
    require(len(values) == 1 and values[0].isdigit() and int(values[0]) > 0)
    return int(values[0])


def _check_symlink_mount(parent, name, entry, root_mount):
    require(hasattr(os, "O_PATH"))
    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        require(
            stat.S_ISLNK(opened.st_mode)
            and (opened.st_dev, opened.st_ino) == (entry.st_dev, entry.st_ino)
            and _mount_id(fd) == root_mount
        )
    finally:
        os.close(fd)


def _check_named_mount(parent, name, entry, kind, root_mount):
    if kind == "symlink":
        _check_symlink_mount(parent, name, entry, root_mount)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY if kind == "directory" else os.O_RDONLY
    fd = _open(parent, name, flags)
    try:
        current = os.fstat(fd)
        require(
            (current.st_dev, current.st_ino) == (entry.st_dev, entry.st_ino)
            and _mount_id(fd) == root_mount
        )
    finally:
        os.close(fd)


def _compare_tree(source_fd, manifest):
    require(
        NOATIME is not None
        and (NOATIME == 0 or fcntl.fcntl(source_fd, fcntl.F_GETFL) & NOATIME)
    )
    root = os.fstat(source_fd)
    require(stat.S_ISDIR(root.st_mode) and _same_source(root, manifest[""]))
    root_mount = _mount_id(source_fd)
    observed = {""}
    total = [0]

    def walk(fd, prefix):
        before = os.fstat(fd)
        _no_xattrs(fd)
        with os.scandir(fd) as scan:
            names = sorted(entry.name for entry in scan)
        for name in names:
            require(name not in ("", ".", "..") and "/" not in name)
            path = prefix + "/" + name if prefix else name
            require(path in manifest and path not in observed)
            observed.add(path)
            item = manifest[path]
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(_same_source(entry, item))
            if item["kind"] == "directory":
                require(stat.S_ISDIR(entry.st_mode))
                child = _open(fd, name, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    require(
                        _same_source(os.fstat(child), item)
                        and _mount_id(child) == root_mount
                    )
                    walk(child, path)
                finally:
                    os.close(child)
            elif item["kind"] == "symlink":
                require(stat.S_ISLNK(entry.st_mode))
                _check_symlink_mount(fd, name, entry, root_mount)
                _no_xattrs(fd, name)
                require(os.readlink(name, dir_fd=fd) == item["target"])
            else:
                require(stat.S_ISREG(entry.st_mode))
                child = _open(fd, name, os.O_RDONLY)
                try:
                    require(
                        _same_source(os.fstat(child), item)
                        and _mount_id(child) == root_mount
                    )
                    _no_xattrs(child)
                    h = hashlib.sha256()
                    size = 0
                    while True:
                        data = os.read(child, BLOCK)
                        if not data:
                            break
                        size += len(data)
                        total[0] += len(data)
                        require(total[0] <= MAX_EXPANDED and size <= item["size"])
                        h.update(data)
                    require(
                        size == item["size"]
                        and h.hexdigest() == item["sha256"]
                        and _same_source(os.fstat(child), item)
                    )
                finally:
                    os.close(child)
            final = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(_same_source(final, item))
            _check_named_mount(fd, name, final, item["kind"], root_mount)
        require(
            _same_source(os.fstat(fd), manifest[prefix])
            and (before.st_dev, before.st_ino)
            == (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        )

    walk(source_fd, "")
    require(observed == set(manifest) and _mount_id(source_fd) == root_mount)


def _read_exact(stream, count):
    parts = []
    while count:
        block = stream.read(min(BLOCK, count))
        require(block)
        parts.append(block)
        count -= len(block)
    return b"".join(parts)


def _pax_records(data):
    result = {}
    offset = 0
    while offset < len(data):
        space = data.find(b" ", offset)
        require(space > offset and data[offset:space].isdigit())
        length = int(data[offset:space])
        require(
            length > space - offset + 2
            and length <= 65536
            and offset + length <= len(data)
        )
        record = data[space + 1 : offset + length]
        require(record.endswith(b"\n") and b"=" in record)
        key, value = record[:-1].split(b"=", 1)
        key = key.decode("utf-8", "strict")
        value = value.decode("utf-8", "strict")
        require(key not in result)
        result[key] = value
        offset += length
    require(offset == len(data))
    return result


def _compare_archive(archive_fd, manifest):
    os.lseek(archive_fd, 0, os.SEEK_SET)
    seen = set()
    total = 0
    pending = None
    with os.fdopen(os.dup(archive_fd), "rb") as compressed:
        with gzip.GzipFile(fileobj=compressed, mode="rb") as stream:
            while True:
                block = _read_exact(stream, 512)
                if block == b"\0" * 512:
                    require(pending is None and _read_exact(stream, 512) == b"\0" * 512)
                    padding = 0
                    while True:
                        rest = stream.read(BLOCK)
                        if not rest:
                            break
                        padding += len(rest)
                        require(padding <= 1024 * 1024 and not rest.strip(b"\0"))
                    break
                member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
                require(member is not None and member.size >= 0)
                if member.type == tarfile.XHDTYPE:
                    require(pending is None and 0 < member.size <= 65536)
                    data = _read_exact(stream, member.size)
                    padding = (-member.size) % 512
                    if padding:
                        require(not _read_exact(stream, padding).strip(b"\0"))
                    pending = _pax_records(data)
                    continue
                require(
                    member.type
                    in (
                        tarfile.REGTYPE,
                        tarfile.AREGTYPE,
                        tarfile.DIRTYPE,
                        tarfile.SYMTYPE,
                    )
                    and pending is not None
                )
                pax = pending
                pending = None
                require(
                    set(pax)
                    <= {
                        "ATLAS.mtime_ns",
                        "ATLAS.atime_ns",
                        "ATLAS.ctime_ns",
                        "ATLAS.birthtime_ns",
                        "path",
                        "linkpath",
                    }
                )
                name = pax.get("path", member.name)
                link = pax.get("linkpath", member.linkname)
                # The producer's PAX directory path may have exactly one final
                # separator; Python's normal tar reader removes it for dirs.
                if name.endswith("/"):
                    require(member.isdir() and not name.endswith("//"))
                    name = name[:-1]
                require(name == "state" or name.startswith("state/"))
                path = "" if name == "state" else name[6:]
                require(
                    not path
                    or all(part not in ("", ".", "..") for part in path.split("/"))
                )
                require(path in manifest and path not in seen)
                seen.add(path)
                item = manifest[path]
                require(
                    member.uid == item["uid"]
                    and member.gid == item["gid"]
                    and member.uname == ""
                    and member.gname == ""
                    and member.mode == item["mode"]
                    and int(member.mtime) == item["mtime_ns"] // 1000000000
                )
                for key in ("mtime_ns", "atime_ns", "ctime_ns", "birthtime_ns"):
                    require(pax.get("ATLAS." + key) == str(item[key]))
                if item["kind"] == "directory":
                    require(member.isdir() and member.size == 0)
                elif item["kind"] == "symlink":
                    require(
                        member.issym() and member.size == 0 and link == item["target"]
                    )
                else:
                    require(member.isfile() and member.size == item["size"])
                    h = hashlib.sha256()
                    remaining = member.size
                    while remaining:
                        chunk = stream.read(min(BLOCK, remaining))
                        require(chunk)
                        remaining -= len(chunk)
                        total += len(chunk)
                        require(total <= MAX_EXPANDED)
                        h.update(chunk)
                    require(h.hexdigest() == item["sha256"])
                padding = (-member.size) % 512
                if padding:
                    require(not _read_exact(stream, padding).strip(b"\0"))
    require(seen == set(manifest))


def verify_contents(
    *,
    source_fd,
    source_parent_fd,
    source_name,
    archive_fd,
    manifest_fd,
    archive_parent_fd,
    archive_receipt,
    manifest_receipt,
):
    """Compare all actual bytes and metadata, with no mutation or deletion."""
    require(source_name not in ("", ".", "..") and "/" not in source_name)
    source = os.fstat(source_fd)
    source_named = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
    require(stat.S_ISDIR(source.st_mode) and _stable(source) == _stable(source_named))
    _check_named_mount(
        source_parent_fd, source_name, source_named, "directory", _mount_id(source_fd)
    )

    def entry_matches(fd, receipt):
        st = os.fstat(fd)
        entry = os.stat(
            receipt["name"], dir_fd=archive_parent_fd, follow_symlinks=False
        )
        require(_stable(st) == _stable(entry))

    entry_matches(archive_fd, archive_receipt)
    entry_matches(manifest_fd, manifest_receipt)
    archive_stat = _read_checked(archive_fd, archive_receipt, MAX_ARCHIVE)
    manifest_stat = _read_checked(manifest_fd, manifest_receipt, MAX_MANIFEST)
    manifest = _manifest(manifest_fd, manifest_receipt)
    _compare_tree(source_fd, manifest)
    _compare_archive(archive_fd, manifest)
    _compare_tree(source_fd, manifest)
    final_source = os.stat(source_name, dir_fd=source_parent_fd, follow_symlinks=False)
    require(_stable(source) == _stable(os.fstat(source_fd)) == _stable(final_source))
    _check_named_mount(
        source_parent_fd, source_name, final_source, "directory", _mount_id(source_fd)
    )
    require(
        _stable(archive_stat) == _stable(os.fstat(archive_fd))
        and _stable(manifest_stat) == _stable(os.fstat(manifest_fd))
    )
    entry_matches(archive_fd, archive_receipt)
    entry_matches(manifest_fd, manifest_receipt)
    return {
        "status": "verified",
        "archive_sha256": archive_receipt["sha256"],
        "manifest_sha256": manifest_receipt["sha256"],
        "source_device": source.st_dev,
        "source_inode": source.st_ino,
    }
