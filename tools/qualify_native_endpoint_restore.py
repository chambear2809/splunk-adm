"""Task-only database-route hook and control for isolated endpoint recovery.

The generated code is installed only by the separately reviewed native fixture;
no live paths are selected by HTTP input and no hook is installed on import.
"""

import json
import os
from pathlib import Path
import re
import secrets
import stat

ROOT = Path("/opt/splunk/var/atlas-endpoint-restore-20261118")
WORKER = "/opt/splunk/etc/apps/splunk_adm/bin/adm_cases_lib/request_worker.py"
_USER = re.compile(r"atlas_er_[0-9a-f]{10}[ab]\Z")
_GENERATION = re.compile(r"[0-9a-f]{32}\Z")
_MODES = {"source", "restored", "blocked"}


def _require(value, message):
    if not value:
        raise RuntimeError(message)


def _safe_directory(path):
    path = Path(path)
    info = path.lstat()
    _require(
        path.is_absolute()
        and path.resolve() == path
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "unsafe fixture directory",
    )
    return path


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate control key")
        result[key] = value
    return result


def read_control(root, generation):
    root = _safe_directory(root)
    _require(
        isinstance(generation, str) and _GENERATION.fullmatch(generation),
        "invalid generation",
    )
    path = root / "control.json"
    info = path.lstat()
    _require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
        and info.st_size <= 1024,
        "unsafe control file",
    )
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        _require(
            (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
            "control changed",
        )
        raw = os.read(fd, 1025)
    finally:
        os.close(fd)
    _require(len(raw) <= 1024, "oversized control")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    _require(
        isinstance(value, dict)
        and set(value) == {"generation", "mode"}
        and value["generation"] == generation
        and value["mode"] in _MODES,
        "invalid control",
    )
    return value["mode"]


def write_control(root, generation, mode, *, expected=None):
    """Publish a route transition under the owner's external serialization."""
    root = _safe_directory(root)
    _require(
        isinstance(generation, str) and _GENERATION.fullmatch(generation),
        "invalid generation",
    )
    _require(mode in _MODES, "invalid route")
    target = root / "control.json"
    if expected is None:
        _require(not os.path.lexists(target), "control already exists")
        _require(mode == "blocked", "initial route must be blocked")
    else:
        _require(read_control(root, generation) == expected, "route changed")
        _require(
            (expected, mode)
            in {
                ("blocked", "source"),
                ("source", "blocked"),
                ("blocked", "restored"),
                ("restored", "blocked"),
            },
            "unsafe route transition",
        )
    temporary = root / (".control-" + secrets.token_hex(16))
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(
                json.dumps(
                    {"generation": generation, "mode": mode},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )
            stream.flush()
            os.fsync(stream.fileno())
        # No second fixture owner may mutate the route; callers hold the task lock.
        if expected is not None:
            _require(
                read_control(root, generation) == expected,
                "route changed before publication",
            )
        else:
            _require(not os.path.lexists(target), "control appeared before publication")
        os.replace(temporary, target)
        dfd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def build_hook(principals, generation):
    """Generate a fixed-principal, fixed-root sitecustomize payload."""
    _require(
        isinstance(principals, (tuple, list))
        and len(principals) == 2
        and all(isinstance(name, str) and _USER.fullmatch(name) for name in principals)
        and principals[0][:-1] == principals[1][:-1]
        and {name[-1] for name in principals} == {"a", "b"},
        "invalid fixture principals",
    )
    _require(
        isinstance(generation, str) and _GENERATION.fullmatch(generation),
        "invalid generation",
    )
    source = (
        _HOOK_TEMPLATE.replace("@ROOT@", repr(str(ROOT)))
        .replace("@USERS@", repr(tuple(principals)))
        .replace("@GENERATION@", repr(generation))
        .replace("@WORKER@", repr(WORKER))
    )
    compile(source, "<endpoint-restore-hook>", "exec")
    return source.encode("utf-8")


_HOOK_TEMPLATE = """
import json, os, re, stat, sys
from pathlib import Path
_ROOT = Path(@ROOT@)
_USERS = @USERS@
_GENERATION = @GENERATION@
_WORKER = @WORKER@

def _read_mode():
    info = _ROOT.lstat()
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and _ROOT.resolve() == _ROOT):
        raise RuntimeError("unsafe route directory")
    path = _ROOT / "control.json"
    entry = path.lstat()
    if not (stat.S_ISREG(entry.st_mode) and entry.st_uid == os.getuid() and stat.S_IMODE(entry.st_mode) == 0o600 and entry.st_nlink == 1 and entry.st_size <= 1024):
        raise RuntimeError("unsafe route control")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino): raise RuntimeError("control changed")
        raw = os.read(fd, 1025)
    finally:
        os.close(fd)
    if len(raw) > 1024: raise RuntimeError("oversized control")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise RuntimeError("duplicate key")
            value[key] = item
        return value
    control = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
    if not (isinstance(control, dict) and set(control) == {"generation", "mode"} and control["generation"] == _GENERATION and control["mode"] in {"source", "restored", "blocked"}):
        raise RuntimeError("invalid control")
    return control["mode"]

def _attest(who, mode, root):
    marker = _ROOT / ("route-" + str(os.getpid()) + "-" + os.urandom(8).hex() + ".json")
    payload = json.dumps({"principal": who, "generation": _GENERATION, "mode": mode, "root": str(root), "pid": os.getpid()}, sort_keys=True, separators=(",", ":")).encode("ascii")
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    directory = os.open(_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def _install():
    sys.path.insert(0, "/opt/splunk/etc/apps/splunk_adm/bin")
    from adm_cases_lib.splunk_host import SplunkHost, HostUnavailable
    original = SplunkHost.database
    def database(self):
        who = self.principal()
        if who not in _USERS:
            return original(self)
        try:
            mode = _read_mode()
            if mode == "blocked": raise RuntimeError("fixture route blocked")
            root = _ROOT / mode
            info = root.lstat()
            if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and root.resolve() == root):
                raise RuntimeError("unsafe fixture root")
            _attest(who, mode, root)
        except (OSError, ValueError, TypeError, UnicodeError, RuntimeError):
            raise HostUnavailable() from None
        previous = self.database_root
        try:
            self.database_root = str(root)
            return original(self)
        finally:
            self.database_root = previous
    SplunkHost.database = database

if __name__ == "sitecustomize" and sys.argv == [_WORKER]:
    try:
        _install()
    except BaseException:
        os._exit(78)
"""


def snapshot_and_restore(source, bundle, target, *, expected_schemas, provenance):
    """Exercise paired copy and negative boundaries after externally proven quiescence.

    The caller blocks fixture routing, verifies every fixture worker has retired,
    and supplies schemas derived independently from the installed runtime.
    Existing artifacts are never adopted or overwritten.
    """
    import shutil

    import case_recovery_snapshot as snapshot

    source, bundle, target = map(Path, (source, bundle, target))
    _require(set(expected_schemas) == set(snapshot.ALLOWLIST), "both schemas required")
    _require(
        source.is_absolute()
        and bundle.is_absolute()
        and target.is_absolute()
        and (bundle.parent == target.parent or target.parent.parent == bundle.parent)
        and not os.path.lexists(bundle)
        and not os.path.lexists(target),
        "unsafe or occupied snapshot destinations",
    )
    root = _safe_directory(bundle.parent)
    _safe_directory(target.parent)
    occupied, corrupt, partial = (
        root / name
        for name in ("negative-occupied", "negative-corrupt", "negative-partial")
    )
    _require(
        not any(os.path.lexists(x) for x in (occupied, corrupt, partial)),
        "negative destination occupied",
    )
    digest = snapshot.create_snapshot(
        source, bundle, expected_schemas=expected_schemas, provenance=provenance
    )
    args = {
        "expected_manifest_sha256": digest,
        "expected_schemas": expected_schemas,
        "expected_provenance": provenance,
    }
    verified = snapshot.validate_snapshot(bundle, **args)
    occupied.mkdir(mode=0o700)
    sentinel = occupied / "sentinel"
    fd = os.open(
        sentinel,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(b"unchanged")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        snapshot.prepare_restore(bundle, occupied, **args)
    except snapshot.SnapshotError:
        _require(sentinel.read_bytes() == b"unchanged", "occupied sentinel changed")
    else:
        raise RuntimeError("occupied target accepted")
    shutil.copytree(bundle, corrupt)
    damaged = corrupt / snapshot.ALLOWLIST[0]
    with damaged.open("r+b") as stream:
        byte = stream.read(1)
        _require(bool(byte), "empty snapshot")
        stream.seek(0)
        stream.write(bytes([byte[0] ^ 1]))
        stream.flush()
        os.fsync(stream.fileno())
    try:
        snapshot.prepare_restore(corrupt, root / "negative-corrupt-target", **args)
    except snapshot.SnapshotError:
        _require(
            not os.path.lexists(root / "negative-corrupt-target"),
            "corrupt target created",
        )
    else:
        raise RuntimeError("corrupt bundle accepted")
    copy = snapshot.shutil.copyfileobj
    calls = [0]

    def fail_second(*values, **kwargs):
        calls[0] += 1
        if calls[0] == 2:
            raise OSError("injected partial copy")
        return copy(*values, **kwargs)

    snapshot.shutil.copyfileobj = fail_second
    try:
        try:
            snapshot.prepare_restore(bundle, partial, **args)
        except OSError:
            _require(
                calls[0] == 2 and not os.path.lexists(partial),
                "partial target retained",
            )
        else:
            raise RuntimeError("partial copy accepted")
    finally:
        snapshot.shutil.copyfileobj = copy
    _require(
        snapshot.validate_snapshot(bundle, **args) == verified, "sealed bundle changed"
    )
    snapshot.prepare_restore(bundle, target, **args)
    for name in snapshot.ALLOWLIST:
        _require(
            snapshot.inspect_database(source / name, expected_schemas[name])
            == snapshot.inspect_database(target / name, expected_schemas[name]),
            "restored database differs",
        )
    return {
        "manifest_sha256": digest,
        "occupied_rejected": True,
        "corrupt_rejected": True,
        "partial_rejected": True,
        "logical_pair_equal": True,
    }
