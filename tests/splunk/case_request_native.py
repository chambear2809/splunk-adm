"""Fixed-path native fixture for disposable case-request qualification."""

import configparser
import base64
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import sqlite3
import stat
import struct
import subprocess
import sys
import time

TASK = "cases-requests-20261118"
ROOT_UID = 0
ROOT_GID = 0
STAGED = Path("/tmp/cases-requests-20261118-fixtures")
APP = Path("/opt/splunk/etc/apps/splunk_adm")
BIN = APP / "bin"
DB = Path("/opt/splunk/var/lib/splunk/splunk_adm_investigations/cases.sqlite")
CONTROL = Path("/tmp/adm-cases-requests-20261118")
HOOK_BACKUP = Path("/tmp/adm-cases-requests-20261118-hook-backup")
HOOK_TRANSACTION = HOOK_BACKUP / "transaction.json"
HOOK_SOURCE = STAGED / "case_request_fault_hook.py"
TEST_SOURCE = STAGED / "qualify/tests/test_case_request_supervisor.py"
PRINCIPAL_RE = re.compile(r"atlas_case_[0-9a-f]{10}a\Z")
REQUEST_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MODES = {"auth", "config", "diagnostic", "precommit", "postcommit", "off"}
GENERATIONS = {
    "auth",
    "config",
    "diagnostic",
    "precommit",
    "postcommit",
    "disconnect",
}
WORKER = str(BIN / "adm_cases_lib/request_worker.py")


def require(condition):
    if not condition:
        raise RuntimeError("native request fixture condition failed")


def _require_root():
    require(os.getuid() == ROOT_UID)


def principal(value):
    require(isinstance(value, str) and PRINCIPAL_RE.fullmatch(value) is not None)
    return value


def request_id(value):
    require(isinstance(value, str) and REQUEST_RE.fullmatch(value) is not None)
    return value


def _read_json_input():
    raw = sys.stdin.buffer.read(16_385)
    require(len(raw) <= 16_384)

    def unique_pairs(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result)
            result[key] = item
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    require(isinstance(value, dict) and isinstance(value.get("action"), str))
    return value


def _exact_keys(value, expected):
    require(set(value) == set(expected))


def _sdk_directory():
    spec = importlib.util.find_spec("splunk")
    require(spec is not None)
    if spec.origin and spec.origin not in ("built-in", "frozen"):
        module_path = Path(spec.origin).resolve()
        sdk = module_path.parent.parent
    else:
        locations = tuple(spec.submodule_search_locations or ())
        require(len(locations) == 1)
        module_path = Path(locations[0]).resolve()
        sdk = module_path.parent
    require(sdk.is_absolute() and str(sdk).startswith("/opt/splunk/"))
    require(sdk.name == "site-packages")
    return sdk, str(module_path)


def _sitecustomize_paths():
    sdk, module_path = _sdk_directory()
    source = sdk / "sitecustomize.py"
    bytecode = (
        sdk
        / "__pycache__"
        / (
            "sitecustomize.cpython-"
            + str(sys.version_info.major)
            + str(sys.version_info.minor)
            + ".pyc"
        )
    )
    try:
        cache_info = bytecode.parent.lstat()
    except FileNotFoundError:
        pass
    else:
        require(
            stat.S_ISDIR(cache_info.st_mode) and not stat.S_ISLNK(cache_info.st_mode)
        )
    return sdk, module_path, source, bytecode


def _app_config():
    path = APP / "default/app.conf"
    require(path.is_file() and not path.is_symlink())
    config = configparser.ConfigParser()
    require(config.read(str(path)) == [str(path)])
    return config


def _flags():
    try:
        output = subprocess.check_output(
            [
                "/opt/splunk/bin/splunk",
                "btool",
                "adm_investigations",
                "list",
                "persistence",
                "--app=splunk_adm",
            ],
            timeout=30,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        config = configparser.ConfigParser()
        config.read_string(output)
        return {
            "mode": config.get("persistence", "mode"),
            "platform": config.get("persistence", "platform"),
            "capture_mode": config.get("persistence", "capture_mode"),
        }
    except Exception as exc:
        raise RuntimeError("fixed public persistence flags unavailable") from exc


def probe():
    sdk, module_path, source, bytecode = _sitecustomize_paths()
    payload = _read_regular(HOOK_SOURCE, owner=os.getuid(), mode=0o600, maximum=64_000)
    source_exists = os.path.lexists(source)
    cache_exists = os.path.lexists(bytecode)
    source_bytes = _platform_file(source, maximum=1_000_000) if source_exists else None
    active = bool(
        source_bytes and source_bytes.endswith(_fixture_appendage(payload, source))
    )
    app = _app_config()
    flags = _flags()
    return {
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "sdk_module_path": module_path,
        "fixture_hook_active": active,
        "sitecustomize_original_absent": not source_exists,
        "sitecustomize_cache_absent": not cache_exists,
        "sitecustomize_source": _platform_metadata(source) if source_exists else None,
        "sitecustomize_cache": _platform_metadata(bytecode) if cache_exists else None,
        "installed_version": app.get("launcher", "version", fallback=""),
        "installed_build": app.get("install", "build", fallback=""),
        "flags": flags,
        "runtime_sha256": {
            str(p.relative_to(APP)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in BIN.rglob("*.py")
            if p.is_file() and not p.is_symlink()
        },
        "notes_enabled_capture_disabled": flags["mode"] == "single_search_head"
        and flags["capture_mode"] == "disabled",
    }


def host_diagnostics():
    sys.path.insert(0, str(BIN))
    from adm_cases_lib.splunk_host import SplunkHost  # noqa: PLC0415

    result = {}
    for name, operation in (
        ("configuration", SplunkHost._configuration),
        ("topology", SplunkHost._topology),
    ):
        try:
            result[name] = operation()
        except Exception as exc:
            result[name] = {"error_type": type(exc).__name__}
    return result


def request_diagnostics():
    results = []
    for path in sorted(CONTROL.glob("diagnostic-*.json")):
        require(re.fullmatch(r"diagnostic-[0-9]+-[a-z-]+\.json", path.name) is not None)
        info = path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            and info.st_size <= 4096
        )
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        require(len(raw) <= 4096)
        value = json.loads(raw.decode("ascii"))
        require(
            isinstance(value, dict)
            and value.get("phase")
            in {
                "qualify",
                "configuration",
                "topology",
                "request-current-context",
                "request-server-info",
                "request-other",
            }
            and value.get("status") in {"ok", "error"}
            and set(value) <= {"phase", "status", "error_type", "frames"}
        )
        if value["status"] == "error":
            require(
                isinstance(value.get("error_type"), str)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value["error_type"])
                and isinstance(value.get("frames"), list)
                and len(value["frames"]) <= 4
            )
            for frame in value["frames"]:
                require(
                    isinstance(frame, dict)
                    and set(frame) == {"file", "line", "function"}
                    and isinstance(frame["file"], str)
                    and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", frame["file"])
                    and type(frame["line"]) is int
                    and frame["line"] > 0
                    and isinstance(frame["function"], str)
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", frame["function"])
                )
            results.append(
                {
                    "phase": value["phase"],
                    "error_type": value["error_type"],
                    "frames": value["frames"],
                }
            )
        else:
            results.append({"phase": value["phase"], "status": "ok"})
    return results


def _ensure_private_directory(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def unit_setup():
    _ensure_private_directory(STAGED)
    qualify = STAGED / "qualify"
    _ensure_private_directory(qualify)
    app_root = qualify / "splunk_app"
    tests_root = qualify / "tests"
    _ensure_private_directory(app_root)
    _ensure_private_directory(tests_root)
    app_link = app_root / "splunk_adm"
    if os.path.lexists(app_link):
        require(app_link.is_symlink() and os.readlink(app_link) == str(APP))
    else:
        app_link.symlink_to(APP, target_is_directory=True)
    source_info = TEST_SOURCE.lstat()
    require(
        stat.S_ISREG(source_info.st_mode)
        and source_info.st_uid in (os.getuid(), 0)
        and source_info.st_nlink == 1
        and source_info.st_size <= 100_000
    )
    source_bytes = TEST_SOURCE.read_bytes()
    unit_path = tests_root / "test_case_request_supervisor.py"
    if os.path.lexists(unit_path):
        require(unit_path.is_file() and not unit_path.is_symlink())
        require(unit_path.read_bytes() == source_bytes)
    else:
        fd = os.open(
            unit_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(source_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    return {"unit_path": str(unit_path), "app_bin": str(app_link / "bin")}


def _case_store():
    sys.path.insert(0, str(BIN))
    from adm_cases_lib.store import CaseStore  # noqa: PLC0415

    return CaseStore(
        DB,
        lambda *_: True,
    )


def seed_large(who):
    who = principal(who)
    flags = _flags()
    require(
        flags["mode"] == "single_search_head" and flags["capture_mode"] == "disabled"
    )
    store = _case_store()
    case_ids, create_requests, case_sizes = [], [], []
    text = "n" * 10_000
    window = {
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-02T00:00:00Z",
    }
    for index in range(3):
        create_id = f"request-native-{who}-{index}"
        created = store.create(
            who,
            create_id,
            {"schema_version": 1, "title": f"Native fixture {index}", "window": window},
        )
        case_id = created["id"]
        case_ids.append(case_id)
        create_requests.append(create_id)
        latest = created
        for note_index in range(75):
            latest = store.append(
                who,
                f"request-native-{who}-{index}-{note_index}",
                case_id,
                latest["revision"],
                "entry",
                {"type": "note", "text": text},
            )
        case_sizes.append(
            len(
                json.dumps(
                    latest, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")
            )
        )
    return {
        "case_ids": case_ids,
        "create_request_ids": create_requests,
        "case_bytes": case_sizes,
        "notes_per_case": 75,
        "note_bytes": len(text.encode("utf-8")),
    }


def _readonly_db():
    info = DB.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
    )
    return sqlite3.connect(DB.as_uri() + "?mode=ro", uri=True, timeout=0.2)


def case_state(who, ident):
    who = principal(who)
    ident = request_id(ident)
    with closing(_readonly_db()) as db:
        count = db.execute(
            "SELECT COUNT(*) FROM requests WHERE principal=? AND request_id=?",
            (who, ident),
        ).fetchone()[0]
        row = db.execute(
            "SELECT result FROM requests WHERE principal=? AND request_id=? LIMIT 1",
            (who, ident),
        ).fetchone()
        total = db.execute(
            "SELECT COUNT(*) FROM cases WHERE owner=?", (who,)
        ).fetchone()[0]
    result = None
    if row and isinstance(row[0], str) and len(row[0]) <= 1_100_000:
        try:
            document = json.loads(row[0])
            case_id, revision = document.get("id"), document.get("revision")
            if (
                isinstance(case_id, str)
                and len(case_id) <= 64
                and type(revision) is int
            ):
                result = {"case_id": case_id, "revision": revision}
        except (ValueError, TypeError, AttributeError):
            result = None
    return {
        "request_count": count,
        "result": result,
        "owner_case_count": total,
    }


def _pid_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _workers():
    workers = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            with (entry / "cmdline").open("rb") as stream:
                raw_argv = stream.read(16385)
            if len(raw_argv) > 16384:
                continue
            argv = raw_argv.split(b"\0")
            if not any(arg.decode("utf-8", "replace") == WORKER for arg in argv):
                continue
            pgid = os.getpgid(pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
        workers.append({"pid": pid, "pgid": pgid})
    return workers


def observe(generation):
    require(generation in GENERATIONS)
    workers = _workers()
    marker = CONTROL / f"marker-{generation}.json"
    try:
        info = marker.lstat()
    except FileNotFoundError:
        return {
            "marker_present": False,
            "marker": None,
            "worker_processes": workers,
            "worker_pids": [w["pid"] for w in workers],
            "child_exists": False,
            "group_alive": False,
        }
    require(
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_size <= 600
    )
    fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        raw = os.read(fd, 601)
    finally:
        os.close(fd)
    require(len(raw) <= 600)
    value = json.loads(raw.decode("ascii"))
    require(set(value) == {"phase", "pid", "pgid", "child_pid"})
    require(value["phase"] == generation)
    pids = [value[name] for name in ("pid", "pgid", "child_pid")]
    require(all(type(pid) is int and pid > 1 for pid in pids))
    group_alive = True
    try:
        os.killpg(value["pgid"], 0)
    except ProcessLookupError:
        group_alive = False
    except PermissionError:
        group_alive = True
    return {
        "marker_present": True,
        "marker": value,
        "worker_pids": [w["pid"] for w in workers],
        "child_exists": _pid_exists(value["child_pid"]),
        "phase": value["phase"],
        "marker_uid": info.st_uid,
        "marker_gid": info.st_gid,
        "marker_size": info.st_size,
        "marker_mode": stat.S_IMODE(info.st_mode),
        "marker_links": info.st_nlink,
        "leader_pid": value["pid"],
        "leader_alive": _pid_exists(value["pid"]),
        "leader_pgid": value["pgid"],
        "group_alive": group_alive,
        "child_pid": value["child_pid"],
        "child_alive": _pid_exists(value["child_pid"]),
        "worker_processes": workers,
    }


def _read_regular(path, *, owner, mode, maximum):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == owner
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == mode
        and info.st_size <= maximum
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        data = os.read(fd, maximum + 1)
    finally:
        os.close(fd)
    require(len(data) <= maximum)
    return data


def _platform_file(path, *, maximum):
    """Read bounded existing platform bytes without following links."""
    info = path.lstat()
    allowed_owners = {0, pwd.getpwnam("splunk").pw_uid}
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid in allowed_owners
        and info.st_nlink == 1
        and info.st_size <= maximum
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        data = os.read(fd, maximum + 1)
    finally:
        os.close(fd)
    require(len(data) <= maximum)
    return data


def _fixture_appendage(
    payload, site_path="/opt/splunk/etc/python3.13/site-packages/sitecustomize.py"
):
    digest = hashlib.sha256(payload).hexdigest()
    return (
        b"\n# ADM_CASES_REQUEST_FIXTURE_HOOK:"
        + digest.encode("ascii")
        + b"\nexec(compile("
        + repr(payload).encode("ascii")
        + b", '<adm-case-request-fixture>', 'exec'), "
        + b"{'__name__': 'sitecustomize', '__file__': "
        + repr(str(site_path)).encode("ascii")
        + b"})\n"
    )


def _platform_metadata(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return {
        "sha256": hashlib.sha256(_platform_file(path, maximum=2_000_000)).hexdigest(),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "mtime_ns": info.st_mtime_ns,
    }


def _fsync_directory(path):
    directory_fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _normalize_temp(path, *, uid, gid, mode, mtime_ns):
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.utime(fd, ns=(time.time_ns(), mtime_ns))
        os.fsync(fd)
    finally:
        os.close(fd)


def _ensure_backup_directory():
    created = False
    try:
        HOOK_BACKUP.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    info = HOOK_BACKUP.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == ROOT_UID
        and stat.S_IMODE(info.st_mode) == 0o700
    )
    if created:
        _fsync_directory(HOOK_BACKUP.parent)


def _load_transaction():
    info = HOOK_BACKUP.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == ROOT_UID
        and stat.S_IMODE(info.st_mode) == 0o700
    )
    raw = _read_regular(HOOK_TRANSACTION, owner=ROOT_UID, mode=0o600, maximum=5_000_000)
    value = json.loads(raw.decode("utf-8"))
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "version",
            "payload_sha256",
            "modified_sha256",
            "modified_mtime",
            "source",
            "cache",
        }
        and value["version"] == 1
        and re.fullmatch(r"[0-9a-f]{64}", value["payload_sha256"])
        and re.fullmatch(r"[0-9a-f]{64}", value["modified_sha256"])
        and isinstance(value["modified_mtime"], int)
        and value["modified_mtime"] >= 0
    )
    for name, maximum in (("source", 1_000_000), ("cache", 2_000_000)):
        snapshot = value[name]
        if snapshot is None:
            continue
        require(
            isinstance(snapshot, dict)
            and set(snapshot) == {"bytes", "sha256", "uid", "gid", "mode", "mtime_ns"}
            and isinstance(snapshot["bytes"], str)
            and re.fullmatch(r"[0-9a-f]{64}", snapshot["sha256"])
            and isinstance(snapshot["uid"], int)
            and snapshot["uid"] in {ROOT_UID, pwd.getpwnam("splunk").pw_uid}
            and isinstance(snapshot["gid"], int)
            and isinstance(snapshot["mode"], int)
            and snapshot["mode"] in {0o444, 0o600, 0o640, 0o644}
            and isinstance(snapshot["mtime_ns"], int)
        )
        data = base64.b64decode(snapshot["bytes"], validate=True)
        require(
            len(data) <= maximum
            and hashlib.sha256(data).hexdigest() == snapshot["sha256"]
        )
    return value


def _write_transaction(value):
    _ensure_backup_directory()
    require(not os.path.lexists(HOOK_TRANSACTION))
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    require(len(raw) <= 5_000_000)
    fd = os.open(
        HOOK_TRANSACTION,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(HOOK_TRANSACTION, ROOT_UID, ROOT_GID)
    os.chmod(HOOK_TRANSACTION, 0o600)
    with open(HOOK_TRANSACTION, "rb") as stream:
        os.fsync(stream.fileno())
    directory_fd = os.open(
        str(HOOK_BACKUP), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _snapshot(path, maximum):
    if not os.path.lexists(path):
        return None
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    require(mode in (0o444, 0o600, 0o640, 0o644))
    data = _platform_file(path, maximum=maximum)
    return {
        "bytes": base64.b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode,
        "mtime_ns": info.st_mtime_ns,
    }


def _matches_snapshot_metadata(path, snapshot):
    if snapshot is None:
        return False
    info = path.lstat()
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == snapshot["uid"]
        and info.st_gid == snapshot["gid"]
        and stat.S_IMODE(info.st_mode) == snapshot["mode"]
        and info.st_mtime_ns == snapshot["mtime_ns"]
    )


def _matches_snapshot(path, snapshot, *, maximum):
    return (
        snapshot is None
        and not os.path.lexists(path)
        or snapshot is not None
        and os.path.lexists(path)
        and _matches_snapshot_metadata(path, snapshot)
        and hashlib.sha256(_platform_file(path, maximum=maximum)).hexdigest()
        == snapshot["sha256"]
    )


def _restore_snapshot(path, snapshot, *, maximum):
    if snapshot is None:
        if os.path.lexists(path):
            path.unlink()
            _fsync_directory(path.parent)
        return
    data = base64.b64decode(snapshot["bytes"], validate=True)
    require(
        len(data) <= maximum and hashlib.sha256(data).hexdigest() == snapshot["sha256"]
    )
    temp = path.with_name("." + path.name + ".adm-cases-restore")
    if os.path.lexists(temp):
        info = temp.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid in {ROOT_UID, pwd.getpwnam("splunk").pw_uid}
            and info.st_size <= maximum
        )
        partial = _platform_file(temp, maximum=maximum)
        require(data.startswith(partial))
        if partial == data:
            require(
                info.st_uid in {ROOT_UID, snapshot["uid"]}
                and info.st_gid in {0, snapshot["gid"]}
                and stat.S_IMODE(info.st_mode) in {0o600, snapshot["mode"]}
                and info.st_mtime_ns in {0, snapshot["mtime_ns"]}
            )
        else:
            require(info.st_uid == ROOT_UID and stat.S_IMODE(info.st_mode) == 0o600)
        if partial != data:
            temp.unlink()
    if not os.path.lexists(temp):
        fd = os.open(
            temp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    _normalize_temp(
        temp,
        uid=snapshot["uid"],
        gid=snapshot["gid"],
        mode=snapshot["mode"],
        mtime_ns=snapshot["mtime_ns"],
    )
    os.replace(temp, path)
    _fsync_directory(path.parent)
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == snapshot["uid"]
        and info.st_gid == snapshot["gid"]
        and stat.S_IMODE(info.st_mode) == snapshot["mode"]
        and info.st_mtime_ns == snapshot["mtime_ns"]
        and hashlib.sha256(_platform_file(path, maximum=maximum)).hexdigest()
        == snapshot["sha256"]
    )


def _atomic_platform_write(path, data, *, uid, gid, mode, mtime):
    temp = path.with_name("." + path.name + ".adm-cases-install")
    require(not os.path.lexists(temp))
    fd = os.open(
        temp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    timestamp_ns = mtime * 1_000_000_000
    _normalize_temp(
        temp,
        uid=uid,
        gid=gid,
        mode=mode,
        mtime_ns=timestamp_ns,
    )
    os.replace(temp, path)
    directory_fd = os.open(
        str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def hook_install(expected_sha):
    _require_root()
    require(
        isinstance(expected_sha, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha)
    )
    sdk, _, target, bytecode = _sitecustomize_paths()
    stage_info = STAGED.lstat()
    splunk_uid = pwd.getpwnam("splunk").pw_uid
    require(
        stat.S_ISDIR(stage_info.st_mode)
        and not stat.S_ISLNK(stage_info.st_mode)
        and stage_info.st_uid == splunk_uid
        and stat.S_IMODE(stage_info.st_mode) == 0o700
    )
    source = _read_regular(HOOK_SOURCE, owner=splunk_uid, mode=0o600, maximum=64_000)
    digest = hashlib.sha256(source).hexdigest()
    require(digest == expected_sha)
    require(not os.path.lexists(HOOK_BACKUP))
    source_snapshot = _snapshot(target, 1_000_000)
    cache_snapshot = _snapshot(bytecode, 2_000_000)
    original = base64.b64decode(source_snapshot["bytes"]) if source_snapshot else b""
    modified = original + _fixture_appendage(source, target)
    transaction = {
        "version": 1,
        "payload_sha256": digest,
        "modified_sha256": hashlib.sha256(modified).hexdigest(),
        "modified_mtime": int(time.time()),
        "source": source_snapshot,
        "cache": cache_snapshot,
    }
    _write_transaction(transaction)
    require(_matches_snapshot(target, source_snapshot, maximum=1_000_000))
    require(_matches_snapshot(bytecode, cache_snapshot, maximum=2_000_000))
    if os.path.lexists(bytecode):
        bytecode.unlink()
        _fsync_directory(bytecode.parent)
    uid = source_snapshot["uid"] if source_snapshot else ROOT_UID
    gid = source_snapshot["gid"] if source_snapshot else ROOT_GID
    mode = source_snapshot["mode"] if source_snapshot else 0o644
    _atomic_platform_write(
        target,
        modified,
        uid=uid,
        gid=gid,
        mode=mode,
        mtime=transaction["modified_mtime"],
    )
    info = target.lstat()
    expected_uid = source_snapshot["uid"] if source_snapshot else ROOT_UID
    expected_gid = source_snapshot["gid"] if source_snapshot else ROOT_GID
    expected_mode = source_snapshot["mode"] if source_snapshot else 0o644
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == expected_uid
        and info.st_gid == expected_gid
        and stat.S_IMODE(info.st_mode) == expected_mode
        and info.st_mtime_ns == transaction["modified_mtime"] * 1_000_000_000
        and hashlib.sha256(_platform_file(target, maximum=2_000_000)).hexdigest()
        == transaction["modified_sha256"]
    )
    directory_fd = os.open(str(sdk), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {
        "hook_sha256": digest,
        "hook_path": str(target),
        "original_source_sha256": source_snapshot["sha256"]
        if source_snapshot
        else None,
        "original_cache_sha256": cache_snapshot["sha256"] if cache_snapshot else None,
        "fixture_hook_active": True,
    }


def _validate_pyc(path, source, source_mtime):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid in (0, pwd.getpwnam("splunk").pw_uid)
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) in (0o600, 0o640, 0o644)
        and info.st_size <= 1_000_000
    )
    data = _read_regular(
        path, owner=info.st_uid, mode=stat.S_IMODE(info.st_mode), maximum=1_000_000
    )
    require(len(data) >= 16 and data[:4] == importlib.util.MAGIC_NUMBER)
    flags = struct.unpack("<I", data[4:8])[0]
    if flags & 1:
        require(data[8:16] == importlib.util.source_hash(source))
    else:
        require(flags == 0)
        require(struct.unpack("<I", data[12:16])[0] == len(source))
        require(struct.unpack("<I", data[8:12])[0] == int(source_mtime) & 0xFFFFFFFF)


def hook_remove(expected_sha):
    _require_root()
    require(
        isinstance(expected_sha, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha)
    )
    sdk, _, target, bytecode = _sitecustomize_paths()
    transaction = _load_transaction()
    require(transaction["payload_sha256"] == expected_sha)
    original = transaction["source"]
    original_bytes = base64.b64decode(original["bytes"]) if original else None
    payload = _read_regular(
        HOOK_SOURCE, owner=pwd.getpwnam("splunk").pw_uid, mode=0o600, maximum=64_000
    )
    require(hashlib.sha256(payload).hexdigest() == expected_sha)
    modified = (original_bytes or b"") + _fixture_appendage(payload, target)
    require(hashlib.sha256(modified).hexdigest() == transaction["modified_sha256"])
    install_temp = target.with_name("." + target.name + ".adm-cases-install")
    if os.path.lexists(install_temp):
        info = install_temp.lstat()
        source_snapshot = transaction["source"]
        temp_uid = source_snapshot["uid"] if source_snapshot else ROOT_UID
        temp_gid = source_snapshot["gid"] if source_snapshot else ROOT_GID
        temp_mode = source_snapshot["mode"] if source_snapshot else 0o644
        temp_mtime_ns = transaction["modified_mtime"] * 1_000_000_000
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid in {ROOT_UID, pwd.getpwnam("splunk").pw_uid}
            and info.st_size <= len(modified)
        )
        partial = _platform_file(install_temp, maximum=2_000_000)
        require(modified.startswith(partial))
        if partial == modified:
            require(
                info.st_uid == temp_uid
                and info.st_gid == temp_gid
                and stat.S_IMODE(info.st_mode) == temp_mode
                and info.st_mtime_ns == temp_mtime_ns
            )
        else:
            require(info.st_uid == ROOT_UID and stat.S_IMODE(info.st_mode) == 0o600)
        install_temp.unlink()
    if os.path.lexists(target):
        current = _platform_file(target, maximum=2_000_000)
        digest = hashlib.sha256(current).hexdigest()
        if digest == transaction["modified_sha256"]:
            source_metadata = {
                "uid": original["uid"] if original else ROOT_UID,
                "gid": original["gid"] if original else ROOT_GID,
                "mode": original["mode"] if original else 0o644,
                "mtime_ns": transaction["modified_mtime"] * 1_000_000_000,
            }
            require(_matches_snapshot_metadata(target, source_metadata))
        else:
            require(
                original_bytes is not None
                and digest == original["sha256"]
                and _matches_snapshot_metadata(target, original)
            )
    else:
        require(original_bytes is None)
    cache = transaction["cache"]
    if os.path.lexists(bytecode):
        current_cache = _platform_file(bytecode, maximum=2_000_000)
        original_cache_matches = (
            cache is not None
            and hashlib.sha256(current_cache).hexdigest() == cache["sha256"]
        )
        if original_cache_matches:
            require(_matches_snapshot_metadata(bytecode, cache))
        else:
            info = bytecode.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid in {ROOT_UID, pwd.getpwnam("splunk").pw_uid}
                and stat.S_IMODE(info.st_mode) in {0o600, 0o640, 0o644}
            )
            _validate_pyc(bytecode, modified, transaction["modified_mtime"])
    _restore_snapshot(target, original, maximum=1_000_000)
    _restore_snapshot(bytecode, cache, maximum=2_000_000)
    for path, snapshot, maximum in (
        (target, original, 1_000_000),
        (bytecode, cache, 2_000_000),
    ):
        if snapshot is None:
            require(not os.path.lexists(path))
        else:
            actual = _platform_metadata(path)
            require(
                actual["sha256"] == snapshot["sha256"]
                and actual["uid"] == snapshot["uid"]
                and actual["gid"] == snapshot["gid"]
                and actual["mode"] == snapshot["mode"]
                and actual["mtime_ns"] == snapshot["mtime_ns"]
            )
    _fsync_directory(target.parent)
    if bytecode.parent.exists():
        _fsync_directory(bytecode.parent)
    HOOK_TRANSACTION.unlink()
    _fsync_directory(HOOK_BACKUP)
    HOOK_BACKUP.rmdir()
    return {
        "hook_removed": True,
        "hook_restored": True,
        "cache_restored": True,
        "fixture_hook_active": False,
        "hook_path": str(target),
        "original_source_sha256": original["sha256"] if original else None,
        "original_cache_sha256": cache["sha256"] if cache else None,
    }


def set_fault(mode, ident, generation):
    require(mode in MODES and generation in GENERATIONS)
    ident = "" if ident is None else ident
    require(isinstance(ident, str) and len(ident) <= 128)
    if mode in {"precommit", "postcommit"}:
        request_id(ident)
    _ensure_private_directory(CONTROL)
    config = CONTROL / "fault.json"
    if os.path.lexists(config):
        _read_regular(config, owner=os.getuid(), mode=0o600, maximum=4096)
    temp_path = CONTROL / f".fault.json.tmp-{os.getpid()}"
    payload = json.dumps(
        {"mode": mode, "request_id": ident, "generation": generation},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    fd = os.open(
        temp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp_path, config)
    directory_fd = os.open(str(CONTROL), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    info = config.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
    )
    return {"fault_written": True, "bytes": len(payload), "uid": info.st_uid}


def main():
    require(os.environ.get("ADM_CASE_REQUEST_NATIVE_TASK") == TASK)
    require(os.environ.get("SPLUNK_HOME") == "/opt/splunk")
    require(platform.system() == "Linux" and sys.platform.startswith("linux"))
    require(APP.is_dir() and APP.resolve() == APP)
    value = _read_json_input()
    action = value["action"]
    require(
        action
        in {
            "probe",
            "host_diagnostics",
            "request_diagnostics",
            "unit_setup",
            "seed_large",
            "case_state",
            "observe",
            "hook_install",
            "set_fault",
            "hook_remove",
        }
    )
    if action in {"hook_install", "hook_remove"}:
        require(os.getuid() == 0)
    else:
        require(os.getuid() != 0)
    if action == "probe":
        _exact_keys(value, {"action"})
        return probe()
    if action == "host_diagnostics":
        _exact_keys(value, {"action"})
        return host_diagnostics()
    if action == "request_diagnostics":
        _exact_keys(value, {"action"})
        return request_diagnostics()
    if action == "unit_setup":
        _exact_keys(value, {"action"})
        return unit_setup()
    if action == "seed_large":
        _exact_keys(value, {"action", "principal"})
        return seed_large(value["principal"])
    if action == "case_state":
        _exact_keys(value, {"action", "principal", "request_id"})
        return case_state(value["principal"], value["request_id"])
    if action == "observe":
        _exact_keys(value, {"action", "generation"})
        return observe(value["generation"])
    if action in {"hook_install", "hook_remove"}:
        _exact_keys(value, {"action", "expected_sha256"})
        return (
            hook_install(value["expected_sha256"])
            if action == "hook_install"
            else hook_remove(value["expected_sha256"])
        )
    _exact_keys(value, {"action", "mode", "request_id", "generation"})
    return set_fault(value["mode"], value["request_id"], value["generation"])


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True, separators=(",", ":")))
    except Exception as exc:
        import traceback

        frames = traceback.extract_tb(exc.__traceback__)
        print(
            json.dumps(
                {
                    "error": "native request fixture failed",
                    "error_type": type(exc).__name__,
                    "location": [
                        {
                            "file": Path(f.filename).name,
                            "line": f.lineno,
                            "function": f.name,
                        }
                        for f in frames[-4:]
                    ],
                }
            )
        )
        raise SystemExit(1)
