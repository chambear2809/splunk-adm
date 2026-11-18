"""Disposable lab-only, opt-in request fault hook (installed as sitecustomize)."""

import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time

CONTROL_DIR = Path("/tmp/adm-cases-requests-20261118")
CONFIG = CONTROL_DIR / "fault.json"
DATABASE = "/opt/splunk/var/lib/splunk/splunk_adm_investigations/cases.sqlite"
WORKER = "/opt/splunk/etc/apps/splunk_adm/bin/adm_cases_lib/request_worker.py"
MODES = {"auth", "config", "diagnostic", "precommit", "postcommit", "off"}
GENERATIONS = {
    "auth",
    "config",
    "diagnostic",
    "precommit",
    "postcommit",
    "disconnect",
}
DIAGNOSTIC_PHASES = {
    "qualify",
    "configuration",
    "topology",
    "request-current-context",
    "request-server-info",
    "request-other",
}
_CHILD_CODE = (
    "import os,signal,sys,time; "
    "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
    "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); "
    "os.write(fd,b'ready'); os.fsync(fd); os.close(fd); time.sleep(60)"
)


class _InvalidConfig(Exception):
    """A present but unsafe or malformed private control file."""


def _read_config():
    """Read the fixed private file; absence is safe, present invalid input is not."""
    try:
        directory = CONTROL_DIR.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _InvalidConfig from exc
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.getuid()
        or stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise _InvalidConfig
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(CONFIG), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _InvalidConfig from exc
    try:
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > 4096
            ):
                raise _InvalidConfig
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        if len(raw) > 4096:
            raise _InvalidConfig
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
            "mode",
            "request_id",
            "generation",
        }:
            raise _InvalidConfig
        mode, request_id, generation = (
            value["mode"],
            value["request_id"],
            value["generation"],
        )
        if mode not in MODES or generation not in GENERATIONS:
            raise _InvalidConfig
        if not isinstance(request_id, str) or len(request_id) > 128:
            raise _InvalidConfig
        if mode in {"precommit", "postcommit"} and not request_id:
            raise _InvalidConfig
        return value
    except _InvalidConfig:
        raise
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise _InvalidConfig from exc


def _stall(generation):
    """Launch a fixed benign same-group child and stall the worker leader."""
    marker = CONTROL_DIR / ("marker-" + generation + ".json")
    ready = CONTROL_DIR / ("ready-" + generation)
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD_CODE, str(ready)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            **{
                key: os.environ[key]
                for key in ("LANG", "LD_LIBRARY_PATH")
                if key in os.environ
            },
        },
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            ready_stat = ready.lstat()
        except FileNotFoundError:
            if child.poll() is not None:
                raise RuntimeError("fault child failed readiness")
            time.sleep(0.01)
            continue
        if (
            not stat.S_ISREG(ready_stat.st_mode)
            or ready_stat.st_uid != os.getuid()
            or stat.S_IMODE(ready_stat.st_mode) != 0o600
            or ready_stat.st_nlink != 1
            or ready_stat.st_size != 5
        ):
            raise RuntimeError("fault child readiness invalid")
        ready_fd = os.open(str(ready), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if os.read(ready_fd, 6) != b"ready":
                raise RuntimeError("fault child readiness invalid")
        finally:
            os.close(ready_fd)
        break
    else:
        raise RuntimeError("fault child readiness timed out")
    payload = json.dumps(
        {
            "phase": generation,
            "pid": os.getpid(),
            "pgid": os.getpgrp(),
            "child_pid": child.pid,
        },
        separators=(",", ":"),
    ).encode("ascii")
    fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(str(CONTROL_DIR), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    time.sleep(60)


def _target_path(args, kwargs):
    value = args[0] if args else kwargs.get("uri")
    return value if isinstance(value, str) else ""


def _record_diagnostic(phase, error_type=None, frames=None):
    if phase not in DIAGNOSTIC_PHASES:
        raise RuntimeError("invalid diagnostic phase")
    value = {"phase": phase, "status": "error" if error_type else "ok"}
    if error_type:
        value["error_type"] = error_type
        value["frames"] = frames or []
    path = CONTROL_DIR / f"diagnostic-{os.getpid()}-{phase}.json"
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(
        str(CONTROL_DIR), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _patch(config, modules=None):
    """Patch only requested targets. modules is a trusted unit-test seam."""
    if not config or config["mode"] == "off":
        return
    mode, generation = config["mode"], config["generation"]
    if mode == "auth":
        try:
            rest = (
                modules["rest"]
                if modules
                else __import__("splunk.rest", fromlist=["simpleRequest"])
            )
            original = rest.simpleRequest
        except (ImportError, AttributeError, KeyError):
            return

        def simple_request(*args, **kwargs):
            if (
                _target_path(args, kwargs).split("?", 1)[0]
                == "/services/authentication/current-context"
            ):
                _stall(generation)
            return original(*args, **kwargs)

        rest.simpleRequest = simple_request
    elif mode == "config":
        original = subprocess.run

        def run(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            if (
                isinstance(command, (list, tuple))
                and len(command) == 7
                and tuple(command[1:])
                == (
                    "btool",
                    "--app=splunk_adm",
                    "--user=nobody",
                    "adm_investigations",
                    "list",
                    "persistence",
                )
            ):
                _stall(generation)
            return original(*args, **kwargs)

        subprocess.run = run
    elif mode == "diagnostic":
        sys.path.insert(0, "/opt/splunk/etc/apps/splunk_adm/bin")
        from adm_cases_lib.splunk_host import SplunkHost

        def wrap(name, original):
            def call(*args, **kwargs):
                try:
                    return original(*args, **kwargs)
                except Exception as exc:
                    from traceback import extract_tb

                    frames = [
                        {
                            "file": Path(frame.filename).name,
                            "line": frame.lineno,
                            "function": frame.name,
                        }
                        for frame in extract_tb(exc.__traceback__)[-4:]
                    ]
                    _record_diagnostic(name, type(exc).__name__, frames)
                    raise

            return call

        original_qualify = SplunkHost.qualify
        original_configuration = SplunkHost._configuration
        original_topology = SplunkHost._topology
        original_request = SplunkHost._request

        def request(host, path):
            name = {
                "/services/authentication/current-context": "request-current-context",
                "/services/server/info": "request-server-info",
            }.get(path, "request-other")
            return wrap(name, original_request)(host, path)

        def qualify(host):
            try:
                result = original_qualify(host)
            except Exception as exc:
                from traceback import extract_tb

                frames = [
                    {
                        "file": Path(frame.filename).name,
                        "line": frame.lineno,
                        "function": frame.name,
                    }
                    for frame in extract_tb(exc.__traceback__)[-4:]
                ]
                _record_diagnostic("qualify", type(exc).__name__, frames)
                raise
            _record_diagnostic("qualify")
            return result

        SplunkHost._configuration = staticmethod(
            wrap("configuration", original_configuration)
        )
        SplunkHost._topology = staticmethod(wrap("topology", original_topology))
        SplunkHost._request = request
        SplunkHost.qualify = qualify
    elif mode in {"precommit", "postcommit"}:
        original_connect = sqlite3.connect
        request_id = config["request_id"]
        real = modules.get("sqlite3", sqlite3) if modules else sqlite3
        base = real.Connection

        class FaultConnection(base):
            def commit(self):
                trigger = False
                if self.in_transaction:
                    try:
                        row = self.execute(
                            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'"
                        ).fetchone()
                        if row:
                            trigger = (
                                self.execute(
                                    "SELECT 1 FROM requests WHERE request_id=? LIMIT 1",
                                    (request_id,),
                                ).fetchone()
                                is not None
                            )
                    except sqlite3.Error:
                        trigger = False
                if trigger and mode == "precommit":
                    _stall(generation)
                result = super().commit()
                if trigger and mode == "postcommit":
                    _stall(generation)
                return result

        def connect(database, *args, **kwargs):
            if os.fspath(database) == DATABASE:
                kwargs["factory"] = FaultConnection
            return original_connect(database, *args, **kwargs)

        real.connect = connect


def _activate():
    if sys.argv and sys.argv[0] == WORKER:
        try:
            _patch(_read_config())
        except _InvalidConfig:
            os._exit(78)


if __name__ == "sitecustomize":
    _activate()
