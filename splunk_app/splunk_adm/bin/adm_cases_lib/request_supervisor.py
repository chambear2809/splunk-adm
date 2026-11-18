"""Bound case work in a disposable child; never cache caller credentials.

The operational deadline covers worker execution and IPC, not an OS guarantee
against an uninterruptible process launch or kernel operation. Source transport
limits remain independent. A failed retirement closes process-wide admission.
"""

import ctypes
import json
import os
from pathlib import Path
import selectors
import resource
import signal
import stat
import subprocess
import sys
import threading
import time

from .transport import _worker_environment

MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
REQUEST_SECONDS = 40.0
RETIRE_SECONDS = 1.0
_slot = threading.BoundedSemaphore(1)
_poisoned = False
_prepared = False
_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
}


def unavailable():
    return {
        "status": 503,
        "payload": {
            "code": "unavailable",
            "error": "Investigation request is unavailable. Retry the same pending operation.",
        },
        "headers": dict(_HEADERS),
    }


def _prepare_parent():
    global _prepared
    if _prepared:
        return
    if sys.platform != "linux":
        raise RuntimeError("Linux request child reaping required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Adopt and reap only the retired request group's orphan descendants.
    # Without this, an image's PID1 could retain their zombies indefinitely.
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int()
    if (
        libc.prctl(36, 1, 0, 0, 0) != 0
        or libc.prctl(37, ctypes.byref(value), 0, 0, 0) != 0
        or value.value != 1
    ):
        raise RuntimeError("request child reaping unavailable")
    _prepared = True


def _environment():
    environment = _worker_environment()
    for key in ("SPLUNK_HOME", "SPLUNK_DB"):
        path = Path(os.environ.get(key, ""))
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise RuntimeError("fixed runtime directory unavailable")
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (0, os.getuid())
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise RuntimeError("unsafe runtime directory")
        environment[key] = str(path)
    return environment


def _retire(process):
    """Final signals precede every wait/poll, so the leader pins its PGID."""
    deadline = time.monotonic() + RETIRE_SECONDS
    for stream in (process.stdin, process.stdout):
        try:
            stream.close()
        except (OSError, ValueError):
            pass
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        if sig == signal.SIGTERM:
            time.sleep(0.025)
    try:
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        return False
    while time.monotonic() < deadline:
        # Never signal after reaping the leader: the PGID may subsequently recycle.
        try:
            while os.waitpid(-process.pid, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        time.sleep(0.01)
    return False


def _exchange(process, raw, deadline):
    output = bytearray()
    expected = None
    sent = 0
    os.set_blocking(process.stdin.fileno(), False)
    os.set_blocking(process.stdout.fileno(), False)
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            events = selector.select(remaining)
            if not events:
                raise TimeoutError()
            for key, _ in events:
                if key.fileobj is process.stdin:
                    try:
                        count = os.write(process.stdin.fileno(), raw[sent:])
                    except BlockingIOError:
                        continue
                    if count <= 0:
                        raise RuntimeError("input closed")
                    sent += count
                    if sent == len(raw):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                else:
                    try:
                        chunk = os.read(process.stdout.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        raise RuntimeError("incomplete worker response")
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT + 4:
                        raise RuntimeError("worker response too large")
                    if expected is None and len(output) >= 4:
                        expected = int.from_bytes(output[:4], "big")
                        if not 0 < expected <= MAX_OUTPUT:
                            raise RuntimeError("invalid response frame")
                    if expected is not None and len(output) >= expected + 4:
                        if len(output) != expected + 4 or sent != len(raw):
                            raise RuntimeError("invalid response frame")
                        return bytes(output[4:])


def supervise(in_string, *, _worker_path=None, _timeout=REQUEST_SECONDS, _env=None):
    """Fixed entrypoint. Underscored injection arguments are trusted unit seams."""
    global _poisoned
    started = time.monotonic()
    if not isinstance(in_string, (str, bytes)):
        return unavailable()
    if len(in_string) > MAX_INPUT:
        return {**unavailable(), "status": 413, "payload": {"error": "body_too_large"}}
    try:
        raw = in_string.encode("utf-8") if isinstance(in_string, str) else in_string
    except UnicodeError:
        return unavailable()
    if len(raw) > MAX_INPUT:
        return {**unavailable(), "status": 413, "payload": {"error": "body_too_large"}}
    if not raw or _poisoned or not _slot.acquire(blocking=False):
        return unavailable()
    process, retired, output = None, True, None
    deadline = started + _timeout
    try:
        _prepare_parent()
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                str(_worker_path or Path(__file__).with_name("request_worker.py")),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_environment() if _env is None else _env,
            start_new_session=True,
            close_fds=True,
        )
        retired = False
        output = _exchange(process, raw, deadline)
    except Exception:
        output = None
    finally:
        if process is not None:
            try:
                retired = _retire(process)
            except Exception:
                retired = False
        if retired:
            _slot.release()
        else:
            _poisoned = True
    if output is None or not retired or time.monotonic() >= deadline:
        return unavailable()
    try:
        result = json.loads(output)
        if (
            not isinstance(result, dict)
            or set(result) != {"status", "payload", "headers"}
            or type(result["status"]) is not int
            or not 200 <= result["status"] <= 599
            or not isinstance(result["payload"], dict)
            or not isinstance(result["headers"], dict)
            or set(result["headers"]) - set(_HEADERS)
            or any(_HEADERS.get(k) != v for k, v in result["headers"].items())
        ):
            return unavailable()
        if time.monotonic() >= deadline:
            return unavailable()
        return {**result, "headers": dict(_HEADERS)}
    except (ValueError, TypeError, RecursionError):
        return unavailable()
