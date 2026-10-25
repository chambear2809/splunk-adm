"""Cooperative cross-worktree lock for the local Splunk lab.

The lock coordinates lab entry points only; direct Docker commands can still
bypass it.  Ownership is inherited by child processes through environment
variables because lab subprocesses do not preserve an open lock descriptor.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, Iterator, Sequence

try:
    import fcntl
except ImportError as exc:  # pragma: no cover - the supported hosts are Unix.
    raise RuntimeError("the lab lock requires a Unix flock implementation") from exc


ENV_TOKEN = "SPLUNK_ADM_LAB_LOCK_TOKEN"
ENV_PATH = "SPLUNK_ADM_LAB_LOCK_PATH"
ENV_PID = "SPLUNK_ADM_LAB_LOCK_PID"


class LabLockError(RuntimeError):
    """Raised when another process owns the lab lock."""


def default_lock_path(_root: str | os.PathLike[str]) -> Path:
    """Coordinate each named lab across checkouts, retaining the default lock."""

    name = os.environ.get("ADM_LAB_NAME", "adm-splunk-lab")
    if not re.fullmatch(r"adm-[a-z0-9-]+", name):
        raise LabLockError("invalid lab container name")
    # Named labs must also use distinct ports/secrets. The same container name
    # still shares a lock across clones; unnamed callers retain the legacy key.
    suffix = "" if name == "adm-splunk-lab" else f"-{name}"
    return Path("/tmp") / f"splunk-adm-lab-{os.getuid()}{suffix}.lock"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class LabLock:
    """An exclusive, non-blocking cooperative lab lock."""

    def __init__(self, root: str | os.PathLike[str] | None = None, *, path=None):
        self.path = (
            Path(path) if path is not None else default_lock_path(root or Path.cwd())
        )
        self._file = None
        self._token = None
        self._inherited = False
        self._previous_env = {
            key: os.environ.get(key) for key in (ENV_TOKEN, ENV_PATH, ENV_PID)
        }

    def _metadata(self) -> dict:
        try:
            self._file.seek(0)
            value = json.loads(self._file.read() or "{}")
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _open_safe(self):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
            ):
                os.close(fd)
                raise LabLockError(f"unsafe lab lock file: {self.path}")
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, "a+", encoding="utf-8")
        except LabLockError:
            raise
        except OSError as exc:
            raise LabLockError(f"unsafe lab lock file: {self.path}") from exc

    def _is_inherited_owner(self) -> bool:
        token = os.environ.get(ENV_TOKEN)
        path = os.environ.get(ENV_PATH)
        try:
            pid = int(os.environ.get(ENV_PID, ""))
        except ValueError:
            return False
        if not token or path != str(self.path) or not _pid_alive(pid):
            return False
        try:
            with self._open_safe() as metadata_file:
                metadata_file.seek(0)
                metadata = json.load(metadata_file)
        except (OSError, ValueError, TypeError):
            return False
        if (
            not isinstance(metadata, dict)
            or metadata.get("token") != token
            or metadata.get("pid") != pid
        ):
            return False
        try:
            with self._open_safe() as probe:
                fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
        except BlockingIOError:
            return True
        except OSError:
            return False
        return False

    def check_owned(self) -> bool:
        """Return whether inherited environment identifies the live owner."""

        return self._is_inherited_owner()

    def acquire(self) -> "LabLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._open_safe()
        if self._is_inherited_owner():
            self._inherited = True
            return self
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            metadata = self._metadata()
            self._file.close()
            self._file = None
            owner = metadata.get("pid", "another process")
            raise LabLockError(
                f"Splunk lab is already locked by process {owner} ({self.path})"
            ) from exc
        self._token = uuid.uuid4().hex
        self._file.seek(0)
        self._file.truncate()
        json.dump({"pid": os.getpid(), "token": self._token}, self._file)
        self._file.flush()
        os.fsync(self._file.fileno())
        os.environ.update(
            {
                ENV_TOKEN: self._token,
                ENV_PATH: str(self.path),
                ENV_PID: str(os.getpid()),
            }
        )
        return self

    def release(self) -> None:
        if self._file is None:
            return
        if self._inherited:
            self._file.close()
            self._file = None
            return
        try:
            self._file.seek(0)
            self._file.truncate()
            self._file.flush()
            fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None
            for key, value in self._previous_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def __enter__(self) -> "LabLock":
        return self.acquire()

    def __exit__(self, *_args) -> None:
        self.release()


@contextlib.contextmanager
def exclusive_lab_lock(root=None, *, path=None) -> Iterator[LabLock]:
    with LabLock(root, path=path) as lock:
        yield lock


def with_lab_lock(function=None, *, root=None, path=None):
    """Decorator form of :func:`exclusive_lab_lock`."""

    def decorate(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            with exclusive_lab_lock(root, path=path):
                return func(*args, **kwargs)

        return wrapped

    return decorate(function) if function is not None else decorate


def run_locked(command: Sequence[str], *, root=None, path=None) -> int:
    """Run a command while holding the lab lock, inheriting ownership env."""

    with exclusive_lab_lock(root, path=path) as lock:
        if lock._inherited:
            return subprocess.call(list(command))
        child = subprocess.Popen(list(command), start_new_session=True)
        cancelled_at = None
        received_signal = None

        def forward(signum, _frame):
            nonlocal cancelled_at, received_signal
            if cancelled_at is None:
                cancelled_at = time.monotonic()
                received_signal = signum
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signum)
                except (ProcessLookupError, PermissionError):
                    pass

        old_handlers = {
            signum: signal.signal(signum, forward)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        }
        try:
            while True:
                if cancelled_at is not None and (
                    child.poll() is not None or time.monotonic() - cancelled_at >= 5
                ):
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    break
                if child.poll() is not None:
                    break
                try:
                    # A finite timeout lets runtimes that restart wait(2) after
                    # EINTR observe that a signal handler requested shutdown.
                    child.wait(timeout=0.1)
                except (InterruptedError, subprocess.TimeoutExpired):
                    continue
        finally:
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
            if cancelled_at is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                time.sleep(0.05)
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            else:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                child.wait()
            if child.poll() is None:
                child.wait()
        if cancelled_at is not None:
            return 128 + (received_signal or signal.SIGTERM)
        return child.returncode


def run_main(main: Callable[[], int], *, root=None, path=None) -> int:
    """Run a CLI main under supervision, or directly for an owned child."""

    if LabLock(root, path=path).check_owned():
        return main()
    try:
        return run_locked(
            [sys.executable, sys.argv[0], *sys.argv[1:]], root=root, path=path
        )
    except LabLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 75


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--check-owned", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.check_owned:
        return 0 if LabLock(args.root).check_owned() else 1
    command = list(args.command)
    if command[:1] == ["--"]:
        command.pop(0)
    if not command:
        parser.error("a command is required after --")
    try:
        return run_locked(command, root=args.root)
    except LabLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
