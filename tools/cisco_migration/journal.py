"""Durable migration journal and evidence-artifact persistence."""

from __future__ import annotations

import contextlib
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any
from .common import (
    JOURNAL_SCHEMA,
    MAX_JOURNAL_BYTES,
    Refused,
    canonical,
    ensure_state_directory,
)


class Journal:
    def __init__(self, path: Path):
        self.path = Path(path).expanduser()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    @contextmanager
    def locked(self, *, blocking: bool = True):
        ensure_state_directory(self.path.parent)
        try:
            fd = os.open(
                self.lock_path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as error:
            raise Refused(
                f"journal lock {self.lock_path} is unavailable: "
                f"{error.strerror or error}"
            ) from None
        try:
            try:
                if os.fstat(fd).st_uid != os.geteuid():
                    raise Refused("journal lock file is owned by another user")
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                    raise Refused("journal lock must be an owner-only regular file")
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except OSError as error:
                raise Refused(
                    f"journal lock {self.lock_path} is unavailable: "
                    f"{error.strerror or error}"
                ) from None
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def read(self) -> dict[str, Any] | None:
        try:
            fd = os.open(
                self.path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise Refused(
                "journal must be a regular owner-only file owned by the current user"
            ) from None
        try:
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise Refused(
                        "journal must be a regular owner-only file owned by the "
                        "current user"
                    )
                if info.st_size > MAX_JOURNAL_BYTES:
                    raise Refused("journal exceeds the 16 MiB limit")
                raw = stream.read(MAX_JOURNAL_BYTES + 1)
            if len(raw) > MAX_JOURNAL_BYTES:
                raise Refused("journal exceeds the 16 MiB limit")
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise Refused("journal is unreadable or corrupt") from None
        if not isinstance(value, dict) or value.get("schema") != JOURNAL_SCHEMA:
            raise Refused("journal schema is unsupported")
        return value

    def write(self, value: dict[str, Any]) -> None:
        payload = canonical(value)
        if len(payload) > MAX_JOURNAL_BYTES:
            raise Refused("journal exceeds the 16 MiB limit")
        self._atomic_write(self.path, payload, "journal")

    @staticmethod
    def _atomic_write(
        path: Path, payload: bytes, label: str, prefix: str = ".cisco-contract-"
    ) -> None:
        name = None
        try:
            fd, name = tempfile.mkstemp(prefix=prefix, dir=path.parent)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as error:
            raise Refused(
                f"{label} {path} could not be written: {error.strerror or error}"
            ) from None
        finally:
            if name is not None:
                with contextlib.suppress(OSError):
                    if os.path.exists(name):
                        os.unlink(name)

    @staticmethod
    def write_artifact(path: Path, value: dict[str, Any]) -> str:
        path = Path(path)
        ensure_state_directory(path.parent)
        payload = canonical(value)
        Journal._atomic_write(path, payload, "artifact", ".cisco-candidate-")
        return hashlib.sha256(payload).hexdigest()
