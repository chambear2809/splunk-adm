"""Private bounded retained-artifact reader; no collector or grants are implied."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .executor import Unavailable
from .store import _json

MAX_RECORD = 2_500_000


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


class RetainedArtifacts:
    """Read immutable digest-addressed records from an owner-private directory.

    authorize is a reviewed current-source entitlement function, not an artifact
    ACL. No such production entitlement function is shipped.
    """

    def __init__(self, directory, authorize, verify_evidence):
        self.directory = Path(directory)
        self.authorize = authorize
        self.verify_evidence = verify_evidence
        if (
            not callable(authorize)
            or not callable(verify_evidence)
            or not self.directory.is_absolute()
        ):
            raise Unavailable("artifact authority unavailable")

    def _read(self, name, limit):
        fd = None
        try:
            directory = self.directory.lstat()
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != os.getuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
            ):
                raise ValueError("unsafe directory")
            fd = os.open(
                self.directory / name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size > limit
            ):
                raise ValueError("unsafe artifact")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("oversized artifact")
            return json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("invalid number")
                ),
            )
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            raise Unavailable("artifact unavailable") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def lookup(self, principal, selection, window):
        # An index is a hint only. The provider independently verifies both.
        key = hashlib.sha256(_json([selection, window]).encode()).hexdigest()
        entry = self._read("index-" + key + ".json", 256)
        if not isinstance(entry, dict) or set(entry) != {"reference"}:
            raise Unavailable("artifact index unavailable")
        return entry["reference"]

    def read(self, reference):
        if not isinstance(reference, str) or not re.fullmatch(
            r"[0-9a-f]{64}", reference
        ):
            raise Unavailable("invalid artifact reference")
        record = self._read(reference + ".json", MAX_RECORD)
        try:
            content = {
                "capture": record["capture"],
                "provenance": dict(record["provenance"]),
            }
            del content["provenance"]["reference"]
            if hashlib.sha256(_json(content).encode()).hexdigest() != reference:
                raise ValueError("artifact digest mismatch")
        except (TypeError, KeyError, ValueError) as exc:
            raise Unavailable("invalid artifact") from exc
        return record
