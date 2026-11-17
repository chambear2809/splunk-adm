"""Private durable watch execution metadata; no source data or credentials.

The trusted executor is responsible for current administrator, owner and source
checks. The journal never interprets lease expiry as proof of remote noncommit.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid
from contextlib import closing

from .store import Conflict, Forbidden, Invalid, NotFound, QuotaExceeded

_TERMINAL = {"committed", "rejected"}
_OPEN = {"intent", "capture_unknown", "prepared", "evaluation_unknown"}
_ALLOWED = {
    "intent": {"capture_unknown", "prepared", "rejected"},
    "prepared": {"evaluation_unknown", "rejected"},
    "evaluation_unknown": {"evaluation_unknown", "committed", "rejected"},
}


def _text(value, limit=256):
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > limit
        or not value.isprintable()
    ):
        raise Invalid("invalid text")
    return value


def _canonical(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise Invalid("invalid data") from exc


def _id(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
    ):
        raise Invalid("invalid id")
    return value


def _owner(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32,64}", value):
        raise Invalid("invalid lease owner")


def _revision(value):
    if type(value) is not int or value < 1:
        raise Invalid("invalid revision")


def _window(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"start", "end"}
        or any(type(value[k]) is not int for k in value)
        or not 0 <= value["start"] < value["end"] <= 253402300799
        or value["end"] - value["start"] > 300
    ):
        raise Invalid("invalid window")


def _definition(value):
    if not isinstance(value, dict) or set(value) != {
        "baselineId",
        "watchId",
        "baselineVersion",
        "principal",
        "selection",
        "providerContractRevision",
    }:
        raise Invalid("invalid binding")
    _id(value["baselineId"])
    _text(value["watchId"], 128)
    _revision(value["baselineVersion"])
    _text(value["principal"])
    _text(value["providerContractRevision"])
    selection = value["selection"]
    if not isinstance(selection, dict) or set(selection) != {
        "service",
        "environment",
        "cluster",
        "namespace",
    }:
        raise Invalid("invalid selection")
    for text in selection.values():
        _text(text)
    return _canonical(value)


def _safe_path(path):
    try:
        path = Path(path)
        if (
            not path.is_absolute()
            or path.name != "watch_runs.sqlite"
            or path.parent.is_symlink()
        ):
            raise ValueError
        info = path.parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError
        return path
    except (OSError, ValueError, TypeError) as exc:
        raise Invalid("invalid journal location") from exc


def _secure_file(path):
    fd = None
    try:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            os.fchmod(fd, 0o600)
        except FileExistsError:
            fd = os.open(path, flags)
        current, entry = os.fstat(fd), path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino)
        ):
            raise Invalid("unsafe journal file")
    except OSError as exc:
        raise Invalid("unsafe journal file") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _check_sidecars(path):
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        try:
            entry = sidecar.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise Invalid("unsafe journal sidecar") from exc
        fd = None
        try:
            fd = os.open(
                sidecar,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            current = os.fstat(fd)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.getuid()
                or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino)
            ):
                raise Invalid("unsafe journal sidecar")
            if suffix in ("-wal", "-shm"):
                raise Invalid("unsupported WAL journal")
        except OSError as exc:
            raise Invalid("unsafe journal sidecar") from exc
        finally:
            if fd is not None:
                os.close(fd)


class ExecutionStore:
    def __init__(
        self,
        path,
        clock=time.time,
        max_open=3,
        max_runs=128,
        max_bindings=100,
        lease_seconds=60,
    ):
        if not callable(clock) or any(
            type(value) is not int or not 1 <= value <= maximum
            for value, maximum in (
                (max_open, 3),
                (max_runs, 128),
                (max_bindings, 100),
                (lease_seconds, 60),
            )
        ):
            raise ValueError("invalid journal configuration")
        self.path = _safe_path(path)
        self.clock = clock
        self.max_open, self.max_runs, self.max_bindings, self.lease_seconds = (
            max_open,
            max_runs,
            max_bindings,
            lease_seconds,
        )
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1):
                    raise Invalid("unsupported journal schema")
                if (
                    version == 0
                    and db.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
                    ).fetchone()
                ):
                    raise Invalid("unversioned journal schema")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS bindings (id TEXT PRIMARY KEY, definition TEXT NOT NULL, fingerprint TEXT NOT NULL, revision INTEGER NOT NULL, enabled INTEGER NOT NULL)"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, principal TEXT NOT NULL, request_id TEXT NOT NULL, binding_id TEXT NOT NULL REFERENCES bindings(id), fingerprint TEXT NOT NULL, binding_revision INTEGER NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, lease_owner TEXT, lease_until REAL, reference TEXT, baseline_revision INTEGER, evaluation_key TEXT, capture_digest TEXT, receipt TEXT, UNIQUE(principal,request_id), UNIQUE(binding_id,window_start,window_end))"
                )
                if not {"capture_digest", "binding_revision"} <= {
                    column[1] for column in db.execute("PRAGMA table_info(runs)")
                }:
                    raise Invalid("unsupported journal schema")
                db.execute("PRAGMA user_version=1")
                db.commit()
            except Exception:
                db.rollback()
                raise

    def _connect(self):
        _safe_path(self.path)
        _secure_file(self.path)
        _check_sidecars(self.path)
        db = sqlite3.connect(self.path, timeout=0.1, isolation_level=None)
        try:
            if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
                raise Invalid("unsupported journal mode")
        except Exception:
            db.close()
            raise
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _now(self):
        try:
            now = self.clock()
        except Exception as exc:
            raise Invalid("clock unavailable") from exc
        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
            or not 0 <= now <= 253402300739
        ):
            raise Invalid("invalid clock")
        return float(now)

    @staticmethod
    def _binding(db, ident):
        row = db.execute("SELECT * FROM bindings WHERE id=?", (ident,)).fetchone()
        if not row:
            raise NotFound("binding not found")
        return row

    @staticmethod
    def _binding_record(row):
        return {
            "id": row["id"],
            "definition": json.loads(row["definition"]),
            "fingerprint": row["fingerprint"],
            "revision": row["revision"],
            "enabled": bool(row["enabled"]),
        }

    @staticmethod
    def _run(db, ident, principal):
        row = db.execute(
            "SELECT * FROM runs WHERE id=? AND principal=?", (ident, principal)
        ).fetchone()
        if not row:
            raise NotFound("run not found")
        return row

    @staticmethod
    def _run_record(row):
        return {
            "id": row["id"],
            "principal": row["principal"],
            "requestId": row["request_id"],
            "bindingId": row["binding_id"],
            "bindingRevision": row["binding_revision"],
            "fingerprint": row["fingerprint"],
            "window": {"start": row["window_start"], "end": row["window_end"]},
            "state": row["state"],
            "revision": row["revision"],
            "leaseOwner": row["lease_owner"],
            "leaseUntil": row["lease_until"],
            "reference": row["reference"],
            "baselineRevision": row["baseline_revision"],
            "evaluationKey": row["evaluation_key"],
            "captureDigest": row["capture_digest"],
            "receipt": json.loads(row["receipt"]) if row["receipt"] else None,
        }

    def create_binding(self, definition):
        encoded = _definition(definition)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        ident = str(uuid.uuid4())
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            if (
                db.execute("SELECT count(*) FROM bindings").fetchone()[0]
                >= self.max_bindings
            ):
                raise QuotaExceeded("binding capacity exhausted")
            db.execute(
                "INSERT INTO bindings VALUES (?,?,?,1,0)", (ident, encoded, digest)
            )
            row = self._binding(db, ident)
            db.commit()
        return self._binding_record(row)

    def binding(self, ident):
        _id(ident)
        with closing(self._connect()) as db:
            return self._binding_record(self._binding(db, ident))

    def set_enabled(self, ident, expected_revision, enabled):
        _id(ident)
        _revision(expected_revision)
        if type(enabled) is not bool:
            raise Invalid("invalid enabled state")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._binding(db, ident)
            if row["revision"] != expected_revision:
                raise Conflict("binding revision changed")
            if bool(row["enabled"]) != enabled:
                db.execute(
                    "UPDATE bindings SET enabled=?,revision=revision+1 WHERE id=?",
                    (enabled, ident),
                )
            result = self._binding_record(self._binding(db, ident))
            db.commit()
        return result

    def begin(
        self,
        principal,
        request_id,
        binding_id,
        window,
        lease_owner,
        *,
        expected_binding_revision=None,
    ):
        _text(principal)
        _text(request_id, 128)
        _id(binding_id)
        _window(window)
        _owner(lease_owner)
        if expected_binding_revision is not None:
            _revision(expected_binding_revision)
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            binding = self._binding(db, binding_id)
            if (
                expected_binding_revision is not None
                and binding["revision"] != expected_binding_revision
            ):
                raise Conflict("binding revision changed")
            if json.loads(binding["definition"])["principal"] != principal:
                raise Forbidden("binding principal mismatch")
            old = db.execute(
                "SELECT * FROM runs WHERE principal=? AND request_id=?",
                (principal, request_id),
            ).fetchone()
            if old:
                if (
                    old["binding_id"] != binding_id
                    or old["fingerprint"] != binding["fingerprint"]
                    or old["binding_revision"] != binding["revision"]
                    or (old["window_start"], old["window_end"])
                    != (window["start"], window["end"])
                ):
                    raise Conflict("request differs")
                if old["state"] in _TERMINAL or old["state"] == "capture_unknown":
                    db.commit()
                    return self._run_record(old)
                if not binding["enabled"]:
                    raise Forbidden("binding disabled")
                if old["lease_owner"] and old["lease_until"] > now:
                    if old["lease_owner"] != lease_owner:
                        raise Conflict("lease held")
                    db.commit()
                    return self._run_record(old)
                if old["state"] == "intent":
                    db.execute(
                        "UPDATE runs SET state='capture_unknown',revision=revision+1,lease_owner=NULL,lease_until=NULL WHERE id=?",
                        (old["id"],),
                    )
                else:
                    db.execute(
                        "UPDATE runs SET revision=revision+1,lease_owner=?,lease_until=? WHERE id=?",
                        (lease_owner, now + self.lease_seconds, old["id"]),
                    )
                result = self._run_record(self._run(db, old["id"], principal))
                db.commit()
                return result
            if not binding["enabled"]:
                raise Forbidden("binding disabled")
            if db.execute(
                "SELECT 1 FROM runs WHERE binding_id=? AND window_start=? AND window_end=?",
                (binding_id, window["start"], window["end"]),
            ).fetchone():
                raise Conflict("window already reserved")
            if (
                db.execute("SELECT count(*) FROM runs").fetchone()[0] >= self.max_runs
                or db.execute(
                    "SELECT count(*) FROM runs WHERE state NOT IN ('committed','rejected')"
                ).fetchone()[0]
                >= self.max_open
            ):
                raise QuotaExceeded("run capacity exhausted")
            ident = str(uuid.uuid4())
            db.execute(
                "INSERT INTO runs(id,principal,request_id,binding_id,fingerprint,binding_revision,window_start,window_end,state,revision,lease_owner,lease_until) VALUES (?,?,?,?,?,?,?,?,'intent',1,?,?)",
                (
                    ident,
                    principal,
                    request_id,
                    binding_id,
                    binding["fingerprint"],
                    binding["revision"],
                    window["start"],
                    window["end"],
                    lease_owner,
                    now + self.lease_seconds,
                ),
            )
            result = self._run_record(self._run(db, ident, principal))
            db.commit()
        return result

    def transition(
        self,
        run_id,
        principal,
        lease_owner,
        expected_revision,
        state,
        *,
        binding_revision=None,
        **data,
    ):
        _id(run_id)
        _text(principal)
        _owner(lease_owner)
        _revision(expected_revision)
        if binding_revision is not None:
            _revision(binding_revision)
        if state not in _OPEN | _TERMINAL:
            raise Invalid("invalid state")
        if state == "prepared":
            if set(data) != {
                "reference",
                "baselineRevision",
                "evaluationKey",
                "captureDigest",
            }:
                raise Invalid("invalid prepared data")
            _text(data["reference"], 4096)
            _revision(data["baselineRevision"])
            _text(data["evaluationKey"], 128)
            if not isinstance(data["captureDigest"], str) or not re.fullmatch(
                r"[0-9a-f]{64}", data["captureDigest"]
            ):
                raise Invalid("invalid capture digest")
        elif state == "committed":
            if (
                set(data) != {"receipt"}
                or not isinstance(data["receipt"], dict)
                or set(data["receipt"]) != {"id", "revision", "resultWithheld"}
                or data["receipt"]["resultWithheld"] is not True
            ):
                raise Invalid("invalid receipt")
            _id(data["receipt"]["id"])
            _revision(data["receipt"]["revision"])
        elif data:
            raise Invalid("invalid transition data")
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._run(db, run_id, principal)
            if (
                row["revision"] != expected_revision
                or row["lease_owner"] != lease_owner
                or row["lease_until"] is None
                or now >= row["lease_until"]
            ):
                raise Conflict("lease or revision changed")
            if state not in _ALLOWED.get(row["state"], set()):
                raise Conflict("invalid state transition")
            binding = self._binding(db, row["binding_id"])
            if state in {"prepared", "evaluation_unknown"}:
                if not binding["enabled"]:
                    raise Forbidden("binding disabled")
                if binding["revision"] != row["binding_revision"] or (
                    binding_revision is not None
                    and binding["revision"] != binding_revision
                ):
                    raise Conflict("binding revision changed")
            if (
                state == "committed"
                and data["receipt"]["id"]
                != json.loads(binding["definition"])["baselineId"]
            ):
                raise Invalid("receipt baseline mismatch")
            release = state in _TERMINAL or state == "capture_unknown"
            db.execute(
                "UPDATE runs SET state=?,revision=revision+1,lease_owner=?,lease_until=?,reference=?,baseline_revision=?,evaluation_key=?,capture_digest=?,receipt=? WHERE id=?",
                (
                    state,
                    None if release else lease_owner,
                    None if release else row["lease_until"],
                    data.get("reference", row["reference"]),
                    data.get("baselineRevision", row["baseline_revision"]),
                    data.get("evaluationKey", row["evaluation_key"]),
                    data.get("captureDigest", row["capture_digest"]),
                    _canonical(data["receipt"])
                    if state == "committed"
                    else row["receipt"],
                    run_id,
                ),
            )
            result = self._run_record(self._run(db, run_id, principal))
            db.commit()
        return result

    def release(self, run_id, principal, lease_owner, expected_revision):
        _id(run_id)
        _text(principal)
        _owner(lease_owner)
        _revision(expected_revision)
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._run(db, run_id, principal)
            if (
                row["revision"] != expected_revision
                or row["lease_owner"] != lease_owner
                or row["lease_until"] is None
                or now >= row["lease_until"]
            ):
                raise Conflict("lease or revision changed")
            state = "capture_unknown" if row["state"] == "intent" else row["state"]
            if state not in _OPEN:
                raise Conflict("run is terminal")
            db.execute(
                "UPDATE runs SET state=?,revision=revision+1,lease_owner=NULL,lease_until=NULL WHERE id=?",
                (state, run_id),
            )
            result = self._run_record(self._run(db, run_id, principal))
            db.commit()
        return result
