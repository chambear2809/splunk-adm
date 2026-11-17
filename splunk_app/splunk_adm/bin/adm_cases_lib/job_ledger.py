"""Private bounded recovery metadata for caller-owned search jobs.

No authentication tokens, raw query text, search results, or network callbacks are stored. The
host supplies an authenticated principal and random per-operation lease owner.
Uncertain creation/deletion never expires automatically or releases the global
budget; only a confirmed deletion or a proven collision is terminal. Lease
expiry only allows the same principal to reconcile an existing record.
"""

import math
import os
import re
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path


class Invalid(ValueError):
    pass


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class QuotaExceeded(Exception):
    pass


_STATES = {
    "creating",
    "created",
    "creation_unknown",
    "cleanup_unknown",
    "deleted",
    "collision",
}
_TERMINAL = {"deleted", "collision"}
_ALLOWED = {
    "creating": {"creation_unknown"},
    "created": {"cleanup_unknown", "deleted"},
    "creation_unknown": {"created", "collision"},
    "cleanup_unknown": {"created", "deleted"},
}


def _principal(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or not value.isprintable()
    ):
        raise Invalid("invalid principal")


def _sid(value, *, new=False):
    pattern = (
        r"adm-capture-[0-9a-f]{32}" if new else r"adm-(?:sid|capture)-[0-9a-f]{32}"
    )
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise Invalid("invalid job id")


def _server_sid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", value):
        raise Invalid("invalid server job id")


def _owner(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32,64}", value):
        raise Invalid("invalid lease owner")


def _revision(value):
    if type(value) is not int or value < 1:
        raise Invalid("invalid expected revision")


def _lease(value):
    if type(value) is not int or not 1 <= value <= 60:
        raise Invalid("invalid lease duration")


def _safe_path(path):
    try:
        path = Path(path)
        if (
            not path.is_absolute()
            or path.name != "capture_jobs.sqlite"
            or path.parent.is_symlink()
        ):
            raise ValueError("invalid path")
        info = path.parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("unsafe parent")
        return path
    except (TypeError, ValueError, OSError) as exc:
        raise Invalid("invalid ledger location") from exc


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
            raise Invalid("unsafe ledger file")
    except OSError as exc:
        raise Invalid("unsafe ledger file") from exc
    finally:
        if fd is not None:
            os.close(fd)


class JobLedger:
    """Separate SQLite ledger: at most three live records and 128 terminal rows."""

    def __init__(self, database_path, clock=time.time, limit=3):
        if not callable(clock) or type(limit) is not int or not 1 <= limit <= 3:
            raise ValueError("invalid ledger configuration")
        self.path = _safe_path(database_path)
        self.clock = clock
        self.limit = limit
        _secure_file(self.path)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1, 2, 3):
                    raise Invalid("unsupported ledger schema")
                if (
                    version == 0
                    and db.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
                    ).fetchone()
                ):
                    raise Invalid("unversioned ledger schema")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS jobs (seq INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL UNIQUE, principal TEXT NOT NULL, query_hash TEXT NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, lease_owner TEXT, lease_until REAL, terminal_seq INTEGER, transport_hash TEXT, server_sid TEXT)"
                )
                columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
                if version == 1:
                    if "transport_hash" in columns:
                        raise Invalid("invalid legacy ledger schema")
                    db.execute("ALTER TABLE jobs ADD COLUMN transport_hash TEXT")
                elif "transport_hash" not in columns:
                    raise Invalid("invalid ledger schema")
                if version in (1, 2):
                    if "server_sid" in columns:
                        raise Invalid("invalid legacy ledger schema")
                    db.execute("ALTER TABLE jobs ADD COLUMN server_sid TEXT")
                    # Older IDs are local intents, never inferred server IDs.
                    # Drop in-flight leases and invalidate stale revisions.
                    db.execute(
                        "UPDATE jobs SET state='creation_unknown',revision=revision+1,lease_owner=NULL,lease_until=NULL WHERE state NOT IN ('deleted','collision')"
                    )
                elif "server_sid" not in columns:
                    raise Invalid("invalid ledger schema")
                db.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS jobs_server_sid_unique ON jobs(server_sid) WHERE server_sid IS NOT NULL"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS ledger_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
                )
                db.execute(
                    "INSERT OR IGNORE INTO ledger_meta VALUES ('terminal_seq',0)"
                )
                db.execute("PRAGMA user_version = 3")
                db.commit()
            except Exception:
                db.rollback()
                raise

    def _connect(self):
        _safe_path(self.path)
        _secure_file(self.path)
        db = sqlite3.connect(self.path, timeout=0.1, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    def _now(self):
        try:
            value = self.clock()
        except Exception as exc:
            raise Invalid("trusted clock unavailable") from exc
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or not 0 <= value <= 253402300739
        ):
            raise Invalid("invalid trusted clock")
        return float(value)

    @staticmethod
    def _row(db, principal, sid):
        row = db.execute(
            "SELECT sid,server_sid,principal,query_hash,transport_hash,window_start,window_end,state,revision,lease_owner,lease_until FROM jobs WHERE sid=? AND principal=?",
            (sid, principal),
        ).fetchone()
        if row is None:
            raise NotFound("job not found")
        return row

    @staticmethod
    def _record(row):
        return dict(row)

    def reserve(
        self,
        principal,
        sid,
        query_hash,
        start,
        end,
        lease_owner,
        lease_seconds=35,
        *,
        transport_hash,
    ):
        _principal(principal)
        _sid(sid, new=True)
        _owner(lease_owner)
        _lease(lease_seconds)
        if not isinstance(query_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", query_hash
        ):
            raise Invalid("invalid query hash")
        if not isinstance(transport_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", transport_hash
        ):
            raise Invalid("invalid transport hash")
        if (
            type(start) is not int
            or type(end) is not int
            or start < 0
            or end > 253402300799
            or not 0 < end - start <= 300
        ):
            raise Invalid("invalid absolute window")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                now = self._now()
                if db.execute("SELECT 1 FROM jobs WHERE sid=?", (sid,)).fetchone():
                    raise Conflict("job id already reserved")
                if (
                    db.execute(
                        "SELECT count(*) FROM jobs WHERE state NOT IN ('deleted','collision')"
                    ).fetchone()[0]
                    >= self.limit
                ):
                    raise QuotaExceeded("job budget exhausted")
                db.execute(
                    "INSERT INTO jobs (sid,principal,query_hash,transport_hash,window_start,window_end,state,revision,lease_owner,lease_until) VALUES (?,?,?,?,?,?,'creating',1,?,?)",
                    (
                        sid,
                        principal,
                        query_hash,
                        transport_hash,
                        start,
                        end,
                        lease_owner,
                        now + lease_seconds,
                    ),
                )
                result = self._record(self._row(db, principal, sid))
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def bind_created(
        self, principal, sid, lease_owner, server_sid, *, expected_revision
    ):
        """Bind only a successful server-assigned POST response to its live intent."""
        _principal(principal)
        _sid(sid)
        _owner(lease_owner)
        _server_sid(server_sid)
        _revision(expected_revision)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(db, principal, sid)
                now = self._now()
                if row["revision"] != expected_revision:
                    raise Conflict("revision changed")
                if (
                    row["lease_owner"] != lease_owner
                    or row["lease_until"] is None
                    or now >= row["lease_until"]
                ):
                    raise Conflict("lease unavailable")
                if (
                    row["state"] != "creating"
                    or row["server_sid"] is not None
                    or row["transport_hash"] is None
                ):
                    raise Conflict("job cannot be bound")
                try:
                    db.execute(
                        "UPDATE jobs SET state='created',server_sid=?,revision=revision+1 WHERE sid=? AND principal=? AND revision=?",
                        (server_sid, sid, principal, expected_revision),
                    )
                except sqlite3.IntegrityError as exc:
                    raise Conflict("server job id already bound") from exc
                result = self._record(self._row(db, principal, sid))
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def transition(self, principal, sid, lease_owner, state, *, expected_revision):
        _principal(principal)
        _sid(sid)
        _owner(lease_owner)
        _revision(expected_revision)
        if not isinstance(state, str) or state not in _STATES:
            raise Invalid("invalid job state")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(db, principal, sid)
                now = self._now()
                if row["revision"] != expected_revision:
                    raise Conflict("revision changed")
                if (
                    row["lease_owner"] != lease_owner
                    or row["lease_until"] is None
                    or now >= row["lease_until"]
                ):
                    raise Conflict("lease unavailable")
                if state not in _ALLOWED.get(row["state"], set()):
                    raise Conflict("invalid state transition")
                if row["transport_hash"] is None and state in (_TERMINAL | {"created"}):
                    raise Conflict("legacy job has no bound transport")
                if row["server_sid"] is None and state in (_TERMINAL | {"created"}):
                    raise Conflict("job has no bound server id")
                finished = None
                if state in _TERMINAL:
                    db.execute(
                        "UPDATE ledger_meta SET value=value+1 WHERE key='terminal_seq'"
                    )
                    finished = db.execute(
                        "SELECT value FROM ledger_meta WHERE key='terminal_seq'"
                    ).fetchone()[0]
                release = state in _TERMINAL or state in (
                    "creation_unknown",
                    "cleanup_unknown",
                )
                db.execute(
                    "UPDATE jobs SET state=?,revision=revision+1,lease_owner=?,lease_until=?,terminal_seq=? WHERE sid=? AND principal=? AND revision=?",
                    (
                        state,
                        None if release else lease_owner,
                        None if release else row["lease_until"],
                        finished,
                        sid,
                        principal,
                        expected_revision,
                    ),
                )
                result = self._record(self._row(db, principal, sid))
                if finished is not None:
                    db.execute(
                        "DELETE FROM jobs WHERE seq IN (SELECT seq FROM jobs WHERE state IN ('deleted','collision') ORDER BY terminal_seq DESC LIMIT -1 OFFSET 128)"
                    )
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def claim(
        self, principal, sid, lease_owner, *, expected_revision, lease_seconds=35
    ):
        _principal(principal)
        _sid(sid)
        _owner(lease_owner)
        _revision(expected_revision)
        _lease(lease_seconds)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(db, principal, sid)
                now = self._now()
                if row["revision"] != expected_revision:
                    raise Conflict("revision changed")
                if row["state"] in _TERMINAL:
                    raise Conflict("job is terminal")
                if (
                    row["lease_owner"] is not None
                    and row["lease_owner"] != lease_owner
                    and row["lease_until"] is not None
                    and now < row["lease_until"]
                ):
                    raise Conflict("lease is held")
                db.execute(
                    "UPDATE jobs SET revision=revision+1,lease_owner=?,lease_until=? WHERE sid=? AND principal=? AND revision=?",
                    (
                        lease_owner,
                        now + lease_seconds,
                        sid,
                        principal,
                        expected_revision,
                    ),
                )
                result = self._record(self._row(db, principal, sid))
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def outstanding(self, principal):
        _principal(principal)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT sid,server_sid,principal,query_hash,transport_hash,window_start,window_end,state,revision,lease_owner,lease_until FROM jobs WHERE principal=? AND state NOT IN ('deleted','collision') ORDER BY seq",
                (principal,),
            )
            return [self._record(row) for row in rows]
