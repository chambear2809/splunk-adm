"""SQLite-backed local case records; no HTTP or Splunk authentication is provided.

The database path and entitlement callback are trusted application configuration. The
caller MUST obtain principal from an authenticated server-side context. The callback
is consulted on every operation and must consult current server-side entitlements.
SQLite's containing directory must be protected by the deploying application.
"""

import datetime as dt
from contextlib import closing
import hashlib
import json
import sqlite3
import uuid


class Invalid(ValueError):
    pass


class Forbidden(Exception):
    pass


class SourceUnavailable(Exception):
    """A trusted source could not provide or authorize a capture before insertion."""


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class QuotaExceeded(Exception):
    pass


def _text(value, name, limit=4096):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise Invalid("invalid " + name)
    return value


def _object(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Invalid("unexpected or missing fields")


def _json(value):
    def check(node):
        if node is None or type(node) in (str, int, float, bool):
            return
        if type(node) is list:
            for child in node:
                check(child)
            return
        if type(node) is dict and all(type(key) is str for key in node):
            for child in node.values():
                check(child)
            return
        raise Invalid("invalid JSON value")

    try:
        check(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise Invalid("invalid JSON") from exc


def _instant(value):
    _text(value, "timestamp", 64)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Invalid("invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Invalid("timestamps require an explicit offset")
    return parsed.astimezone(dt.timezone.utc)


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _valid_uuid(value):
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _capture_ids(document):
    return [
        item["id"]
        for item in document["captures"]
        if isinstance(item, dict)
        and _valid_uuid(item.get("id"))
        and isinstance(item.get("source"), dict)
        and item["source"]
    ]


def _check_capture_selector(document, capture_id):
    if capture_id is not None:
        if not _valid_uuid(capture_id):
            raise Invalid("invalid capture id")
        if capture_id not in _capture_ids(document):
            raise NotFound("capture not found")


class CaseStore:
    """Local records with per-case ACL and transactionally stored retry results.

    Entitlement callback signature: (principal, action, case_id) -> bool. Actions
    are create, read, export, list, write, share, delete, and audit. For create,
    case_id is None. It must fail closed and must not trust request content.
    All limits are trusted deployment configuration, not per-request values.
    """

    def __init__(
        self,
        database_path,
        entitlement,
        *,
        capture_resolver=None,
        source_entitlement=None,
        max_cases=1000,
        max_case_bytes=1_000_000,
        max_items=1000,
        retention_days=365,
        max_acl_members=100,
        max_request_rows=100_000,
        max_request_bytes=100_000_000,
        max_audit_rows=100_000,
    ):
        if (
            not callable(entitlement)
            or (capture_resolver is not None and not callable(capture_resolver))
            or (source_entitlement is not None and not callable(source_entitlement))
            or min(
                max_cases,
                max_case_bytes,
                max_items,
                retention_days,
                max_acl_members,
                max_request_rows,
                max_request_bytes,
                max_audit_rows,
            )
            < 1
        ):
            raise ValueError("invalid store configuration")
        self.path = database_path
        self.entitlement = entitlement
        self.capture_resolver = capture_resolver
        self.source_entitlement = source_entitlement
        self.max_cases = max_cases
        self.max_case_bytes = max_case_bytes
        self.max_items = max_items
        self.retention_days = retention_days
        self.max_acl_members = max_acl_members
        self.max_request_rows = max_request_rows
        self.max_request_bytes = max_request_bytes
        self.max_audit_rows = max_audit_rows
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL,
                    document TEXT NOT NULL, expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS acl (
                    case_id TEXT NOT NULL, principal TEXT NOT NULL,
                    PRIMARY KEY (case_id, principal),
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS requests (
                    principal TEXT NOT NULL, request_id TEXT NOT NULL, action TEXT NOT NULL,
                    case_id TEXT, digest TEXT NOT NULL, result TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (principal, request_id)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
                    principal TEXT NOT NULL, action TEXT NOT NULL, at TEXT NOT NULL,
                    revision INTEGER
                );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(requests)")}
            if "created_at" not in columns:
                db.execute(
                    "ALTER TABLE requests ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
                )

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _entitled(self, principal, action, case_id):
        _text(principal, "principal", 256)
        try:
            allowed = self.entitlement(principal, action, case_id)
        except Exception as exc:
            raise Forbidden("entitlement unavailable") from exc
        if allowed is not True:
            raise Forbidden("not entitled")

    def _project(self, principal, result, *, authorize_sources=True, capture_id=None):
        """Reauthorize each protected item in this particular response snapshot."""
        if not isinstance(result, dict) or not all(
            key in result for key in ("captures", "attachments", "entries")
        ):
            return result
        result = json.loads(_json(result))
        _check_capture_selector(result, capture_id)
        result["capture_ids"] = _capture_ids(result)
        redactions = {}
        for field, kind in (("captures", "capture"), ("attachments", "attachment")):
            visible = []
            for item in result[field]:
                allowed = False
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("source"), dict)
                    and item["source"]
                    and authorize_sources
                    and (
                        capture_id is None
                        or (field == "captures" and item.get("id") == capture_id)
                    )
                    and self.source_entitlement is not None
                ):
                    try:
                        allowed = (
                            self.source_entitlement(
                                principal, kind, json.loads(_json(item))
                            )
                            is True
                        )
                    except Exception:
                        allowed = False
                if allowed:
                    visible.append(
                        {key: value for key, value in item.items() if key != "source"}
                    )
            redactions[field] = len(result[field]) - len(visible)
            result[field] = visible
        result["redactions"] = redactions
        return result

    def _project_checked(self, principal, result, action="read", capture_id=None):
        projected = self._project(principal, result, capture_id=capture_id)
        if isinstance(result, dict) and all(
            key in result for key in ("captures", "attachments", "entries")
        ):
            # Source checks can be slow. Recheck current case access after them.
            with closing(self._connect()) as db:
                self._row(db, principal, "read", result["id"])
                if action not in ("read", "create"):
                    self._entitled(principal, action, result["id"])
        return projected

    def _row(self, db, principal, action, case_id):
        _text(case_id, "case id", 64)
        self._entitled(principal, action, case_id)
        row = db.execute(
            "SELECT owner, revision, document, expires_at FROM cases WHERE id = ?",
            (case_id,),
        ).fetchone()
        if not row or _instant(row[3]) <= dt.datetime.now(dt.timezone.utc):
            raise NotFound("case not found")
        if not db.execute(
            "SELECT 1 FROM acl WHERE case_id = ? AND principal = ?",
            (case_id, principal),
        ).fetchone():
            raise Forbidden("case access denied")
        return row

    def _reserved_actions(self, db):
        # Each live case reserves deletion, and each non-owner member reserves
        # revocation. These slots cannot be consumed by unrelated operations.
        active = db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        members = db.execute(
            "SELECT COUNT(*) FROM acl JOIN cases ON cases.id=acl.case_id WHERE acl.principal != cases.owner"
        ).fetchone()[0]
        return active + members

    def _audit(self, db, case_id, principal, action, revision):
        count = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        # Deletion and expiry consume a previously reserved slot. Revocation
        # removes its membership first, releasing its own reserved slot.
        reserve = 0 if action in ("delete", "expire") else self._reserved_actions(db)
        if count + 1 + reserve > self.max_audit_rows:
            raise QuotaExceeded("audit quota exceeded")
        db.execute(
            "INSERT INTO audit(case_id, principal, action, at, revision) VALUES (?, ?, ?, ?, ?)",
            (case_id, principal, action, _now(), revision),
        )

    def _mutation(
        self, principal, request_id, action, case_id, payload, expected, operation
    ):
        _text(principal, "principal", 256)
        _text(request_id, "request id", 128)
        if expected is not None and (type(expected) is not int or expected < 1):
            raise Invalid("invalid expected revision")
        digest = hashlib.sha256(
            _json(
                {
                    "action": action,
                    "case_id": case_id,
                    "payload": payload,
                    "expected": expected,
                }
            ).encode()
        ).hexdigest()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                previous = db.execute(
                    "SELECT digest, result, case_id FROM requests WHERE principal = ? AND request_id = ?",
                    (principal, request_id),
                ).fetchone()
                if previous:
                    if previous[0] != digest:
                        raise Conflict("request id already used")
                    # Deleted records have no ACL left; the original owner and current
                    # delete entitlement are required to replay the deletion receipt.
                    if action == "delete":
                        self._entitled(principal, action, case_id)
                    else:
                        self._row(db, principal, "read", previous[2])
                        self._entitled(principal, action, case_id)
                    db.commit()
                    return self._project_checked(
                        principal, json.loads(previous[1]), action
                    )
                if case_id is None:
                    self._entitled(principal, action, None)
                else:
                    self._row(db, principal, action, case_id)
                result = operation(db)
                stored_case_id = case_id or result["id"]
                result_json = _json(result)
                count, size = db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(length(CAST(result AS BLOB))), 0) FROM requests"
                ).fetchone()
                reserved = self._reserved_actions(db)
                # Deletion and revocation receipts are compact and fit in 1024 bytes.
                if (
                    count + 1 + reserved > self.max_request_rows
                    or size + len(result_json.encode()) + reserved * 1024
                    > self.max_request_bytes
                ):
                    raise QuotaExceeded("retry metadata quota exceeded")
                db.execute(
                    "INSERT INTO requests (principal, request_id, action, case_id, digest, result, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        principal,
                        request_id,
                        action,
                        stored_case_id,
                        digest,
                        result_json,
                        _now(),
                    ),
                )
                db.commit()
                return self._project_checked(principal, result, action)
            except Exception:
                db.rollback()
                raise

    def create(self, principal, request_id, data):
        _object(data, ("schema_version", "title", "window"))
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise Invalid("unsupported schema version")
        _text(data["title"], "title", 256)
        _object(data["window"], ("start", "end"))
        if _instant(data["window"]["start"]) >= _instant(data["window"]["end"]):
            raise Invalid("invalid time window")

        def apply(db):
            if db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] >= self.max_cases:
                raise QuotaExceeded("case quota exceeded")
            case_id = str(uuid.uuid4())
            document = {
                "schema_version": 1,
                "id": case_id,
                "revision": 1,
                "title": data["title"],
                "window": dict(data["window"]),
                "captures": [],
                "entries": [],
                "attachments": [],
            }
            encoded = _json(document)
            if len(encoded.encode()) > self.max_case_bytes:
                raise QuotaExceeded("case size exceeded")
            expires = (
                dt.datetime.now(dt.timezone.utc)
                + dt.timedelta(days=self.retention_days)
            ).isoformat()
            db.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?)",
                (case_id, principal, 1, encoded, expires),
            )
            db.execute("INSERT INTO acl VALUES (?, ?)", (case_id, principal))
            self._audit(db, case_id, principal, "create", 1)
            return document

        return self._mutation(principal, request_id, "create", None, data, None, apply)

    def get(self, principal, case_id, *, capture_id=None):
        with closing(self._connect()) as db:
            return self._project_checked(
                principal,
                json.loads(self._row(db, principal, "read", case_id)[2]),
                capture_id=capture_id,
            )

    def export(self, principal, case_id, *, capture_id=None):
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = self._row(db, principal, "export", case_id)
                document = json.loads(row[2])
                _check_capture_selector(document, capture_id)
                self._audit(db, case_id, principal, "export", row[1])
                db.commit()
                return self._project_checked(
                    principal, document, "export", capture_id=capture_id
                )
            except Exception:
                db.rollback()
                raise

    def list_cases(self, principal, *, after="", limit=50):
        _text(principal, "principal", 256)
        if (
            not isinstance(after, str)
            or len(after) > 64
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise Invalid("invalid pagination")
        self._entitled(principal, "list", None)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT c.id, c.document, c.expires_at FROM cases c JOIN acl a ON a.case_id=c.id WHERE a.principal=? AND c.id>? ORDER BY c.id",
                (principal, after),
            )
            result = []
            for case_id, document, expires in rows:
                if _instant(expires) <= dt.datetime.now(dt.timezone.utc):
                    continue
                try:
                    self._entitled(principal, "list", case_id)
                    self._entitled(principal, "read", case_id)
                except Forbidden:
                    continue
                result.append(
                    self._project(
                        principal, json.loads(document), authorize_sources=False
                    )
                )
                if len(result) > limit:
                    break
            return {
                "items": result[:limit],
                "next": result[limit - 1]["id"] if len(result) > limit else None,
            }

    def append(self, principal, request_id, case_id, expected_revision, kind, item):
        if kind == "entry":
            _object(item, ("type", "text"))
            if item["type"] not in ("note", "hypothesis", "question"):
                raise Invalid("invalid entry type")
            _text(item["text"], "entry", 10000)
            target = "entries"
        elif kind in ("capture", "attachment"):
            raise Forbidden("protected evidence requires a trusted resolver")
        else:
            raise Invalid("invalid item kind")
        _json(item)

        def apply(db):
            row = self._row(db, principal, "write", case_id)
            if row[1] != expected_revision:
                raise Conflict("revision changed")
            doc = json.loads(row[2])
            if (
                sum(len(doc[key]) for key in ("captures", "entries", "attachments"))
                >= self.max_items
            ):
                raise QuotaExceeded("item quota exceeded")
            doc["revision"] += 1
            doc[target].append(
                {
                    "id": str(uuid.uuid4()),
                    "revision": doc["revision"],
                    "author": principal,
                    "created_at": _now(),
                    **item,
                }
            )
            encoded = _json(doc)
            if len(encoded.encode()) > self.max_case_bytes:
                raise QuotaExceeded("case size exceeded")
            db.execute(
                "UPDATE cases SET revision=?, document=? WHERE id=?",
                (doc["revision"], encoded, case_id),
            )
            self._audit(db, case_id, principal, "append_" + kind, doc["revision"])
            return json.loads(encoded)

        return self._mutation(
            principal,
            request_id,
            "write",
            case_id,
            {"kind": kind, "item": item},
            expected_revision,
            apply,
        )

    def append_capture(
        self,
        principal,
        request_id,
        case_id,
        expected_revision,
        reference,
        label="Capture",
    ):
        _text(reference, "capture reference", 4096)
        _text(label, "label", 256)
        _text(principal, "principal", 256)
        _text(request_id, "request id", 128)
        if type(expected_revision) is not int or expected_revision < 1:
            raise Invalid("invalid expected revision")
        if reference.strip() != reference or label.strip() != label:
            raise Invalid("invalid capture reference or label")
        # Check case access before any source request, without a write transaction.
        # A concurrent writer is checked again under BEGIN IMMEDIATE by _mutation.
        with closing(self._connect()) as db:
            previous = db.execute(
                "SELECT 1 FROM requests WHERE principal=? AND request_id=?",
                (principal, request_id),
            ).fetchone()
            if not previous:
                row = self._row(db, principal, "write", case_id)
                if row[1] != expected_revision:
                    raise Conflict("revision changed")
        item = None
        if not previous:
            if self.capture_resolver is None or self.source_entitlement is None:
                raise SourceUnavailable("capture source unavailable")
            try:
                resolved = self.capture_resolver(principal, reference)
            except Exception as exc:
                raise SourceUnavailable("capture source unavailable") from exc
            if not isinstance(resolved, dict) or set(resolved) != {
                "captured_at",
                "data",
                "source",
            }:
                raise SourceUnavailable("invalid resolved capture")
            try:
                _instant(resolved["captured_at"])
            except Invalid as exc:
                raise SourceUnavailable("invalid resolved capture") from exc
            if (
                not isinstance(resolved["data"], dict)
                or not isinstance(resolved["source"], dict)
                or not resolved["source"]
            ):
                raise SourceUnavailable("invalid resolved capture")
            try:
                resolved = json.loads(_json(resolved))
            except Invalid as exc:
                raise SourceUnavailable("invalid resolved capture") from exc
            item = {
                "id": str(uuid.uuid4()),
                "revision": expected_revision + 1,
                "author": principal,
                "created_at": _now(),
                "label": label,
                **resolved,
            }
            try:
                allowed = (
                    self.source_entitlement(
                        principal, "capture", json.loads(_json(item))
                    )
                    is True
                )
            except Exception as exc:
                raise SourceUnavailable("source entitlement unavailable") from exc
            if not allowed:
                raise SourceUnavailable("source access unavailable")

        def apply(db):
            row = self._row(db, principal, "write", case_id)
            if row[1] != expected_revision:
                raise Conflict("revision changed")
            # A receipt observed during preflight can only disappear if the case
            # was deleted or externally altered; never persist without resolution.
            if item is None:
                raise Conflict("capture request changed")
            doc = json.loads(row[2])
            if (
                sum(len(doc[key]) for key in ("captures", "entries", "attachments"))
                >= self.max_items
            ):
                raise QuotaExceeded("item quota exceeded")
            doc["revision"] += 1
            doc["captures"].append(item)
            encoded = _json(doc)
            if len(encoded.encode()) > self.max_case_bytes:
                raise QuotaExceeded("case size exceeded")
            db.execute(
                "UPDATE cases SET revision=?, document=? WHERE id=?",
                (doc["revision"], encoded, case_id),
            )
            self._audit(db, case_id, principal, "append_capture", doc["revision"])
            return json.loads(encoded)

        return self._mutation(
            principal,
            request_id,
            "write",
            case_id,
            {"kind": "trusted_capture", "reference": reference, "label": label},
            expected_revision,
            apply,
        )

    def share(self, principal, request_id, case_id, expected_revision, member, grant):
        _text(member, "member", 256)
        if type(grant) is not bool:
            raise Invalid("invalid grant")

        def apply(db):
            row = self._row(db, principal, "share", case_id)
            if row[0] != principal:
                raise Forbidden("only owner may change access")
            if row[1] != expected_revision:
                raise Conflict("revision changed")
            if member == row[0]:
                raise Invalid("owner access cannot be changed")
            if grant:
                exists = db.execute(
                    "SELECT 1 FROM acl WHERE case_id=? AND principal=?",
                    (case_id, member),
                ).fetchone()
                count = db.execute(
                    "SELECT COUNT(*) FROM acl WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                if not exists and count >= self.max_acl_members:
                    raise QuotaExceeded("ACL quota exceeded")
                db.execute("INSERT OR IGNORE INTO acl VALUES (?, ?)", (case_id, member))
            else:
                deleted = db.execute(
                    "DELETE FROM acl WHERE case_id=? AND principal=?", (case_id, member)
                )
                if deleted.rowcount != 1:
                    raise Invalid("member does not have access")
            doc = json.loads(row[2])
            doc["revision"] += 1
            db.execute(
                "UPDATE cases SET revision=?, document=? WHERE id=?",
                (doc["revision"], _json(doc), case_id),
            )
            self._audit(
                db, case_id, principal, "grant" if grant else "revoke", doc["revision"]
            )
            # A compact revocation receipt fits the capacity reserved at grant.
            return (
                doc
                if grant
                else {"id": case_id, "revision": doc["revision"], "revoked": True}
            )

        return self._mutation(
            principal,
            request_id,
            "share",
            case_id,
            {"member": member, "grant": grant},
            expected_revision,
            apply,
        )

    def delete(self, principal, request_id, case_id, expected_revision):
        def apply(db):
            row = self._row(db, principal, "delete", case_id)
            if row[0] != principal:
                raise Forbidden("only owner may delete")
            if row[1] != expected_revision:
                raise Conflict("revision changed")
            self._audit(db, case_id, principal, "delete", row[1])
            # Retain request identifiers as tombstones, but erase response snapshots.
            db.execute("UPDATE requests SET result='null' WHERE case_id=?", (case_id,))
            db.execute("DELETE FROM cases WHERE id=?", (case_id,))
            return {"id": case_id, "deleted": True}

        return self._mutation(
            principal, request_id, "delete", case_id, {}, expected_revision, apply
        )

    def audit(self, principal, case_id, *, after=0, limit=100):
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise Invalid("invalid pagination")
        with closing(self._connect()) as db:
            self._row(db, principal, "audit", case_id)
            rows = db.execute(
                "SELECT seq, principal, action, at, revision FROM audit WHERE case_id=? AND seq>? ORDER BY seq LIMIT ?",
                (case_id, after, limit + 1),
            ).fetchall()
            items = [
                {
                    "seq": row[0],
                    "principal": row[1],
                    "action": row[2],
                    "at": row[3],
                    "revision": row[4],
                }
                for row in rows[:limit]
            ]
            return {
                "items": items,
                "next": items[-1]["seq"] if len(rows) > limit else None,
            }

    def purge_expired(self, principal):
        """Remove expired records and retry snapshots; invoke from trusted maintenance."""
        self._entitled(principal, "purge", None)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                ids = [
                    row[0]
                    for row in db.execute("SELECT id, expires_at FROM cases")
                    if _instant(row[1]) <= dt.datetime.now(dt.timezone.utc)
                ]
                for case_id in ids:
                    self._audit(db, case_id, principal, "expire", None)
                    db.execute("DELETE FROM requests WHERE case_id=?", (case_id,))
                    db.execute("DELETE FROM cases WHERE id=?", (case_id,))
                cutoff = (
                    dt.datetime.now(dt.timezone.utc)
                    - dt.timedelta(days=self.retention_days)
                ).isoformat()
                db.execute("DELETE FROM audit WHERE at < ?", (cutoff,))
                db.execute(
                    "DELETE FROM requests WHERE created_at < ? AND NOT EXISTS (SELECT 1 FROM cases WHERE cases.id=requests.case_id)",
                    (cutoff,),
                )
                db.commit()
                return len(ids)
            except Exception:
                db.rollback()
                raise
