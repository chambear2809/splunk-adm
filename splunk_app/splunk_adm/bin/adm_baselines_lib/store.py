"""Private baseline storage. Identity, entitlements and evidence come from trusted hosts.

source_validator(principal, reference) returns the complete dedicated-query capture,
not a caller-supplied qualification. It must enforce current source permissions.
The host must protect the database directory and obtain principal from authentication.
"""

import hashlib
import json
import math
import sqlite3
import time
import uuid
from contextlib import closing


class Invalid(ValueError):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class QuotaExceeded(Exception):
    pass


def _text(value, name, limit=256):
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > limit
        or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        raise Invalid("invalid " + name)
    return value


def _json(value):
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=False,
        )
        encoded.encode("utf-8")
        return encoded
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise Invalid("invalid JSON") from exc


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _window(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"start", "end"}
        or not all(_number(value[k]) for k in value)
        or value["start"] < 0
        or value["end"] <= value["start"]
    ):
        raise Invalid("invalid absolute window")


def signature(dep):
    for key in (
        "authority",
        "scope",
        "source",
        "destination",
        "protocol",
        "relation",
        "direction",
    ):
        _text(dep[key], key)
    return _json(
        [
            1,
            *(
                dep[k]
                for k in (
                    "authority",
                    "scope",
                    "source",
                    "destination",
                    "protocol",
                    "port",
                    "relation",
                    "direction",
                )
            ),
        ]
    )


def validate_capture(capture, max_dependencies=10000, max_bytes=2_000_000):
    if not isinstance(capture, dict) or set(capture) != {
        "id",
        "coverage",
        "dependencies",
    }:
        raise Invalid("invalid capture")
    _text(capture["id"], "capture id")
    c = capture["coverage"]
    keys = {
        "requested",
        "returned",
        "authority",
        "scope",
        "sourceRevision",
        "configRevision",
        "normalizationRevision",
        "signatureVersion",
        "permission",
        "complete",
        "capped",
        "progressive",
        "sampled",
        "stale",
        "knowledgeHorizon",
        "requiredLatenessSeconds",
    }
    if not isinstance(c, dict) or set(c) != keys:
        raise Invalid("invalid coverage")
    _window(c["requested"])
    _window(c["returned"])
    if c["requested"] != c["returned"]:
        raise Invalid("window mismatch")
    for key in (
        "authority",
        "scope",
        "sourceRevision",
        "configRevision",
        "normalizationRevision",
    ):
        _text(c[key], key)
    if (
        type(c["signatureVersion"]) is not int
        or c["signatureVersion"] != 1
        or c["permission"] != "allowed"
        or c["complete"] is not True
        or any(c[k] is not False for k in ("capped", "progressive", "sampled", "stale"))
    ):
        raise Invalid("evidence is not complete")
    if (
        not _number(c["requiredLatenessSeconds"])
        or c["requiredLatenessSeconds"] < 0
        or not _number(c["knowledgeHorizon"])
        or c["knowledgeHorizon"] < c["returned"]["end"] + c["requiredLatenessSeconds"]
    ):
        raise Invalid("late arrival horizon incomplete")
    deps = capture["dependencies"]
    if not isinstance(deps, list) or len(deps) > max_dependencies:
        raise QuotaExceeded("dependency quota exceeded")
    signatures = set()
    for dep in deps:
        required = {
            "authority",
            "scope",
            "source",
            "destination",
            "protocol",
            "port",
            "relation",
            "direction",
            "blocked",
        }
        if (
            not isinstance(dep, dict)
            or not required <= set(dep)
            or set(dep) - required - {"redundancyDomains"}
        ):
            raise Invalid("invalid dependency")
        for key in (
            "authority",
            "scope",
            "source",
            "destination",
            "protocol",
            "relation",
            "direction",
        ):
            _text(dep[key], key)
        if (
            dep["authority"] != c["authority"]
            or dep["scope"] != c["scope"]
            or type(dep["port"]) is not int
            or not 1 <= dep["port"] <= 65535
            or dep["blocked"] not in (True, False, None)
            or type(dep["blocked"]) not in (bool, type(None))
        ):
            raise Invalid("invalid dependency identity or scope")
        domains = dep.get("redundancyDomains", [])
        if not isinstance(domains, list) or len(domains) > 100:
            raise Invalid("invalid domains")
        for domain in domains:
            _text(domain, "domain")
        if len(set(domains)) != len(domains) or signature(dep) in signatures:
            raise Invalid("duplicate identity")
        signatures.add(signature(dep))
    if len(_json(capture).encode()) > max_bytes:
        raise QuotaExceeded("capture size exceeded")
    return capture


def compatible(a, b):
    ca, cb = a["coverage"], b["coverage"]
    keys = (
        "authority",
        "scope",
        "sourceRevision",
        "configRevision",
        "normalizationRevision",
        "signatureVersion",
        "requiredLatenessSeconds",
    )
    return (
        all(ca[k] == cb[k] for k in keys)
        and ca["returned"]["end"] - ca["returned"]["start"]
        == cb["returned"]["end"] - cb["returned"]["start"]
    )


def _dependency_prefix(dep):
    return tuple(
        dep[key] for key in ("source", "authority", "scope", "relation", "direction")
    )


def _prepare_baseline(baseline):
    before = {signature(dep): dep for dep in baseline["dependencies"]}
    destinations = {
        (_dependency_prefix(dep), dep["destination"]) for dep in before.values()
    }
    ports = {
        (_dependency_prefix(dep), dep["protocol"], dep["port"])
        for dep in before.values()
    }
    return before, destinations, ports


def compare_findings(baseline, current, *, prepared=None, selected=None):
    """Return TS-compatible findings; optionally restrict output to selected signatures."""
    if not compatible(baseline, current):
        raise Invalid("incompatible evidence")
    before, destinations, ports = (
        prepared if prepared is not None else _prepare_baseline(baseline)
    )
    after = {}
    for dep in current["dependencies"]:
        key = signature(dep)
        if selected is None or key in selected:
            after[key] = dep
    findings = {}
    for key, dep in after.items():
        old = before.get(key)
        if old is None:
            related = (_dependency_prefix(dep), dep["destination"]) in destinations or (
                _dependency_prefix(dep),
                dep["protocol"],
                dep["port"],
            ) in ports
            findings[key] = [
                "changed_dependency" if related else "new_destination_port"
            ]
        else:
            kinds = []
            if old["blocked"] is False and dep["blocked"] is True:
                kinds.append("newly_blocked")
            if (
                "redundancyDomains" in old
                and "redundancyDomains" in dep
                and len(old["redundancyDomains"]) > len(dep["redundancyDomains"])
            ):
                kinds.append("lost_redundancy")
            if kinds:
                findings[key] = kinds
    candidate_keys = before.keys() if selected is None else selected
    for key in candidate_keys:
        if key in before and key not in after:
            findings[key] = ["not_observed"]
    return findings


class BaselineStore:
    """Transactional ACL-protected versioned captures and passive watch records.

    Watch evaluations require proof for at most 100 distinct historical captures.
    Exceeding that bound fails closed; history is never silently truncated.
    """

    MAX_HISTORY_PROOFS = 100

    def __init__(
        self,
        database_path,
        entitlement,
        source_validator,
        *,
        source_entitlement=None,
        clock=time.time,
        max_baselines=1000,
        max_versions=100,
        max_dependencies=10000,
        max_capture_bytes=2_000_000,
        max_evidence_bytes=8 * 1024 * 1024,
        max_members=100,
        max_watches=100,
        max_occurrences=10000,
        max_requests=100000,
        retry_retention_seconds=86400 * 30,
    ):
        if (
            not callable(entitlement)
            or not callable(source_validator)
            or not callable(clock)
            or (source_entitlement is not None and not callable(source_entitlement))
            or any(
                type(n) is not int or n < 1
                for n in (
                    max_baselines,
                    max_versions,
                    max_dependencies,
                    max_capture_bytes,
                    max_evidence_bytes,
                    max_members,
                    max_watches,
                    max_occurrences,
                    max_requests,
                    retry_retention_seconds,
                )
            )
        ):
            raise ValueError("invalid configuration")
        self.path, self.entitlement, self.source_validator = (
            database_path,
            entitlement,
            source_validator,
        )
        (
            self.max_baselines,
            self.max_versions,
            self.max_dependencies,
            self.max_capture_bytes,
        ) = max_baselines, max_versions, max_dependencies, max_capture_bytes
        self.max_members, self.max_watches, self.max_occurrences, self.max_requests = (
            max_members,
            max_watches,
            max_occurrences,
            max_requests,
        )
        self.source_entitlement = source_entitlement
        self.clock = clock
        self.max_evidence_bytes = max_evidence_bytes
        self.retry_retention_seconds = retry_retention_seconds
        with closing(self._connect()) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS baselines (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, revision INTEGER NOT NULL, version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS members (baseline_id TEXT NOT NULL REFERENCES baselines(id) ON DELETE CASCADE, principal TEXT NOT NULL, PRIMARY KEY(baseline_id,principal));
            CREATE TABLE IF NOT EXISTS versions (baseline_id TEXT NOT NULL REFERENCES baselines(id) ON DELETE CASCADE, version INTEGER NOT NULL, capture TEXT NOT NULL, reference TEXT, PRIMARY KEY(baseline_id,version));
            CREATE TABLE IF NOT EXISTS watches (baseline_id TEXT NOT NULL REFERENCES baselines(id) ON DELETE CASCADE, id TEXT NOT NULL, definition TEXT NOT NULL, baseline_version INTEGER NOT NULL, PRIMARY KEY(baseline_id,id));
            CREATE TABLE IF NOT EXISTS occurrences (seq INTEGER PRIMARY KEY AUTOINCREMENT, baseline_id TEXT NOT NULL, watch_id TEXT NOT NULL, signature TEXT NOT NULL, start REAL NOT NULL, end REAL NOT NULL, observed REAL NOT NULL, reference TEXT, capture TEXT, UNIQUE(baseline_id,watch_id,signature,start,end), FOREIGN KEY(baseline_id,watch_id) REFERENCES watches(baseline_id,id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS requests (principal TEXT NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL, baseline_id TEXT NOT NULL, result TEXT NOT NULL, created_at REAL NOT NULL, PRIMARY KEY(principal,request_id));
            CREATE TABLE IF NOT EXISTS surfaced (baseline_id TEXT NOT NULL, watch_id TEXT NOT NULL, signature TEXT NOT NULL, surfaced_at REAL NOT NULL, PRIMARY KEY(baseline_id,watch_id,signature), FOREIGN KEY(baseline_id,watch_id) REFERENCES watches(baseline_id,id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS evidence (baseline_id TEXT NOT NULL REFERENCES baselines(id) ON DELETE CASCADE, evidence_key TEXT NOT NULL, reference TEXT NOT NULL, capture TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY(baseline_id,evidence_key));
            """)
            if "reference" not in {
                row[1] for row in db.execute("PRAGMA table_info(versions)")
            }:
                db.execute("ALTER TABLE versions ADD COLUMN reference TEXT")
            if "created_at" not in {
                row[1] for row in db.execute("PRAGMA table_info(requests)")
            }:
                db.execute(
                    "ALTER TABLE requests ADD COLUMN created_at REAL NOT NULL DEFAULT 0"
                )
            occurrence_columns = {
                row[1] for row in db.execute("PRAGMA table_info(occurrences)")
            }
            if "reference" not in occurrence_columns:
                db.execute("ALTER TABLE occurrences ADD COLUMN reference TEXT")
            if "capture" not in occurrence_columns:
                db.execute("ALTER TABLE occurrences ADD COLUMN capture TEXT")
            for table in ("versions", "occurrences"):
                if "evidence_key" not in {
                    row[1] for row in db.execute(f"PRAGMA table_info({table})")
                }:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN evidence_key TEXT")
            self._migrate_evidence(db)

    def _migrate_evidence(self, db):
        # Earlier local schemas stored evidence inline. Preserve it transactionally;
        # missing references stay inaccessible rather than guessing authorization.
        db.execute("BEGIN IMMEDIATE")
        try:
            for table, key_column in (("versions", "rowid"), ("occurrences", "seq")):
                rows = db.execute(
                    f"SELECT {key_column},baseline_id,reference,capture FROM {table} WHERE evidence_key IS NULL AND reference IS NOT NULL AND capture IS NOT NULL"
                ).fetchall()
                for row_id, baseline_id, reference, capture in rows:
                    key = self._store_evidence(db, baseline_id, reference, capture)
                    replacement = "" if table == "versions" else None
                    db.execute(
                        f"UPDATE {table} SET evidence_key=?,reference=NULL,capture=? WHERE {key_column}=?",
                        (key, replacement, row_id),
                    )
            db.commit()
        except Exception:
            db.rollback()
            raise

    def _store_evidence(self, db, baseline_id, reference_json, capture_json):
        key = hashlib.sha256(_json([reference_json, capture_json]).encode()).hexdigest()
        if not db.execute(
            "SELECT 1 FROM evidence WHERE baseline_id=? AND evidence_key=?",
            (baseline_id, key),
        ).fetchone():
            size = len(reference_json.encode()) + len(capture_json.encode())
            total = db.execute(
                "SELECT COALESCE(SUM(size),0) FROM evidence WHERE baseline_id=?",
                (baseline_id,),
            ).fetchone()[0]
            if total + size > self.max_evidence_bytes:
                raise QuotaExceeded("aggregate evidence quota exceeded")
            db.execute(
                "INSERT INTO evidence VALUES (?,?,?,?,?)",
                (baseline_id, key, reference_json, capture_json, size),
            )
        return key

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def purge_deleted_receipts(self, principal):
        """Trusted maintenance: remove aged receipts only after baseline deletion.

        Once purged, request IDs can be reused; live baseline retries remain intact.
        """
        self._entitled(principal, "purge", None)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                deleted = db.execute(
                    "DELETE FROM requests WHERE created_at < ? AND NOT EXISTS (SELECT 1 FROM baselines WHERE baselines.id=requests.baseline_id)",
                    (time.time() - self.retry_retention_seconds,),
                ).rowcount
                db.commit()
                return deleted
            except Exception:
                db.rollback()
                raise

    def _entitled(self, principal, action, baseline_id):
        _text(principal, "principal")
        try:
            allowed = self.entitlement(principal, action, baseline_id)
        except Exception as exc:
            raise Forbidden("entitlement unavailable") from exc
        if allowed is not True:
            raise Forbidden("not entitled")

    def _row(self, db, principal, action, baseline_id):
        _text(baseline_id, "baseline id", 64)
        self._entitled(principal, action, baseline_id)
        row = db.execute(
            "SELECT owner,name,revision,version FROM baselines WHERE id=?",
            (baseline_id,),
        ).fetchone()
        if not row:
            raise NotFound("baseline not found")
        if not db.execute(
            "SELECT 1 FROM members WHERE baseline_id=? AND principal=?",
            (baseline_id, principal),
        ).fetchone():
            raise Forbidden("baseline access denied")
        return row

    def _check_source(self, principal, reference, capture):
        try:
            allowed = self.source_entitlement is not None and self.source_entitlement(
                principal, reference, capture
            )
        except Exception as exc:
            raise Forbidden("source entitlement unavailable") from exc
        if allowed is not True:
            raise Forbidden("source access denied")

    def _capture(self, principal, reference):
        _text(reference, "source reference", 4096)
        try:
            capture = self.source_validator(principal, reference)
        except Exception as exc:
            raise Forbidden("source validation failed") from exc
        capture = json.loads(
            _json(
                validate_capture(capture, self.max_dependencies, self.max_capture_bytes)
            )
        )
        return capture

    def _retry(
        self,
        principal,
        request_id,
        action,
        baseline_id,
        expected,
        payload,
        operation_name,
    ):
        _text(request_id, "request id", 128)
        digest = hashlib.sha256(
            _json([action, operation_name, baseline_id, expected, payload]).encode()
        ).hexdigest()
        with closing(self._connect()) as db:
            previous = db.execute(
                "SELECT digest,baseline_id,result FROM requests WHERE principal=? AND request_id=?",
                (principal, request_id),
            ).fetchone()
            if not previous:
                return False, None
            if previous[0] != digest:
                raise Conflict("request id reused")
            self._entitled(principal, action, baseline_id)
            result = json.loads(previous[2])
            if result is not None:
                self._row(db, principal, "read", previous[1])
            return True, result

    @staticmethod
    def _withheld_receipt(result):
        return {
            "id": result["id"],
            "revision": result["revision"],
            "resultWithheld": True,
        }

    def _history_proofs(self, db, baseline_id, watch_id):
        # A surfaced time is trustworthy only if its originating occurrence is retained.
        if db.execute(
            "SELECT 1 FROM surfaced s WHERE s.baseline_id=? AND s.watch_id=? AND NOT EXISTS (SELECT 1 FROM occurrences o WHERE o.baseline_id=s.baseline_id AND o.watch_id=s.watch_id AND o.signature=s.signature AND o.observed=s.surfaced_at) LIMIT 1",
            (baseline_id, watch_id),
        ).fetchone():
            raise Forbidden("history proof unavailable")
        # Limit distinct evidence references before loading capture payloads.
        keys = db.execute(
            "SELECT DISTINCT evidence_key FROM occurrences WHERE baseline_id=? AND watch_id=? LIMIT ?",
            (baseline_id, watch_id, self.MAX_HISTORY_PROOFS + 1),
        ).fetchall()
        if len(keys) > self.MAX_HISTORY_PROOFS or any(key[0] is None for key in keys):
            raise Forbidden("history proof unavailable")
        proofs = []
        for (key,) in keys:
            evidence = db.execute(
                "SELECT reference,capture FROM evidence WHERE baseline_id=? AND evidence_key=?",
                (baseline_id, key),
            ).fetchone()
            if evidence is None:
                raise Forbidden("history proof unavailable")
            proofs.append(evidence)
        return proofs

    def _authorize_proofs(self, principal, proofs):
        for reference, capture in proofs:
            self._check_source(principal, json.loads(reference), json.loads(capture))

    def _recheck_revision(self, principal, baseline_id, revision):
        with closing(self._connect()) as db:
            current = self._row(db, principal, "read", baseline_id)
            if current[2] != revision:
                raise Conflict("revision changed")

    def _prepare_capture(self, principal, reference):
        capture = self._capture(principal, reference)
        self._check_source(principal, reference, capture)
        return capture

    def _preflight(self, principal, baseline_id, expected):
        with closing(self._connect()) as db:
            row = self._row(db, principal, "write", baseline_id)
            # A prior receipt is checked by _mutate; preflight must permit retries.
            return row

    def _admit_evidence(self, db, principal, baseline_id, reference, capture):
        reference_json, capture_json = _json(reference), _json(capture)
        return self._store_evidence(db, baseline_id, reference_json, capture_json)

    def _mutate(
        self,
        principal,
        request_id,
        action,
        baseline_id,
        expected,
        payload,
        operation,
        *,
        operation_name=None,
    ):
        _text(request_id, "request id", 128)
        if baseline_id is not None and (type(expected) is not int or expected < 1):
            raise Invalid("invalid expected revision")
        digest = hashlib.sha256(
            _json(
                [action, operation_name or action, baseline_id, expected, payload]
            ).encode()
        ).hexdigest()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                previous = db.execute(
                    "SELECT digest,baseline_id,result FROM requests WHERE principal=? AND request_id=?",
                    (principal, request_id),
                ).fetchone()
                if previous:
                    if previous[0] != digest:
                        raise Conflict("request id reused")
                    self._entitled(principal, action, baseline_id)
                    if action == "share" and payload[1] is False:
                        self._row(db, principal, "share", previous[1])
                    elif action != "delete":
                        self._row(db, principal, "read", previous[1])
                    db.commit()
                    retry_result = json.loads(previous[2])
                    if (
                        operation_name in ("evaluate_window", "append_occurrence")
                        and retry_result is not None
                    ):
                        return self._withheld_receipt(retry_result)
                    return retry_result
                if baseline_id is None:
                    self._entitled(principal, action, None)
                    row = None
                else:
                    row = self._row(db, principal, action, baseline_id)
                    if row[2] != expected:
                        raise Conflict("revision changed")
                result = operation(db, row)
                # Reserve a retry receipt for deleting every baseline and revoking
                # every non-owner membership, even when ordinary writes fill quota.
                reserved = db.execute("SELECT count(*) FROM baselines").fetchone()[0]
                reserved += db.execute(
                    "SELECT count(*) FROM members m JOIN baselines b ON b.id=m.baseline_id WHERE m.principal != b.owner"
                ).fetchone()[0]
                if (
                    db.execute("SELECT count(*) FROM requests").fetchone()[0]
                    + 1
                    + reserved
                    > self.max_requests
                ):
                    raise QuotaExceeded("request quota exceeded")
                db.execute(
                    "INSERT INTO requests (principal,request_id,digest,baseline_id,result,created_at) VALUES (?,?,?,?,?,?)",
                    (
                        principal,
                        request_id,
                        digest,
                        baseline_id or result["id"],
                        _json(result),
                        time.time(),
                    ),
                )
                db.commit()
                return result
            except Exception:
                db.rollback()
                raise

    def create(self, principal, request_id, name, reference):
        _text(name, "name")
        _text(reference, "source reference", 4096)

        def apply(db, row):
            if (
                db.execute("SELECT count(*) FROM baselines").fetchone()[0]
                >= self.max_baselines
            ):
                raise QuotaExceeded("baseline quota exceeded")
            capture = prepared_capture
            baseline_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO baselines VALUES (?,?,?,?,?)",
                (baseline_id, principal, name, 1, 1),
            )
            db.execute("INSERT INTO members VALUES (?,?)", (baseline_id, principal))
            evidence_key = self._admit_evidence(
                db, principal, baseline_id, reference, capture
            )
            db.execute(
                "INSERT INTO versions (baseline_id,version,capture,evidence_key) VALUES (?,?,?,?)",
                (baseline_id, 1, "", evidence_key),
            )
            return {"id": baseline_id, "revision": 1, "version": 1}

        # Resolve external evidence before acquiring the SQLite write lock.
        found, retry = self._retry(
            principal, request_id, "create", None, None, [name, reference], "create"
        )
        if found:
            return retry
        self._entitled(principal, "create", None)
        prepared_capture = self._prepare_capture(principal, reference)
        return self._mutate(
            principal, request_id, "create", None, None, [name, reference], apply
        )

    def version(self, principal, request_id, baseline_id, expected_revision, reference):
        _text(reference, "source reference", 4096)

        def apply(db, row):
            if row[3] >= self.max_versions:
                raise QuotaExceeded("version quota exceeded")
            capture = prepared_capture
            previous = json.loads(
                db.execute(
                    "SELECT e.capture FROM versions v JOIN evidence e ON e.baseline_id=v.baseline_id AND e.evidence_key=v.evidence_key WHERE v.baseline_id=? AND v.version=?",
                    (baseline_id, row[3]),
                ).fetchone()[0]
            )
            if not compatible(previous, capture):
                raise Invalid("incompatible evidence")
            evidence_key = self._admit_evidence(
                db, principal, baseline_id, reference, capture
            )
            db.execute(
                "INSERT INTO versions (baseline_id,version,capture,evidence_key) VALUES (?,?,?,?)",
                (baseline_id, row[3] + 1, "", evidence_key),
            )
            db.execute(
                "UPDATE baselines SET revision=revision+1,version=version+1 WHERE id=?",
                (baseline_id,),
            )
            return {"id": baseline_id, "revision": row[2] + 1, "version": row[3] + 1}

        found, retry = self._retry(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            reference,
            "version",
        )
        if found:
            return retry
        self._preflight(principal, baseline_id, expected_revision)
        self.get(principal, baseline_id)
        prepared_capture = self._prepare_capture(principal, reference)
        return self._mutate(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            reference,
            apply,
            operation_name="version",
        )

    def get(self, principal, baseline_id, version=None, *, action="read"):
        if action not in ("read", "export"):
            raise Invalid("invalid action")
        with closing(self._connect()) as db:
            row = self._row(db, principal, action, baseline_id)
            version = row[3] if version is None else version
            if type(version) is not int or version < 1:
                raise Invalid("invalid version")
            capture = db.execute(
                "SELECT e.reference,e.capture FROM versions v JOIN evidence e ON e.baseline_id=v.baseline_id AND e.evidence_key=v.evidence_key WHERE v.baseline_id=? AND v.version=?",
                (baseline_id, version),
            ).fetchone()
            if not capture:
                raise NotFound("version not found")
            reference, evidence = map(json.loads, capture)
        self._check_source(principal, reference, evidence)
        with closing(self._connect()) as db:
            current = self._row(db, principal, action, baseline_id)
            if current[2] != row[2]:
                raise Conflict("revision changed")
        return {
            "id": baseline_id,
            "name": row[1],
            "revision": row[2],
            "version": version,
            "capture": evidence,
        }

    def export(self, principal, baseline_id, version=None):
        return self.get(principal, baseline_id, version, action="export")

    def list(self, principal, *, after="", limit=50):
        if (
            not isinstance(after, str)
            or len(after) > 64
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise Invalid("invalid pagination")
        self._entitled(principal, "list", None)
        with closing(self._connect()) as db:
            result = []
            for baseline_id, name, revision, version in db.execute(
                "SELECT b.id,b.name,b.revision,b.version FROM baselines b JOIN members m ON m.baseline_id=b.id WHERE m.principal=? AND b.id>? ORDER BY b.id",
                (principal, after),
            ):
                try:
                    self._entitled(principal, "list", baseline_id)
                    self._entitled(principal, "read", baseline_id)
                except Forbidden:
                    continue
                result.append(
                    {
                        "id": baseline_id,
                        "name": name,
                        "revision": revision,
                        "version": version,
                    }
                )
                if len(result) > limit:
                    break
            return {
                "items": result[:limit],
                "next": result[limit - 1]["id"] if len(result) > limit else None,
            }

    def share(
        self, principal, request_id, baseline_id, expected_revision, member, grant
    ):
        _text(member, "member")
        if type(grant) is not bool:
            raise Invalid("invalid grant")

        def apply(db, row):
            if row[0] != principal:
                raise Forbidden("owner required")
            if member == row[0]:
                raise Invalid("owner membership fixed")
            exists = db.execute(
                "SELECT 1 FROM members WHERE baseline_id=? AND principal=?",
                (baseline_id, member),
            ).fetchone()
            if grant and not exists:
                if (
                    db.execute(
                        "SELECT count(*) FROM members WHERE baseline_id=?",
                        (baseline_id,),
                    ).fetchone()[0]
                    >= self.max_members
                ):
                    raise QuotaExceeded("membership quota exceeded")
                db.execute("INSERT INTO members VALUES (?,?)", (baseline_id, member))
            elif not grant:
                if not exists:
                    raise Invalid("member not found")
                db.execute(
                    "DELETE FROM members WHERE baseline_id=? AND principal=?",
                    (baseline_id, member),
                )
            db.execute(
                "UPDATE baselines SET revision=revision+1 WHERE id=?", (baseline_id,)
            )
            return {"id": baseline_id, "revision": row[2] + 1}

        return self._mutate(
            principal,
            request_id,
            "share",
            baseline_id,
            expected_revision,
            [member, grant],
            apply,
        )

    def delete(self, principal, request_id, baseline_id, expected_revision):
        def apply(db, row):
            if row[0] != principal:
                raise Forbidden("owner required")
            db.execute(
                "UPDATE requests SET result='null',created_at=? WHERE baseline_id=?",
                (time.time(), baseline_id),
            )
            db.execute("DELETE FROM baselines WHERE id=?", (baseline_id,))
            return {"id": baseline_id, "deleted": True}

        return self._mutate(
            principal, request_id, "delete", baseline_id, expected_revision, {}, apply
        )

    def set_watch(
        self, principal, request_id, baseline_id, expected_revision, definition
    ):
        if not isinstance(definition, dict) or set(definition) != {
            "id",
            "threshold",
            "cooldownSeconds",
            "expectedWindows",
        }:
            raise Invalid("invalid watch")
        _text(definition["id"], "watch id", 128)
        if (
            type(definition["threshold"]) is not int
            or not 1 <= definition["threshold"] <= self.max_occurrences
            or not _number(definition["cooldownSeconds"])
            or definition["cooldownSeconds"] < 0
            or not isinstance(definition["expectedWindows"], list)
            or len(definition["expectedWindows"]) > 100
        ):
            raise Invalid("invalid watch")
        for window in definition["expectedWindows"]:
            _window(window)

        def apply(db, row):
            exists = db.execute(
                "SELECT 1 FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, definition["id"]),
            ).fetchone()
            if (
                not exists
                and db.execute(
                    "SELECT count(*) FROM watches WHERE baseline_id=?", (baseline_id,)
                ).fetchone()[0]
                >= self.max_watches
            ):
                raise QuotaExceeded("watch quota exceeded")
            db.execute(
                "INSERT INTO watches VALUES (?,?,?,?) ON CONFLICT(baseline_id,id) DO UPDATE SET definition=excluded.definition",
                (baseline_id, definition["id"], _json(definition), row[3]),
            )
            db.execute(
                "UPDATE baselines SET revision=revision+1 WHERE id=?", (baseline_id,)
            )
            return {
                "id": baseline_id,
                "revision": row[2] + 1,
                "watch_id": definition["id"],
            }

        return self._mutate(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            definition,
            apply,
            operation_name="set_watch",
        )

    def append_occurrence(
        self,
        principal,
        request_id,
        baseline_id,
        expected_revision,
        watch_id,
        signature_value,
        reference,
    ):
        _text(watch_id, "watch id", 128)
        _text(signature_value, "signature", 4096)
        _text(reference, "source reference", 4096)

        def apply(db, row):
            watch = db.execute(
                "SELECT baseline_version FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, watch_id),
            ).fetchone()
            if not watch:
                raise NotFound("watch not found")
            capture = prepared_capture
            observed_at = self.clock()
            if not _number(observed_at) or observed_at < 0:
                raise RuntimeError("trusted clock unavailable")
            if observed_at < capture["coverage"]["knowledgeHorizon"]:
                raise Invalid("evidence horizon is in the future")
            baseline = json.loads(
                db.execute(
                    "SELECT e.capture FROM versions v JOIN evidence e ON e.baseline_id=v.baseline_id AND e.evidence_key=v.evidence_key WHERE v.baseline_id=? AND v.version=?",
                    (baseline_id, watch[0]),
                ).fetchone()[0]
            )
            if signature_value not in compare_findings(baseline, capture):
                raise Invalid("signature does not identify a finding")
            window = capture["coverage"]["returned"]
            if observed_at < window["end"]:
                raise Invalid("observation precedes window")
            existing = db.execute(
                "SELECT seq FROM occurrences WHERE baseline_id=? AND watch_id=? AND signature=? AND start=? AND end=?",
                (
                    baseline_id,
                    watch_id,
                    signature_value,
                    window["start"],
                    window["end"],
                ),
            ).fetchone()
            if not existing:
                if (
                    db.execute(
                        "SELECT count(*) FROM occurrences WHERE baseline_id=?",
                        (baseline_id,),
                    ).fetchone()[0]
                    >= self.max_occurrences
                ):
                    raise QuotaExceeded("occurrence quota exceeded")
                evidence_key = self._admit_evidence(
                    db, principal, baseline_id, reference, capture
                )
                db.execute(
                    "INSERT INTO occurrences(baseline_id,watch_id,signature,start,end,observed,evidence_key) VALUES (?,?,?,?,?,?,?)",
                    (
                        baseline_id,
                        watch_id,
                        signature_value,
                        window["start"],
                        window["end"],
                        observed_at,
                        evidence_key,
                    ),
                )
                db.execute(
                    "UPDATE baselines SET revision=revision+1 WHERE id=?",
                    (baseline_id,),
                )
            return {
                "id": baseline_id,
                "revision": row[2] + (not bool(existing)),
                "inserted": not bool(existing),
            }

        found, retry = self._retry(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            [watch_id, signature_value, reference],
            "append_occurrence",
        )
        if found:
            return self._withheld_receipt(retry) if retry is not None else None
        self._preflight(principal, baseline_id, expected_revision)
        with closing(self._connect()) as db:
            watch = db.execute(
                "SELECT baseline_version FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, watch_id),
            ).fetchone()
        if not watch:
            raise NotFound("watch not found")
        self.get(principal, baseline_id, watch[0])
        prepared_capture = self._prepare_capture(principal, reference)
        window = prepared_capture["coverage"]["returned"]
        with closing(self._connect()) as db:
            existing = db.execute(
                "SELECT e.reference,e.capture FROM occurrences o LEFT JOIN evidence e ON e.baseline_id=o.baseline_id AND e.evidence_key=o.evidence_key WHERE o.baseline_id=? AND o.watch_id=? AND o.signature=? AND o.start=? AND o.end=?",
                (
                    baseline_id,
                    watch_id,
                    signature_value,
                    window["start"],
                    window["end"],
                ),
            ).fetchone()
        if existing:
            if any(value is None for value in existing):
                raise Forbidden("history proof unavailable")
            self._authorize_proofs(principal, [existing])
        return self._mutate(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            [watch_id, signature_value, reference],
            apply,
            operation_name="append_occurrence",
        )

    def evaluate_window(
        self,
        principal,
        request_id,
        baseline_id,
        expected_revision,
        watch_id,
        baseline_version,
        reference,
    ):
        """Evaluate a trusted complete capture against the watch's pinned version."""
        _text(watch_id, "watch id", 128)
        _text(reference, "source reference", 4096)
        if type(baseline_version) is not int or baseline_version < 1:
            raise Invalid("invalid baseline version")
        payload = [watch_id, baseline_version, reference]
        found, retry = self._retry(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            payload,
            "evaluate_window",
        )
        if found:
            return self._withheld_receipt(retry) if retry is not None else None
        row = self._preflight(principal, baseline_id, expected_revision)
        if row[2] != expected_revision:
            raise Conflict("revision changed")
        with closing(self._connect()) as db:
            watch = db.execute(
                "SELECT definition,baseline_version FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, watch_id),
            ).fetchone()
            proofs = self._history_proofs(db, baseline_id, watch_id)
        if not watch:
            raise NotFound("watch not found")
        if watch[1] != baseline_version:
            raise Conflict("watch version changed")
        baseline = self.get(principal, baseline_id, baseline_version)["capture"]
        self._authorize_proofs(principal, proofs)
        capture = self._prepare_capture(principal, reference)
        findings = sorted(compare_findings(baseline, capture))
        now = self.clock()
        if not _number(now) or now < 0:
            raise RuntimeError("trusted clock unavailable")
        if now < capture["coverage"]["knowledgeHorizon"]:
            raise Invalid("evidence horizon is in the future")
        window = capture["coverage"]["returned"]

        def apply(db, row):
            current_watch = db.execute(
                "SELECT definition,baseline_version FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, watch_id),
            ).fetchone()
            if current_watch != watch:
                raise Conflict("watch changed")
            definition = json.loads(watch[0])
            inserted = surfaced = 0
            for sig in findings:
                exists = db.execute(
                    "SELECT 1 FROM occurrences WHERE baseline_id=? AND watch_id=? AND signature=? AND start=? AND end=?",
                    (baseline_id, watch_id, sig, window["start"], window["end"]),
                ).fetchone()
                if exists:
                    continue
                if (
                    db.execute(
                        "SELECT count(*) FROM occurrences WHERE baseline_id=?",
                        (baseline_id,),
                    ).fetchone()[0]
                    >= self.max_occurrences
                ):
                    raise QuotaExceeded("occurrence quota exceeded")
                key = self._admit_evidence(
                    db, principal, baseline_id, reference, capture
                )
                db.execute(
                    "INSERT INTO occurrences(baseline_id,watch_id,signature,start,end,observed,evidence_key) VALUES (?,?,?,?,?,?,?)",
                    (
                        baseline_id,
                        watch_id,
                        sig,
                        window["start"],
                        window["end"],
                        now,
                        key,
                    ),
                )
                inserted += 1
                count = db.execute(
                    "SELECT count(*) FROM occurrences WHERE baseline_id=? AND watch_id=? AND signature=?",
                    (baseline_id, watch_id, sig),
                ).fetchone()[0]
                last = db.execute(
                    "SELECT surfaced_at FROM surfaced WHERE baseline_id=? AND watch_id=? AND signature=?",
                    (baseline_id, watch_id, sig),
                ).fetchone()
                expected = any(
                    w["start"] < window["end"] and window["start"] < w["end"]
                    for w in definition["expectedWindows"]
                )
                if (
                    count >= definition["threshold"]
                    and not expected
                    and (last is None or now >= last[0] + definition["cooldownSeconds"])
                ):
                    db.execute(
                        "INSERT INTO surfaced VALUES (?,?,?,?) ON CONFLICT(baseline_id,watch_id,signature) DO UPDATE SET surfaced_at=excluded.surfaced_at",
                        (baseline_id, watch_id, sig, now),
                    )
                    surfaced += 1
            if inserted:
                db.execute(
                    "UPDATE baselines SET revision=revision+1 WHERE id=?",
                    (baseline_id,),
                )
            return {
                "id": baseline_id,
                "revision": row[2] + bool(inserted),
                "inserted": inserted,
                "surfaced": surfaced,
            }

        return self._mutate(
            principal,
            request_id,
            "write",
            baseline_id,
            expected_revision,
            payload,
            apply,
            operation_name="evaluate_window",
        )

    def list_versions(self, principal, baseline_id, *, after=0, limit=50):
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise Invalid("invalid pagination")
        with closing(self._connect()) as db:
            self._row(db, principal, "read", baseline_id)
            rows = db.execute(
                "SELECT version FROM versions WHERE baseline_id=? AND version>? ORDER BY version LIMIT ?",
                (baseline_id, after, limit + 1),
            ).fetchall()
            items = [{"version": row[0]} for row in rows[:limit]]
            return {
                "items": items,
                "next": items[-1]["version"] if len(rows) > limit else None,
            }

    def list_watches(self, principal, baseline_id, *, after="", limit=50):
        if (
            not isinstance(after, str)
            or len(after) > 128
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise Invalid("invalid pagination")
        with closing(self._connect()) as db:
            self._row(db, principal, "read", baseline_id)
            rows = db.execute(
                "SELECT id,definition,baseline_version FROM watches WHERE baseline_id=? AND id>? ORDER BY id LIMIT ?",
                (baseline_id, after, limit + 1),
            ).fetchall()
            items = [
                dict(json.loads(row[1]), baselineVersion=row[2]) for row in rows[:limit]
            ]
            return {
                "items": items,
                "next": items[-1]["id"] if len(rows) > limit else None,
            }

    def _page_evidence(self, db, baseline_id, keys):
        """Load each page evidence payload once, irrespective of occurrence count."""
        result = {}
        for key in keys:
            if key is None:
                raise Forbidden("history proof unavailable")
            proof = db.execute(
                "SELECT reference,capture FROM evidence WHERE baseline_id=? AND evidence_key=?",
                (baseline_id, key),
            ).fetchone()
            if not proof or any(value is None for value in proof):
                raise Forbidden("history proof unavailable")
            result[key] = proof
        return result

    def occurrences(self, principal, baseline_id, watch_id, *, after=0, limit=50):
        _text(watch_id, "watch id", 128)
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise Invalid("invalid pagination")
        with closing(self._connect()) as db:
            row = self._row(db, principal, "read", baseline_id)
            watch = db.execute(
                "SELECT baseline_version FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, watch_id),
            ).fetchone()
            if not watch:
                raise NotFound("watch not found")
            rows = db.execute(
                "SELECT seq,signature,start,end,observed,evidence_key FROM occurrences WHERE baseline_id=? AND watch_id=? AND seq>? ORDER BY seq LIMIT ?",
                (baseline_id, watch_id, after, min(limit + 1, self.MAX_HISTORY_PROOFS)),
            ).fetchall()
            proofs = self._page_evidence(db, baseline_id, {r[5] for r in rows})
        baseline = self.get(principal, baseline_id, watch[0])["capture"]
        self._authorize_proofs(principal, proofs.values())
        # Classify only retained proof, including lookahead. A legacy or corrupt
        # occurrence that no longer represents a finding must fail closed.
        classifications = {}
        try:
            validate_capture(baseline, self.max_dependencies, self.max_capture_bytes)
            prepared = _prepare_baseline(baseline)
            requested = {}
            for r in rows:
                requested.setdefault(r[5], set()).add(r[1])
            for evidence_key, selected in requested.items():
                evidence = json.loads(proofs[evidence_key][1])
                validate_capture(
                    evidence, self.max_dependencies, self.max_capture_bytes
                )
                classifications[evidence_key] = (
                    evidence["coverage"]["returned"],
                    compare_findings(
                        baseline, evidence, prepared=prepared, selected=selected
                    ),
                )
        except (Invalid, QuotaExceeded, KeyError, TypeError, ValueError) as exc:
            raise Forbidden("history proof unavailable") from exc
        for r in rows:
            window, findings = classifications[r[5]]
            if window != {"start": r[2], "end": r[3]} or r[1] not in findings:
                raise Forbidden("history proof unavailable")
        items = [
            {
                "seq": r[0],
                "signature": r[1],
                "window": {"start": r[2], "end": r[3]},
                "observedAt": r[4],
                "baselineVersion": watch[0],
                "changeKinds": classifications[r[5]][1][r[1]],
            }
            for r in rows[:limit]
        ]
        has_more = len(rows) > limit or (
            limit == self.MAX_HISTORY_PROOFS and len(rows) == limit
        )
        self._recheck_revision(principal, baseline_id, row[2])
        return {"items": items, "next": items[-1]["seq"] if has_more else None}

    def evaluate(self, principal, baseline_id, watch_id, signature_value, now):
        _text(watch_id, "watch id", 128)
        _text(signature_value, "signature", 4096)
        if not _number(now) or now < 0:
            raise Invalid("invalid time")
        with closing(self._connect()) as db:
            row = self._row(db, principal, "read", baseline_id)
            watch = db.execute(
                "SELECT definition,baseline_version FROM watches WHERE baseline_id=? AND id=?",
                (baseline_id, watch_id),
            ).fetchone()
            if not watch:
                raise NotFound("watch not found")
            proofs = self._history_proofs(db, baseline_id, watch_id)
            count = db.execute(
                "SELECT count(*) FROM occurrences WHERE baseline_id=? AND watch_id=? AND signature=? AND observed<=?",
                (baseline_id, watch_id, signature_value, now),
            ).fetchone()[0]
            last_row = db.execute(
                "SELECT surfaced_at FROM surfaced WHERE baseline_id=? AND watch_id=? AND signature=?",
                (baseline_id, watch_id, signature_value),
            ).fetchone()
        self.get(principal, baseline_id, watch[1])
        self._authorize_proofs(principal, proofs)
        self._recheck_revision(principal, baseline_id, row[2])
        definition = json.loads(watch[0])
        last = last_row[0] if last_row else None
        # Only the most recent surface is retained. An earlier query cannot
        # reconstruct whether a prior surface was still cooling down.
        if last is not None and now < last:
            raise Invalid("historical cooldown unavailable")
        return {
            "count": count,
            "thresholdMet": count >= definition["threshold"],
            "expected": any(
                w["start"] <= now < w["end"] for w in definition["expectedWindows"]
            ),
            "coolingDown": last is not None
            and now < last + definition["cooldownSeconds"],
        }
