"""Insert-only CAS ledger. Collection POST uniqueness is the only write primitive."""

import hashlib
import json
import re

TOKEN = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
KIND = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")


class LedgerError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code = status, code


class Invalid(LedgerError):
    def __init__(self, message="Invalid ledger operation."):
        super().__init__(400, "invalid", message)


class Conflict(LedgerError):
    def __init__(self, message="The record changed. Reload before saving."):
        super().__init__(409, "conflict", message)


class Uncertain(LedgerError):
    def __init__(self, message="Save outcome is uncertain. Retry the same request."):
        super().__init__(503, "uncertain", message)


class Unavailable(LedgerError):
    def __init__(self, message="Ledger evidence is unavailable or incomplete."):
        super().__init__(503, "unavailable", message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    if not isinstance(value, str):
        value = canonical(value)
    return hashlib.sha256(value.encode()).hexdigest()


def root_key(kind):
    if not KIND.fullmatch(kind):
        raise Invalid("Unsupported ledger kind.")
    return kind + "_root"


def successor_key(kind, revision):
    if not KIND.fullmatch(kind):
        raise Invalid("Unsupported ledger kind.")
    return kind + "_after_" + digest(revision)


class RecordLedger:
    """A store supplies bounded scan and insert-only operations."""

    def __init__(self, store, kind, max_records=1024):
        if not KIND.fullmatch(kind):
            raise Invalid("Unsupported ledger kind.")
        if type(max_records) is not int or not 1 <= max_records <= 4096:
            raise Invalid("Unsupported ledger bound.")
        self.store, self.kind, self.max_records = store, kind, max_records

    def inspect(self):
        rows = self.store.scan(self.max_records + 1)
        if not isinstance(rows, list) or len(rows) > self.max_records:
            raise Unavailable("Ledger history limit reached; writes are disabled.")
        records = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("_key"), str):
                raise Unavailable()
            if row["_key"] in records:
                raise Unavailable()
            records[row["_key"]] = row
        root = records.get(root_key(self.kind))
        if root is None:
            if records:
                raise Unavailable()
            return None, [], len(rows)
        previous = None
        key, chain, ids = root_key(self.kind), [], set()
        while key in records:
            row = records[key]
            try:
                payload = json.loads(row["payload_json"])
                if (
                    row.get("format") != 2
                    or row.get("kind") != self.kind
                    or row.get("previous_revision") != previous
                    or not isinstance(row.get("request_id"), str)
                    or not TOKEN.fullmatch(row["request_id"])
                    or row["request_id"] in ids
                    or row.get("operation_fingerprint")
                    != self.fingerprint(payload, previous, row["request_id"])
                    or row.get("revision")
                    != digest(["revision", row["operation_fingerprint"]])
                ):
                    raise Unavailable()
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise Unavailable() from exc
            chain.append(row)
            ids.add(row["request_id"])
            previous = row["revision"]
            key = successor_key(self.kind, previous)
            if len(chain) > self.max_records:
                raise Unavailable("Ledger history limit reached; writes are disabled.")
        if len(chain) != len(records):
            raise Unavailable()
        return json.loads(chain[-1]["payload_json"]), chain, len(rows)

    def fingerprint(self, payload, previous, request_id):
        return digest([self.kind, previous, request_id, payload])

    def read(self):
        payload, chain, count = self.inspect()
        return {
            "state": "configured" if payload is not None else "absent",
            "payload": payload,
            "revision": chain[-1]["revision"] if chain else None,
            "recordCount": count,
            "maxRecords": self.max_records,
        }

    def write(self, payload, expected_revision, request_id):
        if not isinstance(payload, dict):
            raise Invalid("Invalid ledger payload.")
        if not isinstance(request_id, str) or not TOKEN.fullmatch(request_id):
            raise Invalid("Invalid request identity.")
        if expected_revision is not None and (
            not isinstance(expected_revision, str)
            or not TOKEN.fullmatch(expected_revision)
        ):
            raise Invalid("Invalid expected revision.")
        fingerprint = self.fingerprint(payload, expected_revision, request_id)
        current, chain, count = self.inspect()
        for row in chain:
            if row["request_id"] == request_id:
                if row["operation_fingerprint"] != fingerprint:
                    raise Conflict("Request ID was used with a different payload.")
                return self._verified(row, chain, current, count)
        head = chain[-1]["revision"] if chain else None
        if head != expected_revision:
            raise Conflict()
        if count >= self.max_records:
            raise Unavailable("Ledger history limit reached; writes are disabled.")
        revision = digest(["revision", fingerprint])
        document = {
            "_key": successor_key(self.kind, expected_revision)
            if chain
            else root_key(self.kind),
            "format": 2,
            "kind": self.kind,
            "previous_revision": expected_revision,
            "request_id": request_id,
            "operation_fingerprint": fingerprint,
            "revision": revision,
            "payload_json": canonical(payload),
        }
        try:
            self.store.insert(document)
        except Exception:
            pass
        try:
            current, chain, count = self.inspect()
        except Exception as exc:
            raise Uncertain() from exc
        for row in chain:
            if row["_key"] == document["_key"]:
                if row["operation_fingerprint"] == fingerprint:
                    return self._verified(row, chain, current, count)
                raise Conflict()
        raise Uncertain()

    def _verified(self, row, chain, current, count):
        return {
            "state": "configured",
            "payload": current,
            "committedRevision": row["revision"],
            "requestId": row["request_id"],
            "superseded": not chain or row["revision"] != chain[-1]["revision"],
            "recordCount": count,
            "maxRecords": self.max_records,
        }
