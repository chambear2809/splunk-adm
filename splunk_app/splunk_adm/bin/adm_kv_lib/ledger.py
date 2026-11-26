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


class Forbidden(LedgerError):
    def __init__(self, message="Permission denied."):
        super().__init__(403, "forbidden", message)


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


def epoch_key(kind, epoch):
    if not KIND.fullmatch(kind):
        raise Invalid("Unsupported ledger kind.")
    return kind + "_epoch_" + str(epoch)


LIMIT_MESSAGE = (
    "Ledger history limit reached; writes are disabled until an administrator "
    "compacts the ledger."
)
BLOCKED_MESSAGE = (
    "An interrupted ledger compaction is blocking saves; an administrator must "
    "retry compaction."
)
MAX_EPOCH = 1_000_000
# A compaction of a full ledger inserts a seal and an epoch root before cleanup.
SLACK = 2
SUCCESSOR = re.compile(r"[a-z][a-z0-9_]{0,31}_after_[0-9a-f]{64}\Z")


def _epoch_of(row):
    epoch = row.get("epoch", 0)
    fmt = row.get("format")
    if (
        type(epoch) is not int
        or not 0 <= epoch <= MAX_EPOCH
        or fmt not in (2, 3)
        or (fmt == 2) != (epoch == 0)
    ):
        raise Unavailable()
    return epoch


class Snapshot:
    __slots__ = (
        "payload",
        "chain",
        "count",
        "residue",
        "garbage",
        "records",
        "pending",
    )

    def __init__(self, payload, chain, count, residue, garbage, records, pending):
        self.payload, self.chain, self.count = payload, chain, count
        self.residue, self.garbage, self.records = residue, garbage, records
        self.pending = pending

    @property
    def head(self):
        return self.chain[-1]["revision"] if self.chain else None

    @property
    def epoch(self):
        return self.chain[0].get("epoch", 0) if self.chain else 0

    @property
    def debris(self):
        return self.residue + self.garbage


class RecordLedger:
    """A store supplies bounded scan, insert-only writes, and debris deletion.

    History is a hash chain per epoch. Compaction first inserts a *seal* in the
    successor slot of the current head, so no later write can extend the old
    epoch, then an *epoch root* at the fixed key for the next epoch number, so
    at most one compaction can win that epoch. A root is authoritative only
    while its own seal exists. A seal in the head's successor slot without its
    root is *pending*: it is never deleted, and any compaction finishes it with
    the root it fully determines. Rows of older epochs (residue), other seals
    and unsealed roots (garbage) are debris that only compaction deletes; none
    of them can ever become authoritative again, so deleting debris found by an
    earlier scan is always safe.
    """

    def __init__(self, store, kind, max_records=1024):
        if not KIND.fullmatch(kind):
            raise Invalid("Unsupported ledger kind.")
        if type(max_records) is not int or not 1 <= max_records <= 4096:
            raise Invalid("Unsupported ledger bound.")
        self.store, self.kind, self.max_records = store, kind, max_records

    def _check_shape(self, row, epoch):
        key = row["_key"]
        is_root, is_seal = row.get("epoch_root", False), row.get("seal", False)
        if type(is_root) is not bool or type(is_seal) is not bool:
            raise Unavailable()
        if is_root and is_seal:
            raise Unavailable()
        if is_root:
            valid = epoch >= 1 and key == epoch_key(self.kind, epoch)
        elif is_seal:
            previous = row.get("previous_revision")
            valid = (
                epoch >= 1
                and isinstance(previous, str)
                and TOKEN.fullmatch(previous) is not None
                and key == successor_key(self.kind, previous)
            )
        else:
            valid = key == root_key(self.kind) or (
                key.startswith(self.kind + "_after_")
                and SUCCESSOR.fullmatch(key) is not None
            )
        if not valid:
            raise Unavailable()

    def _sealed(self, records, key, epoch):
        root = records[key]
        previous, request_id = root.get("previous_revision"), root.get("request_id")
        if not isinstance(previous, str) or not isinstance(request_id, str):
            return False
        seal = records.get(successor_key(self.kind, previous))
        return (
            seal is not None
            and seal.get("seal") is True
            and seal.get("epoch") == epoch
            and seal.get("kind") == self.kind
            and seal.get("request_id") == request_id
            and seal.get("previous_revision") == previous
            and seal.get("operation_fingerprint")
            == self.seal_fingerprint(previous, request_id, epoch)
        )

    def inspect(self, slack=SLACK):
        rows = self.store.scan(self.max_records + slack + 1)
        if not isinstance(rows, list) or len(rows) > self.max_records + slack:
            raise Unavailable(LIMIT_MESSAGE)
        records, epochs = {}, {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("_key"), str):
                raise Unavailable()
            if row["_key"] in records:
                raise Unavailable()
            epochs[row["_key"]] = _epoch_of(row)
            self._check_shape(row, epochs[row["_key"]])
            records[row["_key"]] = row
        if not records:
            return Snapshot(None, [], 0, [], [], records, None)
        epoch, start, seal_key = 0, root_key(self.kind), None
        roots = [k for k, row in records.items() if row.get("epoch_root") is True]
        for key in sorted(roots, key=lambda k: -epochs[k]):
            if self._sealed(records, key, epochs[key]):
                epoch, start = epochs[key], key
                seal_key = successor_key(self.kind, records[key]["previous_revision"])
                break
        if start not in records:
            # Epoch 0 starts at the fixed root; it is deleted only after a sealed
            # epoch root exists, so its absence with any rows is never valid.
            raise Unavailable()
        previous = records[start]["previous_revision"] if epoch else None
        key, chain, ids = start, [], set()
        while key in records and records[key].get("seal") is not True:
            row = records[key]
            try:
                payload = json.loads(row["payload_json"])
                is_root = row.get("epoch_root", False)
                if (
                    epochs[key] != epoch
                    or is_root is not (bool(epoch) and not chain)
                    or row.get("kind") != self.kind
                    or row.get("previous_revision") != previous
                    or not isinstance(row.get("request_id"), str)
                    or not TOKEN.fullmatch(row["request_id"])
                    or row["request_id"] in ids
                    or row.get("operation_fingerprint")
                    != self.fingerprint(
                        payload, previous, row["request_id"], epoch, is_root
                    )
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
        accounted = {row["_key"] for row in chain}
        if seal_key is not None:
            accounted.add(seal_key)
        pending = records.get(key) if chain else None
        if pending is not None:
            head = chain[-1]["revision"]
            if (
                pending.get("seal") is not True
                or epochs[key] != epoch + 1
                or pending.get("kind") != self.kind
                or pending.get("previous_revision") != head
                or not isinstance(pending.get("request_id"), str)
                or not TOKEN.fullmatch(pending["request_id"])
                or pending.get("operation_fingerprint")
                != self.seal_fingerprint(head, pending["request_id"], epoch + 1)
            ):
                raise Unavailable()
            accounted.add(key)
        residue, garbage = [], []
        for key, row in sorted(records.items()):
            if key in accounted:
                continue
            if epochs[key] < epoch:
                residue.append(key)
            elif row.get("seal") is True or row.get("epoch_root") is True:
                garbage.append(key)
            else:
                raise Unavailable()
        if len(rows) > self.max_records and not (residue or garbage or pending):
            raise Unavailable(LIMIT_MESSAGE)
        payload = json.loads(chain[-1]["payload_json"]) if chain else None
        return Snapshot(payload, chain, len(rows), residue, garbage, records, pending)

    def fingerprint(self, payload, previous, request_id, epoch=0, epoch_root=False):
        if epoch == 0:
            return digest([self.kind, previous, request_id, payload])
        return digest(
            [self.kind, previous, request_id, payload, epoch, bool(epoch_root)]
        )

    def seal_fingerprint(self, previous, request_id, epoch):
        return digest([self.kind, previous, request_id, epoch, "seal"])

    def read(self):
        return self._status(self.inspect())

    def _status(self, snap):
        return {
            "state": "configured" if snap.payload is not None else "absent",
            "payload": snap.payload,
            "revision": snap.head,
            "recordCount": snap.count,
            "maxRecords": self.max_records,
            "epoch": snap.epoch,
            "residueCount": len(snap.debris),
        }

    @staticmethod
    def _check_identity(expected_revision, request_id):
        if not isinstance(request_id, str) or not TOKEN.fullmatch(request_id):
            raise Invalid("Invalid request identity.")
        if expected_revision is not None and (
            not isinstance(expected_revision, str)
            or not TOKEN.fullmatch(expected_revision)
        ):
            raise Invalid("Invalid expected revision.")

    def write(self, payload, expected_revision, request_id, precheck=None):
        """Append ``payload`` after ``expected_revision``.

        ``precheck`` runs against the head payload the write will supersede, so
        authorization decisions and the CAS observe the same scan.
        """
        if not isinstance(payload, dict):
            raise Invalid("Invalid ledger payload.")
        self._check_identity(expected_revision, request_id)
        snap = self.inspect()
        epoch = snap.epoch
        fingerprint = self.fingerprint(payload, expected_revision, request_id, epoch)
        for row in snap.chain:
            if row["request_id"] == request_id:
                if row["operation_fingerprint"] != fingerprint:
                    raise Conflict("Request ID was used with a different payload.")
                return self._verified(row, snap)
        if snap.head != expected_revision:
            raise Conflict()
        target = (
            successor_key(self.kind, expected_revision)
            if snap.chain
            else root_key(self.kind)
        )
        if snap.pending is not None:
            raise Unavailable(BLOCKED_MESSAGE)
        if snap.count >= self.max_records:
            raise Unavailable(LIMIT_MESSAGE)
        if precheck is not None:
            precheck(snap.payload)
        document = {
            "_key": target,
            "format": 3 if epoch else 2,
            "kind": self.kind,
            "previous_revision": expected_revision,
            "request_id": request_id,
            "operation_fingerprint": fingerprint,
            "revision": digest(["revision", fingerprint]),
            "payload_json": canonical(payload),
        }
        if epoch:
            document["epoch"] = epoch
        self._insert(document)
        try:
            snap = self.inspect()
        except Exception as exc:
            raise Uncertain() from exc
        for row in snap.chain:
            if row["_key"] == target:
                if row["operation_fingerprint"] == fingerprint:
                    return self._verified(row, snap)
                raise Conflict()
        if target in snap.records:
            raise Conflict()
        raise Uncertain()

    def compact(self, expected_revision, request_id):
        """Seal the head, open the next epoch with its payload, delete debris.

        Retrying with the same request ID resumes an interrupted compaction.
        """
        self._check_identity(expected_revision, request_id)
        if expected_revision is None:
            raise Invalid("Compaction requires the current revision.")
        # A wider first scan lets cleanup recover a ledger over-filled by
        # delayed writers; only debris is deleted before the strict scan.
        snap = self._purge(self.inspect(slack=self.max_records + SLACK))
        if not snap.chain:
            raise Invalid("The ledger has no history to compact.")
        root = snap.chain[0]
        if root.get("epoch_root") is True and root["request_id"] == request_id:
            return self._verified(root, snap)
        if any(row["request_id"] == request_id for row in snap.chain):
            raise Conflict("Request ID was used with a different payload.")
        if snap.head != expected_revision:
            raise Conflict()
        seal = snap.pending
        if seal is None:
            if snap.epoch and len(snap.chain) == 1:
                return self._status(snap)
            seal_key = successor_key(self.kind, expected_revision)
            epoch = snap.epoch + 1
            self._insert(
                {
                    "_key": seal_key,
                    "format": 3,
                    "epoch": epoch,
                    "seal": True,
                    "kind": self.kind,
                    "previous_revision": expected_revision,
                    "request_id": request_id,
                    "operation_fingerprint": self.seal_fingerprint(
                        expected_revision, request_id, epoch
                    ),
                }
            )
            snap = self._inspect_after_insert()
            seal = snap.pending
            if seal is None:
                if seal_key in snap.records:
                    raise Conflict()
                raise Uncertain()
            if snap.head != expected_revision:
                raise Conflict()
        # Finish this or another caller's pending seal: its root is fully
        # determined, so racing finishers insert byte-identical rows.
        epoch = seal["epoch"]
        fingerprint = self.fingerprint(
            snap.payload, expected_revision, seal["request_id"], epoch, True
        )
        root_doc = {
            "_key": epoch_key(self.kind, epoch),
            "format": 3,
            "epoch": epoch,
            "epoch_root": True,
            "kind": self.kind,
            "previous_revision": expected_revision,
            "request_id": seal["request_id"],
            "operation_fingerprint": fingerprint,
            "revision": digest(["revision", fingerprint]),
            "payload_json": canonical(snap.payload),
        }
        self._insert(root_doc)
        opened = self._inspect_after_insert()
        if not opened.chain or opened.chain[0]["_key"] != root_doc["_key"]:
            if root_doc["_key"] in opened.records:
                raise Conflict()
            raise Uncertain()
        if opened.chain[0]["operation_fingerprint"] != fingerprint:
            raise Conflict()
        result = self._verified(opened.chain[0], opened)
        cleaned = self._purge(opened)
        result.update(
            recordCount=cleaned.count,
            epoch=cleaned.epoch,
            residueCount=len(cleaned.debris),
        )
        return result

    def _insert(self, document):
        try:
            self.store.insert(document)
        except Forbidden:
            raise
        except Exception:
            pass

    def _inspect_after_insert(self):
        try:
            return self.inspect()
        except Exception as exc:
            raise Uncertain() from exc

    def _purge(self, snap):
        if not snap.debris:
            return snap
        for key in snap.debris:
            try:
                self.store.delete(key)
            except Forbidden:
                raise
            except Exception as exc:
                raise Uncertain(
                    "Compaction cleanup is incomplete. Retry the same request."
                ) from exc
        return self.inspect()

    def _verified(self, row, snap):
        return {
            "state": "configured",
            "payload": snap.payload,
            "committedRevision": row["revision"],
            "requestId": row["request_id"],
            "superseded": row["revision"] != snap.head,
            "recordCount": snap.count,
            "maxRecords": self.max_records,
            "epoch": snap.epoch,
            "residueCount": len(snap.debris),
        }
