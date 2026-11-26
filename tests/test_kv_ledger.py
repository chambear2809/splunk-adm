import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_kv_lib.ledger import (  # noqa: E402
    Conflict,
    Forbidden,
    Invalid,
    LedgerError,
    RecordLedger,
    Uncertain,
    Unavailable,
    canonical,
    digest,
    successor_key,
)


class MemoryStore:
    def __init__(self):
        self.rows = []
        self.fail_insert = False

    def scan(self, limit):
        ordered = sorted(self.rows, key=lambda row: row["_key"])
        return ordered[:limit]

    def insert(self, document):
        if self.fail_insert:
            raise RuntimeError("insert lost")
        if any(row["_key"] == document["_key"] for row in self.rows):
            raise RuntimeError("duplicate")
        self.rows.append(dict(document))

    def delete(self, key):
        if self.fail_delete_after is not None:
            if self.fail_delete_after == 0:
                raise RuntimeError("delete lost")
            self.fail_delete_after -= 1
        self.rows = [row for row in self.rows if row["_key"] != key]

    fail_delete_after = None


class KvLedgerTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.ledger = RecordLedger(self.store, kind="views", max_records=8)

    def test_first_write_and_idempotent_retry(self):
        first = self.ledger.write(
            {"name": "Payments Prod Map"},
            expected_revision=None,
            request_id="req-1",
        )
        self.assertEqual(first["state"], "configured")
        retry = self.ledger.write(
            {"name": "Payments Prod Map"},
            expected_revision=None,
            request_id="req-1",
        )
        self.assertEqual(retry["committedRevision"], first["committedRevision"])
        self.assertEqual(len(self.store.rows), 1)

    def test_stale_revision_conflict_preserves_head(self):
        self.ledger.write({"name": "a"}, None, "req-1")
        with self.assertRaises(Conflict):
            self.ledger.write({"name": "b"}, None, "req-2")

    def test_successor_and_duplicate_request_conflict(self):
        first = self.ledger.write({"name": "a"}, None, "req-1")
        second = self.ledger.write({"name": "b"}, first["committedRevision"], "req-2")
        self.assertNotEqual(first["committedRevision"], second["committedRevision"])
        with self.assertRaises(Conflict):
            self.ledger.write({"name": "c"}, first["committedRevision"], "req-2")

    def test_lost_insert_is_uncertain_until_retry_proves_absence(self):
        self.store.fail_insert = True
        with self.assertRaises(Uncertain):
            self.ledger.write({"name": "a"}, None, "req-1")
        self.store.fail_insert = False
        retry = self.ledger.write({"name": "a"}, None, "req-1")
        self.assertEqual(retry["state"], "configured")
        self.assertFalse(retry["superseded"])
        self.assertEqual(len(self.store.rows), 1)

    def test_successor_key_is_stable(self):
        self.assertEqual(
            successor_key("views", "abc"),
            "views_after_" + digest("abc"),
        )
        self.assertEqual(canonical({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_invalid_request_rejected(self):
        with self.assertRaises(Invalid):
            self.ledger.write({"name": "a"}, None, "bad id")
        with self.assertRaises(LedgerError):
            self.ledger.write({"name": "a"}, None, "bad id")

    def test_forbidden_insert_is_not_uncertain(self):
        class DenyStore(MemoryStore):
            def insert(self, document):
                raise Forbidden("Collection write is not permitted.")

        ledger = RecordLedger(DenyStore(), "views")
        with self.assertRaises(Forbidden):
            ledger.write({"name": "a"}, None, "req-1")

    def _fill(self, count):
        revision = None
        for index in range(count):
            revision = self.ledger.write({"n": index}, revision, "req-" + str(index))[
                "committedRevision"
            ]
        return revision

    def _root_row(self):
        return next(row for row in self.store.rows if row.get("epoch_root"))

    def _stale_compaction(self, stale, request_id):
        """Run compact() as if its first scan had happened at ``stale``."""
        real = self.ledger.inspect
        calls = []

        def inspect(**options):
            calls.append(1)
            return stale if len(calls) == 1 else real(**options)

        with patch.object(self.ledger, "inspect", side_effect=inspect):
            return self.ledger.compact(stale.head, request_id)

    def test_full_ledger_refuses_writes_until_compacted(self):
        head = self._fill(8)
        with self.assertRaisesRegex(Unavailable, "compacts the ledger"):
            self.ledger.write({"n": 99}, head, "req-over")
        compacted = self.ledger.compact(head, "compact-1")
        self.assertEqual(compacted["payload"], {"n": 7})
        self.assertEqual(compacted["recordCount"], 2)
        self.assertEqual(compacted["residueCount"], 0)
        self.assertEqual(compacted["epoch"], 1)
        state = self.ledger.read()
        self.assertEqual(state["payload"], {"n": 7})
        self.assertEqual(state["revision"], compacted["committedRevision"])
        written = self.ledger.write({"n": 8}, state["revision"], "req-8")
        self.assertFalse(written["superseded"])
        self.assertEqual(self.ledger.read()["payload"], {"n": 8})
        self.assertTrue(all(row.get("epoch") == 1 for row in self.store.rows))

    def test_stale_writer_conflicts_with_compaction(self):
        head = self._fill(3)
        self.ledger.compact(head, "compact-1")
        with self.assertRaises(Conflict):
            self.ledger.write({"n": 9}, head, "req-stale")
        with self.assertRaises(Conflict):
            self.ledger.compact(head, "compact-2")

    def test_concurrent_compaction_of_same_head_cannot_fork(self):
        head = self._fill(3)
        stale = self.ledger.inspect()
        self.ledger.compact(head, "compact-a")
        with self.assertRaises(Conflict):
            self._stale_compaction(stale, "compact-b")
        self.assertEqual(self.ledger.read()["payload"], {"n": 2})
        self.assertEqual(self._root_row()["request_id"], "compact-a")

    def test_delayed_compaction_after_purge_cannot_brick_ledger(self):
        r2 = self._fill(3)
        stale = self.ledger.inspect()
        r3 = self.ledger.write({"n": 3}, r2, "req-3")["committedRevision"]
        epoch1 = self.ledger.compact(r3, "compact-a")["committedRevision"]
        with self.assertRaises(Conflict):
            self._stale_compaction(stale, "compact-b")
        state = self.ledger.read()
        self.assertEqual(state["payload"], {"n": 3})
        self.assertEqual(state["revision"], epoch1)
        self.assertEqual(state["residueCount"], 1)
        r4 = self.ledger.write({"n": 4}, epoch1, "req-4")["committedRevision"]
        cleaned = self.ledger.compact(r4, "compact-c")
        self.assertEqual(cleaned["epoch"], 2)
        self.assertEqual(cleaned["residueCount"], 0)
        self.assertEqual(self.ledger.read()["payload"], {"n": 4})

    def test_cleanup_from_scan_between_seal_and_root_keeps_ledger_valid(self):
        head = self._fill(3)
        real = self.store.insert
        between = []

        def capture(document):
            result = real(document)
            if document.get("seal") and not between:
                between.append(self.ledger.inspect())
            return result

        with patch.object(self.store, "insert", side_effect=capture):
            done = self.ledger.compact(head, "compact-a")
        self.assertEqual(between[0].pending["request_id"], "compact-a")
        for key in between[0].debris:
            self.store.delete(key)
        state = self.ledger.read()
        self.assertEqual(state["revision"], done["committedRevision"])
        self.assertEqual(state["payload"], {"n": 2})
        self.ledger.write({"n": 3}, state["revision"], "req-3")

    def test_other_compaction_finishes_pending_seal_identically(self):
        head = self._fill(3)
        real = self.store.insert

        def lose_root(document):
            if document.get("epoch_root"):
                raise RuntimeError("insert lost")
            return real(document)

        with patch.object(self.store, "insert", side_effect=lose_root):
            with self.assertRaises(Uncertain):
                self.ledger.compact(head, "compact-a")
        finished = self.ledger.compact(head, "compact-b")
        self.assertEqual(finished["requestId"], "compact-a")
        self.assertEqual(finished["epoch"], 1)
        retried = self.ledger.compact(head, "compact-a")
        self.assertEqual(retried["committedRevision"], finished["committedRevision"])

    def test_interrupted_compaction_blocks_saves_until_retried(self):
        head = self._fill(3)
        real = self.store.insert

        def lose_root(document):
            if document.get("epoch_root"):
                raise RuntimeError("insert lost")
            return real(document)

        with patch.object(self.store, "insert", side_effect=lose_root):
            with self.assertRaises(Uncertain):
                self.ledger.compact(head, "compact-1")
        state = self.ledger.read()
        self.assertEqual((state["revision"], state["epoch"]), (head, 0))
        with self.assertRaisesRegex(Unavailable, "retry compaction"):
            self.ledger.write({"n": 9}, head, "req-blocked")
        resumed = self.ledger.compact(head, "compact-1")
        self.assertEqual(resumed["epoch"], 1)
        self.assertEqual(resumed["payload"], {"n": 2})
        self.assertEqual(resumed["recordCount"], 2)

    def test_interrupted_cleanup_is_readable_and_resumes(self):
        head = self._fill(8)
        self.store.fail_delete_after = 3
        with self.assertRaises(Uncertain):
            self.ledger.compact(head, "compact-1")
        state = self.ledger.read()
        self.assertEqual(state["payload"], {"n": 7})
        self.assertEqual(state["residueCount"], 5)
        self.assertEqual(state["recordCount"], 7)
        self.store.fail_delete_after = None
        resumed = self.ledger.compact(head, "compact-1")
        self.assertEqual(resumed["recordCount"], 2)
        self.assertEqual(resumed["committedRevision"], state["revision"])

    def test_lost_cleanup_at_limit_still_compacts_again(self):
        head = self._fill(8)
        self.store.fail_delete_after = 0
        with self.assertRaises(Uncertain):
            self.ledger.compact(head, "compact-1")
        self.assertEqual(len(self.store.rows), 10)
        self.store.fail_delete_after = None
        current = self.ledger.read()["revision"]
        again = self.ledger.compact(current, "compact-2")
        self.assertEqual(again["recordCount"], 2)
        self.assertEqual(self.ledger.read()["payload"], {"n": 7})

    def test_compaction_cleans_residue_beyond_strict_scan_bound(self):
        head = self._fill(3)
        current = self.ledger.compact(head, "compact-1")["committedRevision"]
        template = next(row for row in self.store.rows if row.get("epoch_root"))
        for index in range(9):
            self.store.rows.append(
                {
                    "_key": successor_key("views", "late-" + str(index)),
                    "format": 2,
                    "kind": "views",
                }
            )
        self.assertEqual(len(self.store.rows), 11)
        with self.assertRaisesRegex(Unavailable, "compacts the ledger"):
            self.ledger.read()
        result = self.ledger.compact(current, "compact-2")
        self.assertEqual(result["recordCount"], 2)
        self.assertEqual(self.ledger.read()["revision"], template["revision"])

    def test_compaction_is_noop_when_already_compact(self):
        head = self._fill(2)
        first = self.ledger.compact(head, "compact-1")
        second = self.ledger.compact(first["committedRevision"], "compact-2")
        self.assertEqual(second["revision"], first["committedRevision"])
        self.assertEqual(len(self.store.rows), 2)

    def test_forged_epoch_rows_fail_closed(self):
        head = self._fill(2)
        self.ledger.compact(head, "compact-1")
        self._root_row()["payload_json"] = canonical({"n": "forged"})
        with self.assertRaises(Unavailable):
            self.ledger.read()

    def test_root_without_its_seal_fails_closed(self):
        head = self._fill(2)
        self.ledger.compact(head, "compact-1")
        self.store.rows = [row for row in self.store.rows if not row.get("seal")]
        with self.assertRaises(Unavailable):
            self.ledger.read()

    def test_unreachable_current_epoch_row_fails_closed(self):
        head = self._fill(2)
        self.ledger.compact(head, "compact-1")
        orphan = dict(self._root_row())
        orphan["_key"] = successor_key("views", digest("elsewhere"))
        orphan["epoch_root"] = False
        self.store.rows.append(orphan)
        with self.assertRaises(Unavailable):
            self.ledger.read()

    def test_unexpected_key_shape_fails_closed(self):
        self._fill(1)
        self.store.rows.append(dict(self.store.rows[0], _key="views_other"))
        with self.assertRaises(Unavailable):
            self.ledger.read()

    def test_precheck_sees_superseded_head(self):
        head = self._fill(1)
        seen = []
        self.ledger.write({"n": 1}, head, "req-x", precheck=seen.append)
        self.assertEqual(seen, [{"n": 0}])
        with self.assertRaises(Forbidden):

            def deny(_payload):
                raise Forbidden()

            self.ledger.write(
                {"n": 2}, self.ledger.read()["revision"], "req-y", precheck=deny
            )
        self.assertEqual(self.ledger.read()["payload"], {"n": 1})


class RichMemoryStore(MemoryStore):
    """Test store supporting metadata scans, point gets, indexed queries, and $in deletes."""

    def __init__(self):
        super().__init__()
        self.calls = []

    def scan(self, limit):
        self.calls.append(("scan", limit))
        return super().scan(limit)

    def scan_metadata(self, limit):
        self.calls.append(("scan_metadata", limit))
        meta_keys = {
            "_key",
            "format",
            "epoch",
            "epoch_root",
            "seal",
            "kind",
            "previous_revision",
            "request_id",
            "operation_fingerprint",
            "revision",
        }
        return [
            {k: v for k, v in row.items() if k in meta_keys}
            for row in sorted(self.rows, key=lambda r: r["_key"])[:limit]
        ]

    def get(self, key):
        self.calls.append(("get", key))
        for row in self.rows:
            if row["_key"] == key:
                return dict(row)
        return None

    def query(self, filter_doc, *, limit, sort=None, fields=None):
        self.calls.append(("query", filter_doc, limit, sort, fields))
        field_set = set(fields.split(",")) if fields else None

        def match(row):
            for k, cond in filter_doc.items():
                if isinstance(cond, dict) and "$exists" in cond:
                    if (k in row) != bool(cond["$exists"]):
                        return False
                elif row.get(k) != cond:
                    return False
            return True

        matched = [row for row in self.rows if match(row)]
        if sort == "epoch:-1":
            matched.sort(key=lambda r: -(r.get("epoch", 0)))
        else:
            matched.sort(key=lambda r: r["_key"])
        matched = matched[:limit]
        if field_set is not None:
            return [{k: v for k, v in row.items() if k in field_set} for row in matched]
        return [dict(row) for row in matched]

    def delete_many(self, keys):
        self.calls.append(("delete_many", list(keys)))
        key_set = set(keys)
        self.rows = [row for row in self.rows if row["_key"] not in key_set]


class KvLedgerPerfAndCapsTests(unittest.TestCase):
    def test_head_only_read_never_scans_historical_payloads_and_verifies_head(self):
        store = RichMemoryStore()
        ledger = RecordLedger(store, kind="views", max_records=32)
        rev = None
        for i in range(10):
            rev = ledger.write({"n": i}, rev, f"req-{i}")["committedRevision"]
        store.calls.clear()
        result = ledger.read()
        self.assertEqual(result["payload"], {"n": 9})
        self.assertEqual(result["revision"], rev)
        self.assertEqual(result["recordCount"], 10)
        # Must use metadata scan + 1 single point get for the head document; never full scan.
        self.assertEqual([c[0] for c in store.calls], ["scan_metadata", "get"])
        # Forging payload_json on the head document must still fail closed.
        head_key = store.calls[1][1]
        for row in store.rows:
            if row["_key"] == head_key:
                row["payload_json"] = canonical({"n": 999})
        with self.assertRaises(Unavailable):
            ledger.read()

    def test_write_uses_point_verification_without_post_write_scan(self):
        store = RichMemoryStore()
        ledger = RecordLedger(store, kind="views", max_records=16)
        first = ledger.write({"n": 0}, None, "req-0")
        store.calls.clear()
        second = ledger.write({"n": 1}, first["committedRevision"], "req-1")
        self.assertEqual(second["payload"], {"n": 1})
        self.assertFalse(second["superseded"])
        self.assertEqual(second["recordCount"], 2)
        # Pre-write: 1 scan_metadata (no precheck => 0 head payload get);
        # Post-write: 2 point gets (committed target + empty successor), 0 post-write scans!
        self.assertEqual([c[0] for c in store.calls], ["scan_metadata", "get", "get"])

    def test_read_head_uses_indexed_epoch_query_and_skips_old_epoch_residue(self):
        store = RichMemoryStore()
        ledger = RecordLedger(store, kind="assertions", max_records=16)
        rev = None
        for i in range(5):
            rev = ledger.write({"step": i}, rev, f"req-{i}")["committedRevision"]
        # Add stale epoch-0 residue after compaction by saving rows, compacting, then re-inserting residue.
        old_rows = [dict(r) for r in store.rows]
        compacted = ledger.compact(rev, "compact-1")
        rev = compacted["committedRevision"]
        rev = ledger.write({"step": 5}, rev, "req-5")["committedRevision"]
        existing_keys = {r["_key"] for r in store.rows}
        for row in old_rows:
            if row["_key"] not in existing_keys:
                store.rows.append(row)
        store.calls.clear()
        head = ledger.read_head()
        self.assertEqual(head["state"], "configured")
        self.assertEqual(head["payload"], {"step": 5})
        self.assertEqual(head["revision"], rev)
        self.assertEqual(head["epoch"], 1)
        self.assertEqual(head["activeEpochRecords"], 2)
        # Must use indexed query(epoch_root=True), get(seal), query(epoch=1), get(head); never scan!
        self.assertFalse(any(c[0] in ("scan", "scan_metadata") for c in store.calls))
        queries = [c[1] for c in store.calls if c[0] == "query"]
        self.assertEqual(queries, [{"epoch_root": True}, {"epoch": 1}])

    def test_compact_purges_debris_with_batched_delete_many(self):
        store = RichMemoryStore()
        ledger = RecordLedger(store, kind="views", max_records=16)
        rev = None
        for i in range(6):
            rev = ledger.write({"n": i}, rev, f"req-{i}")["committedRevision"]
        store.calls.clear()
        res = ledger.compact(rev, "compact-batch")
        self.assertEqual(res["epoch"], 1)
        self.assertEqual(res["residueCount"], 0)
        delete_many_calls = [c for c in store.calls if c[0] == "delete_many"]
        self.assertEqual(len(delete_many_calls), 1)
        self.assertEqual(len(delete_many_calls[0][1]), 6)

    def test_splunk_collection_store_caps_and_batched_delete_many(self):
        import types
        from adm_kv_lib import store as store_mod

        s = store_mod.SplunkCollectionStore("tok", "adm_saved_views")
        # Limit bounds reject 0, negative, booleans, and > MAX_SCAN_LIMIT.
        for bad_limit in (0, -1, True, store_mod.MAX_SCAN_LIMIT + 1):
            with self.assertRaises(Unavailable):
                s.scan(bad_limit)
            with self.assertRaises(Unavailable):
                s.query({}, limit=bad_limit)

        # Oversized response is rejected before json.loads.
        fake_resp = types.SimpleNamespace(status=200)
        oversized = b"x" * (store_mod.MAX_RESPONSE_BYTES + 1)
        fake_splunk = types.SimpleNamespace(
            rest=types.SimpleNamespace(
                simpleRequest=lambda *a, **k: (fake_resp, oversized)
            )
        )
        with patch.dict(
            sys.modules, {"splunk": fake_splunk, "splunk.rest": fake_splunk.rest}
        ):
            with self.assertRaisesRegex(Unavailable, "size limit"):
                s.get("views_root")

        # scan_metadata projects METADATA_FIELDS and delete_many chunks by MAX_IN_BATCH (50).
        recorded = []

        def fake_simple_request(path, **kwargs):
            recorded.append((kwargs["method"], path))
            if kwargs["method"] == "DELETE":
                return fake_resp, b""
            return fake_resp, b"[]"

        fake_splunk_ok = types.SimpleNamespace(
            rest=types.SimpleNamespace(simpleRequest=fake_simple_request)
        )
        with patch.dict(
            sys.modules, {"splunk": fake_splunk_ok, "splunk.rest": fake_splunk_ok.rest}
        ):
            s.scan_metadata(10)
            self.assertIn("fields=", recorded[0][1])
            self.assertNotIn("payload_json", recorded[0][1])
            recorded.clear()
            keys = [f"views_after_{i:064x}" for i in range(120)]
            s.delete_many(keys)
            self.assertEqual(len(recorded), 3)
            self.assertTrue(all(m == "DELETE" and "%24in" in p for m, p in recorded))
            # Invalid key shape must be rejected before issuing any DELETE.
            recorded.clear()
            with self.assertRaises(Unavailable):
                s.delete_many(["../bad_key"])
            self.assertEqual(recorded, [])


if __name__ == "__main__":
    unittest.main()
