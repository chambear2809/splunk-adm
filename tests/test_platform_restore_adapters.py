import copy
import hashlib
import unittest

from tools import platform_restore_adapters as adapters


class KVAdapterTests(unittest.TestCase):
    def setUp(self):
        self.rows = {
            name: [{"_key": "a", "value": name}] for name in adapters.COLLECTIONS
        }
        self.events = []
        self.archive = {"sha256": "a" * 64, "size": 42}
        self.status = {"type": "Pdl", "status": "ready", "backupRestoreStatus": "ready"}

    def fetch(self, name, last, limit):
        return [copy.deepcopy(row) for row in self.rows[name] if row["_key"] > last][
            :limit
        ]

    def test_exact_all_collections_and_keyset_pages(self):
        import configparser
        from pathlib import Path

        conf = configparser.RawConfigParser()
        conf.read(
            Path(__file__).resolve().parents[1]
            / "splunk_app/splunk_adm/default/collections.conf"
        )
        self.assertEqual(set(adapters.COLLECTIONS), set(conf.sections()))
        self.assertEqual(
            adapters.discover_collections(
                [{"name": x} for x in reversed(adapters.COLLECTIONS)]
            ),
            tuple(sorted(adapters.COLLECTIONS)),
        )
        for entries in (
            [{"name": x} for x in adapters.COLLECTIONS[:-1]],
            [{"name": x} for x in adapters.COLLECTIONS]
            + [{"name": adapters.COLLECTIONS[0]}],
        ):
            with self.assertRaises(adapters.RestoreError):
                adapters.discover_collections(entries)
        many = [{"_key": f"{n:04d}"} for n in range(501)]
        result = adapters.read_collection(
            lambda name, last, limit: [r for r in many if r["_key"] > last][:limit],
            adapters.COLLECTIONS[0],
        )
        self.assertEqual(result, many)
        with self.assertRaises(adapters.RestoreError):
            adapters.read_collection(
                lambda *_: [{"_key": "a"}, {"_key": "a"}], adapters.COLLECTIONS[0]
            )

    def test_discovery_pagination_requires_stable_complete_total(self):
        entries = [{"name": name} for name in adapters.COLLECTIONS]
        calls = []

        def pages(offset, limit):
            calls.append(offset)
            return {
                "paging": {"total": len(entries)},
                "entry": entries[offset : offset + 7],
            }

        self.assertEqual(
            adapters.discover_pages(pages), tuple(sorted(adapters.COLLECTIONS))
        )
        self.assertEqual(calls, [0, 7, 14])

        def changing(offset, limit):
            return {
                "paging": {"total": len(entries) + int(offset > 0)},
                "entry": entries[offset : offset + 7],
            }

        with self.assertRaises(adapters.RestoreError):
            adapters.discover_pages(changing)

    def test_corrupt_expected_restore_refused_before_dispatch(self):
        expected = adapters.stable_kv_snapshot(self.fetch, lambda: True)
        self.rows = {name: [] for name in adapters.COLLECTIONS}
        expected["rows"].pop(adapters.COLLECTIONS[0])
        called = []
        with self.assertRaises(adapters.RestoreError):
            adapters.pdl_parallel_restore(
                cli=called.append,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                expected_snapshot=expected,
                archive_info=lambda: self.archive,
                expected_archive=self.archive,
                journal=self.events.append,
                dispatch_clear=lambda: (
                    not any(e["state"].endswith("_intent") for e in self.events)
                ),
                fresh_instance_verified=lambda: True,
            )
        self.assertEqual(called, [])
        self.assertEqual(self.events, [])

    def test_population_report_includes_legitimate_empty_collections(self):
        self.rows[adapters.COLLECTIONS[0]] = []
        snapshot = adapters.stable_kv_snapshot(self.fetch, lambda: True)
        report = adapters.collection_population_report(snapshot)
        self.assertEqual(len(report["counts"]), len(adapters.COLLECTIONS))
        self.assertEqual(report["empty"], [adapters.COLLECTIONS[0]])
        self.assertEqual(len(report["populated"]), len(adapters.COLLECTIONS) - 1)
        self.assertFalse(report["domain_validity_qualified"])
        snapshot["rows"].pop(adapters.COLLECTIONS[0])
        with self.assertRaises(adapters.RestoreError):
            adapters.collection_population_report(snapshot)

    def test_native_parallel_backup_preserves_exact_snapshot(self):
        calls = []
        result = adapters.pdl_parallel_backup(
            cli=lambda argv: calls.append(argv),
            status=lambda: self.status,
            writer_barrier=lambda: True,
            fetch=self.fetch,
            archive_info=lambda: self.archive if calls else None,
            journal=self.events.append,
            dispatch_clear=lambda: (
                not any(e["state"].endswith("_intent") for e in self.events)
            ),
        )
        self.assertEqual(
            calls,
            [
                [
                    "backup",
                    "kvstore",
                    "-archiveName",
                    "atlas_platform_fixture",
                    "-backupParallelJobs",
                    "true",
                ]
            ],
        )
        self.assertFalse(result["point_in_time"])
        self.assertEqual(
            [event["state"] for event in self.events],
            ["kv_backup_intent", "kv_backup_ack", "kv_backup_verified"],
        )
        self.assertEqual(
            result["snapshot"]["sha256"],
            hashlib.sha256(adapters.canonical(self.rows)).hexdigest(),
        )

    def test_native_dispatch_gate_requires_ordered_complete_receipts(self):
        self.assertTrue(adapters.native_dispatches_clear([]))
        phases = [
            {"state": "kv_backup_" + state, "archive": adapters.KV_ARCHIVE}
            for state in ("intent", "ack", "verified")
        ]
        phases[2].update(sha256="a" * 64, size=1)
        self.assertTrue(adapters.native_dispatches_clear(phases))
        restore = [
            {"state": "kv_restore_" + state, "archive": adapters.KV_ARCHIVE}
            for state in ("intent", "ack", "verified")
        ]
        restore[2]["sha256"] = "b" * 64
        self.assertTrue(adapters.native_dispatches_clear(phases + restore))
        transfer = [
            {"state": "kv_archive_transfer_intent", "sha256": "a" * 64},
            {"state": "kv_archive_transfer_verified", "sha256": "a" * 64, "size": 1},
        ]
        self.assertTrue(adapters.native_dispatches_clear(phases + transfer + restore))
        self.assertFalse(
            adapters.native_dispatches_clear(
                phases + [transfer[0], dict(transfer[1], size=2)] + restore
            )
        )
        self.assertFalse(adapters.native_dispatches_clear(phases + transfer[:1]))
        self.assertFalse(
            adapters.native_dispatches_clear(
                phases + [transfer[0], dict(transfer[1], sha256="b" * 64)]
            )
        )
        self.assertFalse(
            adapters.native_dispatches_clear(
                [phases[0], restore[0], phases[1], restore[1], phases[2], restore[2]]
            )
        )
        self.assertFalse(
            adapters.native_dispatches_clear(
                [
                    phases[0],
                    phases[1],
                    {"state": "kv_backup_verified", "archive": adapters.KV_ARCHIVE},
                ]
            )
        )
        self.assertFalse(
            adapters.native_dispatches_clear(
                phases[:2] + [dict(phases[2], sha256="not-a-digest")]
            )
        )
        self.assertFalse(
            adapters.native_dispatches_clear(
                restore[:2] + [dict(restore[2], sha256="invalid")]
            )
        )
        self.assertFalse(
            adapters.native_dispatches_clear([{"state": "kv_backup_unrecognized"}])
        )
        for bad in (
            phases[:1],
            phases[:2],
            phases[::-1],
            phases + phases,
            [dict(phases[0], archive="other")],
        ):
            self.assertFalse(adapters.native_dispatches_clear(bad))

    def test_uncertain_backup_retains_durable_intent(self):
        def uncertain(_):
            raise TimeoutError()

        with self.assertRaises(TimeoutError):
            adapters.pdl_parallel_backup(
                cli=uncertain,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                archive_info=lambda: None,
                journal=self.events.append,
                dispatch_clear=lambda: (
                    not any(e["state"].endswith("_intent") for e in self.events)
                ),
            )
        self.assertEqual([e["state"] for e in self.events], ["kv_backup_intent"])

    def test_pdl_fresh_restore_exact_readback_and_occupied_refusal(self):
        expected = adapters.stable_kv_snapshot(self.fetch, lambda: True)
        self.rows = {name: [] for name in adapters.COLLECTIONS}

        def restore(argv):
            self.assertEqual(
                argv,
                [
                    "restore",
                    "kvstore",
                    "-archiveName",
                    "atlas_platform_fixture.tar.gz",
                    "-restoreParallelJobs",
                    "true",
                ],
            )
            self.rows = copy.deepcopy(expected["rows"])

        result = adapters.pdl_parallel_restore(
            cli=restore,
            status=lambda: self.status,
            writer_barrier=lambda: True,
            fetch=self.fetch,
            expected_snapshot=expected,
            archive_info=lambda: self.archive,
            expected_archive=self.archive,
            journal=self.events.append,
            dispatch_clear=lambda: (
                not any(e["state"].endswith("_intent") for e in self.events)
            ),
            fresh_instance_verified=lambda: True,
        )
        self.assertEqual(result, expected)
        self.events.clear()
        with self.assertRaises(adapters.RestoreError):
            adapters.pdl_parallel_restore(
                cli=restore,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                expected_snapshot=expected,
                archive_info=lambda: self.archive,
                expected_archive=self.archive,
                journal=self.events.append,
                dispatch_clear=lambda: (
                    not any(e["state"].endswith("_intent") for e in self.events)
                ),
                fresh_instance_verified=lambda: True,
            )
        self.assertEqual(self.events, [])

    def test_restore_rejects_callback_mutation_of_original_expected_snapshot(self):
        expected = adapters.stable_kv_snapshot(self.fetch, lambda: True)
        self.rows = {name: [] for name in adapters.COLLECTIONS}

        def mutate_and_restore(_argv):
            expected["rows"][adapters.COLLECTIONS[0]][0]["value"] = "altered"
            expected["sha256"] = hashlib.sha256(
                adapters.canonical(expected["rows"])
            ).hexdigest()
            self.rows = copy.deepcopy(expected["rows"])

        with self.assertRaises(adapters.RestoreError):
            adapters.pdl_parallel_restore(
                cli=mutate_and_restore,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                expected_snapshot=expected,
                archive_info=lambda: self.archive,
                expected_archive=self.archive,
                journal=self.events.append,
                dispatch_clear=lambda: True,
                fresh_instance_verified=lambda: True,
            )
        self.assertEqual(
            [event["state"] for event in self.events],
            ["kv_restore_intent", "kv_restore_ack"],
        )

    def test_uncertain_restore_retains_intent_and_refuses_implicit_replay(self):
        expected = adapters.stable_kv_snapshot(self.fetch, lambda: True)
        self.rows = {name: [] for name in adapters.COLLECTIONS}

        def uncertain(_argv):
            raise TimeoutError()

        with self.assertRaises(TimeoutError):
            adapters.pdl_parallel_restore(
                cli=uncertain,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                expected_snapshot=expected,
                archive_info=lambda: self.archive,
                expected_archive=self.archive,
                journal=self.events.append,
                dispatch_clear=lambda: (
                    not any(e["state"].endswith("_intent") for e in self.events)
                ),
                fresh_instance_verified=lambda: True,
            )
        self.assertEqual([e["state"] for e in self.events], ["kv_restore_intent"])
        with self.assertRaises(adapters.RestoreError):
            adapters.pdl_parallel_restore(
                cli=uncertain,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                expected_snapshot=expected,
                archive_info=lambda: self.archive,
                expected_archive=self.archive,
                journal=self.events.append,
                dispatch_clear=lambda: (
                    not any(e["state"].endswith("_intent") for e in self.events)
                ),
                fresh_instance_verified=lambda: True,
            )
        self.assertEqual([e["state"] for e in self.events], ["kv_restore_intent"])

    def test_changed_state_and_wrong_engine_refuse(self):
        count = 0

        def changed(name, last, limit):
            nonlocal count
            if name == adapters.COLLECTIONS[0] and not last:
                count += 1
                if count == 2:
                    self.rows[name].append({"_key": "b"})
            return self.fetch(name, last, limit)

        with self.assertRaises(adapters.RestoreError):
            adapters.stable_kv_snapshot(changed, lambda: True)
        self.status["type"] = "mongo"
        with self.assertRaises(adapters.RestoreError):
            adapters.pdl_parallel_backup(
                cli=lambda _: None,
                status=lambda: self.status,
                writer_barrier=lambda: True,
                fetch=self.fetch,
                archive_info=lambda: None,
                journal=self.events.append,
                dispatch_clear=lambda: (
                    not any(e["state"].endswith("_intent") for e in self.events)
                ),
            )

    def test_same_mutable_rows_cannot_hide_mid_snapshot_change(self):
        count = 0

        def fetch(name, last, limit):
            nonlocal count
            if name == adapters.COLLECTIONS[0] and not last:
                count += 1
                if count == 2:
                    self.rows[name][0]["value"] = "changed"
            return [row for row in self.rows[name] if row["_key"] > last][:limit]

        with self.assertRaises(adapters.RestoreError):
            adapters.stable_kv_snapshot(fetch, lambda: True)

    def test_old_absolute_paths_must_be_owned_and_rebased(self):
        self.assertEqual(
            adapters.source_home_rebase(
                "/fixture/source/etc/apps", "/fixture/source", "/fixture/dest"
            ),
            "/fixture/dest/etc/apps",
        )
        for value in ("/fixture/other/etc", "/fixture/source/../other", "relative"):
            with self.assertRaises(adapters.RestoreError):
                adapters.source_home_rebase(value, "/fixture/source", "/fixture/dest")


class ColdBucketTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path

        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        for name in adapters.FIXTURE_INDEXES:
            bucket = self.source / name / "db_2_1_0"
            bucket.mkdir(mode=0o700, parents=True)
            (bucket / "data.tsidx").write_bytes(name.encode())
            (bucket / "data.tsidx").chmod(0o600)
        self.events = []

    def tearDown(self):
        self.temp.cleanup()

    def test_copy_exact_fixture_indexes_and_refuse_occupied_target(self):
        target = self.root / "target"
        result = adapters.capture_cold_buckets(
            self.source,
            target,
            processes_stopped=lambda: True,
            journal=self.events.append,
        )
        self.assertEqual(len(result), 3)
        self.assertEqual(adapters._bucket_tree(target), result)
        with self.assertRaises(FileExistsError):
            adapters.capture_cold_buckets(
                self.source,
                target,
                processes_stopped=lambda: True,
                journal=self.events.append,
            )

    def test_invalid_bucket_empty_directory_and_walk_error_fail_closed(self):
        from unittest.mock import patch

        index = self.source / adapters.FIXTURE_INDEXES[0]
        bogus = index / "db_not_a_directory"
        bogus.write_text("not a bucket")
        with self.assertRaises(adapters.RestoreError):
            adapters.capture_cold_buckets(
                self.source,
                self.root / "refused",
                processes_stopped=lambda: True,
                journal=self.events.append,
            )
        bogus.unlink()
        empty = index / "db_empty"
        empty.mkdir(mode=0o700)
        with self.assertRaises(adapters.RestoreError):
            adapters.capture_cold_buckets(
                self.source,
                self.root / "refused",
                processes_stopped=lambda: True,
                journal=self.events.append,
            )
        empty.rmdir()

        def failed_walk(*args, **kwargs):
            kwargs["onerror"](PermissionError("unreadable"))
            return iter(())

        with patch("os.walk", side_effect=failed_walk):
            with self.assertRaises(adapters.RestoreError):
                adapters.capture_cold_buckets(
                    self.source,
                    self.root / "refused",
                    processes_stopped=lambda: True,
                    journal=self.events.append,
                )
        self.assertFalse((self.root / "refused").exists())
        self.assertEqual(self.events, [])

    def test_partial_copy_is_retained_and_not_replayed(self):
        from unittest.mock import patch

        target = self.root / "partial"
        with patch("os.write", return_value=0):
            with self.assertRaises(adapters.RestoreError):
                adapters.capture_cold_buckets(
                    self.source,
                    target,
                    processes_stopped=lambda: True,
                    journal=self.events.append,
                )
        self.assertEqual([e["state"] for e in self.events], ["bucket_copy_intent"])
        self.assertTrue(target.exists())
        with self.assertRaises(FileExistsError):
            adapters.capture_cold_buckets(
                self.source,
                target,
                processes_stopped=lambda: True,
                journal=self.events.append,
            )

    def test_hot_bucket_symlink_and_running_source_refuse_before_target(self):
        bucket = self.source / adapters.FIXTURE_INDEXES[0] / "db_2_1_0"
        hot = bucket.with_name("hot_v1_0")
        bucket.rename(hot)
        with self.assertRaises(adapters.RestoreError):
            adapters.capture_cold_buckets(
                self.source,
                self.root / "target",
                processes_stopped=lambda: True,
                journal=self.events.append,
            )
        hot.rename(bucket)
        (bucket / "data.tsidx").unlink()
        (bucket / "data.tsidx").symlink_to("/etc/passwd")
        with self.assertRaises(OSError):
            adapters.capture_cold_buckets(
                self.source,
                self.root / "target",
                processes_stopped=lambda: True,
                journal=self.events.append,
            )
        with self.assertRaises(adapters.RestoreError):
            adapters.capture_cold_buckets(
                self.source,
                self.root / "target",
                processes_stopped=lambda: False,
                journal=self.events.append,
            )
        self.assertFalse((self.root / "target").exists())


class RealSQLiteFixtureTests(unittest.TestCase):
    def test_four_app_schemas_preserve_unknown_job_and_quota(self):
        import sys
        import tempfile
        from pathlib import Path
        from tools import case_recovery_snapshot

        bin_path = str(
            Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin"
        )
        sys.path.insert(0, bin_path)
        try:
            from adm_baselines_lib.run_store import ExecutionStore
            from adm_baselines_lib.store import BaselineStore
            from adm_cases_lib.job_ledger import JobLedger, QuotaExceeded
            from adm_cases_lib.store import CaseStore

            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                root.chmod(0o700)
                source = root / "source"
                source.mkdir(mode=0o700)
                for folder in ("baselines", "investigations"):
                    (source / folder).mkdir(mode=0o700)
                base = source / "baselines"
                cases = source / "investigations"
                BaselineStore(base / "baselines.sqlite", lambda *_: True, lambda *_: {})
                ExecutionStore(base / "watch_runs.sqlite")
                CaseStore(cases / "cases.sqlite", lambda *_: True)
                ledger = JobLedger(cases / "capture_jobs.sqlite", clock=lambda: 100)
                ident = "adm-capture-" + "1" * 32
                ledger.reserve(
                    "alice", ident, "c" * 64, 1, 301, "a" * 32, transport_hash="c" * 64
                )
                ledger.transition(
                    "alice", ident, "a" * 32, "creation_unknown", expected_revision=1
                )
                original = ledger.outstanding("alice")
                # Installed host provisions these databases with private file modes.
                for folder, name in (
                    ("baselines", "baselines.sqlite"),
                    ("baselines", "watch_runs.sqlite"),
                    ("investigations", "cases.sqlite"),
                    ("investigations", "capture_jobs.sqlite"),
                ):
                    (source / folder / name).chmod(0o600)
                schemas = {
                    name: case_recovery_snapshot.schema_descriptor(
                        source / folder / name
                    )
                    for name, folder in {
                        "baselines.sqlite": "baselines",
                        "watch_runs.sqlite": "baselines",
                        "cases.sqlite": "investigations",
                        "capture_jobs.sqlite": "investigations",
                    }.items()
                }
                events = []
                evidence = adapters.snapshot_fixture_databases(
                    source,
                    root / "copy",
                    expected_schemas=schemas,
                    processes_stopped=lambda: True,
                    unsettled_dispatches=0,
                    journal=events.append,
                )
                self.assertEqual(len(evidence), 4)
                restored = JobLedger(
                    root / "copy/capture_jobs.sqlite", clock=lambda: 100000
                )
                self.assertEqual(restored.outstanding("alice"), original)
                for digit in "23":
                    restored.reserve(
                        "alice",
                        "adm-capture-" + digit * 32,
                        "c" * 64,
                        1,
                        301,
                        "a" * 32,
                        transport_hash="c" * 64,
                    )
                with self.assertRaises(QuotaExceeded):
                    restored.reserve(
                        "alice",
                        "adm-capture-" + "4" * 32,
                        "c" * 64,
                        1,
                        301,
                        "a" * 32,
                        transport_hash="c" * 64,
                    )
                with self.assertRaises(adapters.RestoreError):
                    adapters.snapshot_fixture_databases(
                        source,
                        root / "refused",
                        expected_schemas=schemas,
                        processes_stopped=lambda: True,
                        unsettled_dispatches=1,
                        journal=events.append,
                    )
                self.assertFalse((root / "refused").exists())
        finally:
            sys.path.remove(bin_path)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.home = self.state / "source/splunk"
        self.home.mkdir(mode=0o700, parents=True)
        self.tls = self.state / "tls"
        self.tls.mkdir(mode=0o700)
        (self.home / "synthetic.db").write_bytes(b"data")
        (self.tls / "ca.pem").write_bytes(b"private fixture")
        self.custody = self.root / "custody"
        self.custody.mkdir(mode=0o700)
        self.events = []
        self.receipt = {
            "unit_retired": True,
            "cgroup_empty": True,
            "processes_retired": True,
            "sids_terminal_absent": True,
            "source_pid": 321,
            "source_start_ticks": 123,
            "source_guid_sha256": "a" * 64,
            "tls_ca_sha256": hashlib.sha256(b"private fixture").hexdigest(),
            "license_group": "Enterprise",
            "native_sids": ["123.1"],
            "state_host_uid": os.getuid(),
            "idmap_evidence_sha256": "c" * 64,
            "retirement_evidence_sha256": "d" * 64,
        }
        self.patches = [
            patch.object(adapters, "CUSTODY_STATE", self.state),
            patch.object(adapters, "CUSTODY_ROOT", self.custody),
            patch.object(
                adapters, "CUSTODY_PATHS", {"home": self.home, "tls": self.tls}
            ),
            patch.object(adapters, "CUSTODY_OWNER", os.getuid()),
            patch.object(adapters, "OFFICIAL_LINKS_COUNT", 0),
            patch.object(
                adapters,
                "OFFICIAL_LINKS_SHA256",
                hashlib.sha256(adapters.canonical({})).hexdigest(),
            ),
            patch.object(os, "geteuid", return_value=0),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])
        self.addCleanup(self.temp.cleanup)

    def test_retirement_receipt_requires_prior_exact_sid_evidence_and_process_proof(
        self,
    ):
        import copy

        provenance = {
            "unit": "atlas-platform-recovery-20261118.service",
            "cgroup": "/system.slice/atlas-platform-recovery-20261118.service",
            "source_pid": 321,
            "source_start_ticks": 123,
            "source_guid_sha256": "a" * 64,
            "tls_ca_sha256": self.receipt["tls_ca_sha256"],
            "license_group": "Enterprise",
            "native_jobs": [],
            "stop_intent_sequence": 10,
            "transport_sha256": "e" * 64,
            "authority_sha256": "f" * 64,
            "state_host_uid": self.receipt["state_host_uid"],
            "idmap_evidence_sha256": "c" * 64,
            "live_provenance_sha256": "d" * 64,
        }
        for i in (1, 2):
            provenance["native_jobs"].append(
                {
                    "sid": "123." + str(i),
                    "terminal_sequence": i * 2 - 1,
                    "absence_sequence": i * 2,
                    "terminal_evidence_sha256": "1" * 64,
                    "absence_evidence_sha256": "2" * 64,
                    "principal_sha256": "3" * 64,
                    "query_sha256": "4" * 64,
                    "source_guid_sha256": "a" * 64,
                    "transport_sha256": "e" * 64,
                    "authority_sha256": "f" * 64,
                }
            )
        kwargs = {
            "read_unit": lambda _: {"state": "inactive", "main_pid": 0},
            "read_cgroup": lambda _: [],
            "read_process_start": lambda _: None,
            "verify_prior_native_evidence": lambda job, _: True,
            "verify_stop_intent": lambda _: True,
            "read_tls_ca_sha256": lambda: self.receipt["tls_ca_sha256"],
        }
        original = copy.deepcopy(provenance)

        def mutate_stop(item):
            item["source_pid"] = 999
            provenance["source_pid"] = 888
            return True

        def mutate_job(job, item):
            job["sid"] = "999.1"
            item["native_jobs"].clear()
            return True

        frozen = adapters.observe_fixture_retirement(
            provenance,
            **dict(
                kwargs,
                verify_stop_intent=mutate_stop,
                verify_prior_native_evidence=mutate_job,
            ),
        )
        self.assertEqual(frozen["source_pid"], original["source_pid"])
        self.assertEqual(frozen["native_sids"], ["123.1", "123.2"])
        provenance = original
        result = adapters.observe_fixture_retirement(provenance, **kwargs)
        self.assertTrue(adapters._retirement_receipt(result))
        for key, invalid in (
            ("read_unit", lambda _: {"state": "active", "main_pid": 321}),
            ("read_cgroup", lambda _: [444]),
            ("read_process_start", lambda _: 123),
            ("verify_prior_native_evidence", lambda job, _: job["sid"] != "123.2"),
            ("verify_stop_intent", lambda _: False),
            ("read_tls_ca_sha256", lambda: "f" * 64),
        ):
            with self.subTest(key=key), self.assertRaises(adapters.RestoreError):
                adapters.observe_fixture_retirement(
                    provenance, **dict(kwargs, **{key: invalid})
                )
        for field, value in (
            ("absence_sequence", 11),
            ("source_guid_sha256", "0" * 64),
            ("transport_sha256", "0" * 64),
        ):
            bad = copy.deepcopy(provenance)
            bad["native_jobs"][0][field] = value
            with self.subTest(field=field), self.assertRaises(adapters.RestoreError):
                adapters.observe_fixture_retirement(bad, **kwargs)

    def test_restored_identity_records_differences_without_claiming_endpoint_restore(
        self,
    ):
        restored = {
            "pid": 322,
            "start_ticks": 124,
            "guid_sha256": self.receipt["source_guid_sha256"],
            "tls_ca_sha256": self.receipt["tls_ca_sha256"],
            "license_group": "Enterprise",
            "source_custody_inaccessible": True,
            "observation_sha256": "e" * 64,
        }
        result = adapters.assess_restored_identity(self.receipt, restored)
        self.assertTrue(result["identity_compatible"])
        self.assertFalse(result["endpoint_restore_qualified"])
        restored["tls_ca_sha256"] = "f" * 64
        self.assertFalse(
            adapters.assess_restored_identity(self.receipt, restored)[
                "identity_compatible"
            ]
        )
        restored["source_custody_inaccessible"] = False
        with self.assertRaises(adapters.RestoreError):
            adapters.assess_restored_identity(self.receipt, restored)

    def test_noreplace_uses_exported_libc_and_never_falls_back(self):
        import ctypes
        from types import SimpleNamespace
        from unittest.mock import patch

        class Call:
            argtypes = None
            restype = None

            def __init__(self):
                self.calls = []

            def __call__(self, *args):
                self.calls.append(args)
                return 0

        function = Call()
        with patch.object(
            ctypes, "CDLL", return_value=SimpleNamespace(renameat2=function)
        ):
            adapters._rename_noreplace(3, "source", 4, "destination")
        self.assertEqual(function.calls, [(3, b"source", 4, b"destination", 1)])
        with patch.object(ctypes, "CDLL", return_value=SimpleNamespace()):
            with self.assertRaises(adapters.RestoreError):
                adapters._rename_noreplace(3, "source", 4, "destination")

    def test_sealed_native_kv_archive_custody_and_partial_refusal(self):
        from unittest.mock import patch

        directory = self.custody / "sealed-source/var/lib/splunk/kvstorebackup"
        directory.mkdir(mode=0o700, parents=True)
        source = directory / adapters.NATIVE_KV_NAME
        source.write_bytes(b"synthetic native archive")
        source.chmod(0o600)
        expected = {
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "size": source.stat().st_size,
        }
        original_data = source.read_bytes()
        original_expected = copy.deepcopy(expected)

        def mutate_archive():
            source.write_bytes(b"x" * len(original_data))
            expected["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            return self.receipt

        with self.assertRaises(adapters.RestoreError):
            adapters.seal_kv_archive(
                expected=expected,
                source_retirement=self.receipt,
                retirement_verified=mutate_archive,
                journal=self.events.append,
            )
        self.assertNotIn("sealed_kv_copy_verified", [e["state"] for e in self.events])
        source.write_bytes(original_data)
        expected = original_expected
        self.events.clear()
        result = adapters.seal_kv_archive(
            expected=expected,
            source_retirement=self.receipt,
            retirement_verified=lambda: self.receipt,
            journal=self.events.append,
        )
        self.assertEqual(result, expected)
        self.assertEqual(
            (self.custody / adapters.SEALED_KV_NAME).read_bytes(), source.read_bytes()
        )
        with self.assertRaises(FileExistsError):
            adapters.seal_kv_archive(
                expected=expected,
                source_retirement=self.receipt,
                retirement_verified=lambda: self.receipt,
                journal=self.events.append,
            )
        (self.custody / adapters.SEALED_KV_NAME).unlink()
        self.events.clear()
        with patch("os.write", return_value=0):
            with self.assertRaises(adapters.RestoreError):
                adapters.seal_kv_archive(
                    expected=expected,
                    source_retirement=self.receipt,
                    retirement_verified=lambda: self.receipt,
                    journal=self.events.append,
                )
        self.assertEqual(
            [event["state"] for event in self.events], ["sealed_kv_copy_intent"]
        )
        self.assertTrue((self.custody / adapters.SEALED_KV_NAME).exists())
        self.assertEqual(source.read_bytes(), b"synthetic native archive")

    def test_sealed_archive_installs_only_into_distinct_fresh_canonical_home(self):
        import os
        from unittest.mock import patch

        old = self.home.stat()
        source_dir = self.home / "var/lib/splunk/kvstorebackup"
        source_dir.mkdir(mode=0o700, parents=True)
        source = source_dir / adapters.NATIVE_KV_NAME
        source.write_bytes(b"native kv backup")
        source.chmod(0o600)
        expected = {
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "size": source.stat().st_size,
        }
        with patch.object(
            adapters,
            "_rename_noreplace",
            side_effect=lambda sf, sn, df, dn: os.rename(
                sn, dn, src_dir_fd=sf, dst_dir_fd=df
            ),
        ):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        adapters.seal_kv_archive(
            expected=expected,
            source_retirement=self.receipt,
            retirement_verified=lambda: self.receipt,
            journal=self.events.append,
        )
        self.home.mkdir(mode=0o700)
        target_dir = self.home / "var/lib/splunk/kvstorebackup"
        target_dir.mkdir(mode=0o700, parents=True)
        new = self.home.stat()
        target = {
            "unit_retired": True,
            "cgroup_empty": True,
            "processes_retired": True,
            "target_home_device": new.st_dev,
            "target_home_inode": new.st_ino,
            "target_host_uid": new.st_uid,
            "target_host_gid": new.st_gid,
            "target_guid_sha256": "1" * 64,
            "fresh_evidence_sha256": "2" * 64,
            "retirement_evidence_sha256": "3" * 64,
        }
        # Local test UID/GID are non-root fixture IDs. Actual target mapping is
        # obtained from independent native evidence before the mutation.
        if new.st_gid in (0, 1000):
            self.skipTest("test group is reserved")
        identity = {"device": old.st_dev, "inode": old.st_ino}
        wrong_identity = {"device": old.st_dev, "inode": old.st_ino + 1}

        def mutate_source_identity():
            wrong_identity["inode"] = old.st_ino
            return target

        with self.assertRaises(adapters.RestoreError):
            adapters.install_sealed_kv_archive(
                expected=expected,
                source_identity=wrong_identity,
                target_proof=target,
                target_verified=mutate_source_identity,
                journal=self.events.append,
            )
        self.assertFalse((target_dir / adapters.NATIVE_KV_NAME).exists())
        adapters.install_sealed_kv_archive(
            expected=expected,
            source_identity=identity,
            target_proof=target,
            target_verified=lambda: target,
            journal=self.events.append,
        )
        self.assertEqual(
            (target_dir / adapters.NATIVE_KV_NAME).read_bytes(), b"native kv backup"
        )
        with self.assertRaises(adapters.RestoreError):
            adapters.install_sealed_kv_archive(
                expected=expected,
                source_identity=identity,
                target_proof=target,
                target_verified=lambda: target,
                journal=self.events.append,
            )
        self.assertEqual(
            (
                self.custody
                / "sealed-source/var/lib/splunk/kvstorebackup"
                / adapters.NATIVE_KV_NAME
            ).read_bytes(),
            b"native kv backup",
        )
        (target_dir / adapters.NATIVE_KV_NAME).unlink()
        with self.assertRaises(adapters.RestoreError):
            adapters.install_sealed_kv_archive(
                expected=expected,
                source_identity={"device": old.st_dev, "inode": old.st_ino + 1},
                target_proof=target,
                target_verified=lambda: target,
                journal=self.events.append,
            )
        sealed = self.custody / adapters.SEALED_KV_NAME
        sealed.write_bytes(b"tampered archive")
        with self.assertRaises(adapters.RestoreError):
            adapters.install_sealed_kv_archive(
                expected=expected,
                source_identity=identity,
                target_proof=target,
                target_verified=lambda: target,
                journal=self.events.append,
            )
        self.assertFalse((target_dir / adapters.NATIVE_KV_NAME).exists())

    def test_exact_real_directory_moves_and_identity_reconciliation(self):
        import os
        from unittest.mock import patch

        original = self.home.stat()
        (self.custody / "outer-evidence.json").write_text("retained")
        with patch.object(
            adapters,
            "_rename_noreplace",
            side_effect=lambda srcfd, src, dstfd, dst: os.rename(
                src, dst, src_dir_fd=srcfd, dst_dir_fd=dstfd
            ),
        ):
            result = adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        self.assertTrue(result["canonical_home_absent"])
        self.assertEqual((self.custody / "outer-evidence.json").read_text(), "retained")
        self.assertEqual(
            adapters.reconcile_custody_identity(
                "home", {"device": original.st_dev, "inode": original.st_ino}
            ),
            "custody",
        )
        self.assertEqual(
            (self.custody / "sealed-source/synthetic.db").read_bytes(), b"data"
        )
        self.assertEqual(
            [e["state"] for e in self.events],
            [
                "custody_seal_intent",
                "custody_move_intent",
                "custody_move_ack",
                "custody_move_intent",
                "custody_move_ack",
                "custody_sealed",
            ],
        )

    def test_only_sealed_internal_link_is_preserved_without_following(self):
        import os
        from unittest.mock import patch

        links = {"lib.so": "synthetic.db"}
        (self.home / "lib.so").symlink_to("synthetic.db")
        digest = hashlib.sha256(adapters.canonical(links)).hexdigest()
        with (
            patch.object(adapters, "OFFICIAL_LINKS_COUNT", 1),
            patch.object(adapters, "OFFICIAL_LINKS_SHA256", digest),
            patch.object(
                adapters,
                "_rename_noreplace",
                side_effect=lambda sf, sn, df, dn: os.rename(
                    sn, dn, src_dir_fd=sf, dst_dir_fd=df
                ),
            ),
        ):
            result = adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links=links,
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        self.assertTrue(result["canonical_home_absent"])
        self.assertTrue((self.custody / "sealed-source/lib.so").is_symlink())
        self.assertEqual(
            os.readlink(self.custody / "sealed-source/lib.so"), "synthetic.db"
        )

    def test_unapproved_missing_modified_and_escaping_links_refuse(self):
        from unittest.mock import patch
        import os

        links = {"lib.so": "synthetic.db"}
        digest = hashlib.sha256(adapters.canonical(links)).hexdigest()
        with (
            patch.object(adapters, "OFFICIAL_LINKS_COUNT", 1),
            patch.object(adapters, "OFFICIAL_LINKS_SHA256", digest),
        ):
            with self.assertRaises(adapters.RestoreError):
                adapters.seal_fixture_custody(
                    source_uid=os.getuid(),
                    retirement_verified=lambda: self.receipt,
                    official_links=links,
                    unsettled_dispatches=0,
                    journal=self.events.append,
                )
            (self.home / "lib.so").symlink_to("../changed")
            with self.assertRaises(adapters.RestoreError):
                adapters.seal_fixture_custody(
                    source_uid=os.getuid(),
                    retirement_verified=lambda: self.receipt,
                    official_links=links,
                    unsettled_dispatches=0,
                    journal=self.events.append,
                )
        escape = {"lib.so": "../../outside"}
        with (
            patch.object(adapters, "OFFICIAL_LINKS_COUNT", 1),
            patch.object(
                adapters,
                "OFFICIAL_LINKS_SHA256",
                hashlib.sha256(adapters.canonical(escape)).hexdigest(),
            ),
        ):
            with self.assertRaises(adapters.RestoreError):
                adapters._validated_official_links(escape)
        self.assertEqual(self.events, [])

    def test_occupied_sealed_destination_refuses_before_any_move(self):
        import os

        (self.custody / "sealed-tls").mkdir(mode=0o700)
        with self.assertRaises(adapters.RestoreError):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        self.assertTrue(self.home.exists())
        self.assertEqual(self.events, [])

    def test_intermediate_symlink_and_replaced_ancestor_refuse(self):
        import os

        source_parent = self.home.parent
        actual = self.state / "other-source"
        source_parent.rename(actual)
        source_parent.symlink_to(actual, target_is_directory=True)
        with self.assertRaises((OSError, adapters.RestoreError)):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        source_parent.unlink()
        actual.rename(source_parent)
        calls = 0

        def retirement():
            nonlocal calls
            calls += 1
            if calls == 2:
                source_parent.rename(actual)
                source_parent.symlink_to(actual, target_is_directory=True)
            return self.receipt

        with self.assertRaises((OSError, adapters.RestoreError)):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=retirement,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        self.assertEqual([e["state"] for e in self.events], ["custody_seal_intent"])
        self.assertTrue((actual / "splunk").exists())
        self.assertFalse((self.custody / "sealed-source").exists())

    def test_interrupted_second_move_retains_exact_identity_without_replay(self):
        import os
        from unittest.mock import patch

        original = self.tls.stat()
        calls = []

        def move(srcfd, source, dstfd, destination):
            calls.append(source)
            if len(calls) == 2:
                raise OSError("injected move failure")
            os.rename(source, destination, src_dir_fd=srcfd, dst_dir_fd=dstfd)

        with patch.object(adapters, "_rename_noreplace", side_effect=move):
            with self.assertRaises(OSError):
                adapters.seal_fixture_custody(
                    source_uid=os.getuid(),
                    retirement_verified=lambda: self.receipt,
                    official_links={},
                    unsettled_dispatches=0,
                    journal=self.events.append,
                )
        self.assertEqual(
            adapters.reconcile_custody_identity(
                "tls", {"device": original.st_dev, "inode": original.st_ino}
            ),
            "source",
        )
        self.assertEqual(
            [e["state"] for e in self.events],
            [
                "custody_seal_intent",
                "custody_move_intent",
                "custody_move_ack",
                "custody_move_intent",
            ],
        )
        self.assertTrue((self.custody / "sealed-source").exists())
        self.assertTrue(self.tls.exists())

    def test_symlink_hardlink_and_unknown_dispatch_refused_before_moves(self):
        import os

        link = self.home / "link"
        link.symlink_to("synthetic.db")
        with self.assertRaises((OSError, adapters.RestoreError)):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        link.unlink()
        os.link(self.home / "synthetic.db", link)
        with self.assertRaises(adapters.RestoreError):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=0,
                journal=self.events.append,
            )
        link.unlink()
        with self.assertRaises(adapters.RestoreError):
            adapters.seal_fixture_custody(
                source_uid=os.getuid(),
                retirement_verified=lambda: self.receipt,
                official_links={},
                unsettled_dispatches=1,
                journal=self.events.append,
            )
        self.assertEqual(self.events, [])
        self.assertTrue(self.home.exists())


if __name__ == "__main__":
    unittest.main()
