"""Pure resume and duplicate-injection guards for the Cisco upgrade harness."""

import copy
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from tools.cisco_contract_migration import Migration, Refused

from tests.splunk.test_cisco_upgrade import (
    _assert_completed_cutover_evidence,
    _await_restoration_v1_checkpoint,
    _restoration_checkpoint_origin,
    _gap_injection_resume_action,
    _read_gap_evidence,
    _resume_staging,
    _upgrade_resume_route,
    _qualification_cutover,
    QualificationInterrupted,
)


class CiscoUpgradeHarnessResumeTest(unittest.TestCase):
    @staticmethod
    def _expected_row():
        return Migration._v1_record_map(
            [
                {
                    "rollup_id": "a" * 64,
                    "adm_record": "conversation",
                    "records": 1,
                    "client_port_list": "61001",
                }
            ]
        )["a" * 64]

    class _FakeJournal:
        def __init__(self, value):
            self.value = value

        def read(self):
            return self.value

    class _FakeMigration:
        def __init__(self, journal):
            self.journal = CiscoUpgradeHarnessResumeTest._FakeJournal(journal)
            self.calls = []

        def _load(self):
            return self.journal.value

        def prepare(self, start, end):
            self.calls.append("prepare")

        def backfill(self):
            self.calls.append("backfill")

        def validate(self, scenario):
            self.calls.append("validate")
            return {"cutover_eligible": True, "status": "coverage_validated"}

    @staticmethod
    def _completed_cutover():
        # Compact shape of retained native disabled-pass evidence. Configuration
        # identities come from the actual interface, without copying lab data.
        migration = Migration(None, None)
        interface, _ = migration._interface()
        acl = {"app": "splunk_adm", "owner": "nobody", "sharing": "app"}
        journal = {
            "phase": "rolled_back",
            "candidate_cutover_eligible": True,
            "rollback": {"state": "complete"},
            "origin": {
                "saved_searches": {
                    writer["name"]: {"content": {"disabled": True}, "acl": acl}
                    for writer in interface["activation"]["writer_contracts"]
                },
                "macros": {
                    selector["name"]: {
                        "definition": selector["before"],
                        "args": ",".join(
                            f"argument{index}"
                            for index in range(
                                int(re.search(r"\((\d+)\)$", selector["name"])[1])
                                if "(" in selector["name"]
                                else 0
                            )
                        ),
                        "acl": acl,
                    }
                    for selector in interface["activation"]["cutover_selectors"]
                },
            },
            "cutover": {
                "state": "complete",
                "started_at": 1792353737,
                "completed_at": 1792354038,
                "scheduled_cycle_bounds": {
                    "index_earliest": 1792353300,
                    "index_latest": 1792353600,
                },
                "scheduled_watermark_at": 1792354023,
                "public_selector_evidence": [],
            },
        }
        mutations = migration._build_cutover_mutations(journal, interface)
        for mutation in mutations:
            mutation.update(state="applied", verified_at=1792354026)
        journal["cutover"]["mutations"] = mutations
        for surface in interface["public_surfaces"]:
            if surface.get("surface") == "writers":
                continue
            for version in ("v2", "network_client_v2", "traffic_v2"):
                spec = surface.get(version)
                if isinstance(spec, dict) and (
                    spec.get("public_after_invoke")
                    or version in {"network_client_v2", "traffic_v2"}
                    and spec.get("invoke")
                ):
                    journal["cutover"]["public_selector_evidence"].append(
                        {
                            "surface": surface["surface"],
                            "version": version,
                            "phase": "public_after_invoke",
                            "validated_at": 1792354038,
                            "row_count": 1,
                            "query_sha256": "a" * 64,
                            "rows_sha256": "b" * 64,
                        }
                    )
        return migration, journal

    def test_completed_activation_survives_terminal_rollback(self):
        migration, journal = self._completed_cutover()
        self.assertEqual(_upgrade_resume_route(journal), "terminal")
        _assert_completed_cutover_evidence(migration, journal)

    def test_failed_first_history_rollback_is_not_successful_activation(self):
        migration, journal = self._completed_cutover()
        # Actual retained failed-first-history journal: staging was eligible,
        # rollback succeeded, but all eight public selectors remained pending.
        cutover = journal["cutover"]
        cutover.update(state="awaiting_first_scheduled_cycle", started_at=1792353040)
        for field in (
            "completed_at",
            "scheduled_cycle_bounds",
            "scheduled_watermark_at",
            "public_selector_evidence",
        ):
            cutover.pop(field)
        for mutation in cutover["mutations"]:
            if mutation["kind"] == "macro_definition":
                mutation["state"] = "pending"
                mutation.pop("verified_at")
        self.assertTrue(journal["candidate_cutover_eligible"])
        self.assertEqual(journal["rollback"]["state"], "complete")
        self.assertEqual(_upgrade_resume_route(journal), "terminal")
        with self.assertRaisesRegex(AssertionError, "durable completed cutover"):
            _assert_completed_cutover_evidence(migration, journal)
        # A completion label alone must not launder the pending selector plan.
        cutover.update(state="complete", completed_at=1792354038)
        with self.assertRaisesRegex(AssertionError, "unverified intended mutation"):
            _assert_completed_cutover_evidence(migration, journal)

    def test_terminal_activation_requires_exact_applied_plan_and_readbacks(self):
        migration, baseline = self._completed_cutover()
        for change_index, change in enumerate(
            (
                lambda c: c["mutations"].pop(),
                lambda c: c["mutations"].append(copy.deepcopy(c["mutations"][0])),
                lambda c: c["mutations"][0].update(state="request_unknown"),
                lambda c: c["mutations"][0].pop("verified_at"),
                lambda c: c["mutations"][0].update(verified_at=True),
                lambda c: c["mutations"][0].update(verified_at=c["completed_at"] + 1),
                lambda c: c["mutations"][-1].update(after="1"),
                lambda c: c["mutations"][-1].update(rest_target="/different"),
            )
        ):
            journal = copy.deepcopy(baseline)
            change(journal["cutover"])
            with (
                self.subTest(change=change_index),
                self.assertRaises(AssertionError),
            ):
                _assert_completed_cutover_evidence(migration, journal)

    def test_terminal_activation_requires_cycle_and_public_smoke_proof(self):
        migration, baseline = self._completed_cutover()
        for change_index, change in enumerate(
            (
                lambda c: c.update(completed_at=None),
                lambda c: c.update(completed_at=True),
                lambda c: c.update(completed_at=c["started_at"] - 1),
                lambda c: c.pop("scheduled_cycle_bounds"),
                lambda c: c["scheduled_cycle_bounds"].update(index_latest=1792353601),
                lambda c: c.update(scheduled_watermark_at=c["completed_at"] + 1),
                lambda c: c["public_selector_evidence"].pop(),
                lambda c: c["public_selector_evidence"][0].update(
                    phase="rollback_before_invoke"
                ),
                lambda c: c["public_selector_evidence"][0].update(
                    validated_at=1792353000
                ),
                lambda c: c["public_selector_evidence"][0].update(rows_sha256=""),
            )
        ):
            journal = copy.deepcopy(baseline)
            change(journal["cutover"])
            with (
                self.subTest(change=change_index),
                self.assertRaises(AssertionError),
            ):
                _assert_completed_cutover_evidence(migration, journal)

    def test_phase_routes_do_not_repeat_staging(self):
        self.assertEqual(_upgrade_resume_route(None), "fresh")
        self.assertEqual(_upgrade_resume_route({"phase": "prepared"}), "backfill")
        self.assertEqual(_upgrade_resume_route({"phase": "backfilled"}), "validate")
        self.assertEqual(
            _upgrade_resume_route({"phase": "coverage_validated"}), "cutover"
        )
        self.assertEqual(
            _upgrade_resume_route({"phase": "cutover_in_progress"}), "cutover"
        )
        self.assertEqual(_upgrade_resume_route({"phase": "cutover"}), "rollback")
        self.assertEqual(
            _upgrade_resume_route({"phase": "rollback_in_progress"}), "rollback"
        )
        self.assertEqual(_upgrade_resume_route({"phase": "rolled_back"}), "terminal")

    def test_orchestration_calls_only_missing_stages(self):
        for phase, expected in (
            (None, ["prepare", "backfill", "validate"]),
            ("prepared", ["backfill", "validate"]),
            ("backfilled", ["validate"]),
            ("coverage_validated", []),
        ):
            journal = {} if phase is None else {"phase": phase}
            migration = self._FakeMigration(journal)
            _resume_staging(migration, 1, 2, {})
            self.assertEqual(migration.calls, expected)

    def test_controlled_interruption_is_durable_and_retry_does_not_rewrite(self):
        class Controller:
            def __init__(self):
                self.state = {"phase": "cutover_in_progress"}
                self.value = "1"
                self.writes = 0

            def _mutation_equal(self, mutation, first, second):
                return first == second

            def _write_journal(self, journal):
                self.state = json.loads(json.dumps(journal))

            def _apply_mutation(self, journal, mutation):
                if self.value != mutation["after"]:
                    self.value = mutation["after"]
                    self.writes += 1
                mutation["state"] = "applied"
                self._write_journal(journal)

            def cutover(self):
                self._apply_mutation(
                    self.state, {"id": "selector", "before": "1", "after": "2"}
                )
                return {"status": "cutover"}

        controller = Controller()
        with self.assertRaises(QualificationInterrupted):
            _qualification_cutover(controller, True)
        self.assertEqual(
            controller.state["qualification_interrupt"]["mutation_id"], "selector"
        )
        self.assertEqual(controller.writes, 1)
        self.assertEqual(_qualification_cutover(controller, True)["status"], "cutover")
        self.assertEqual(controller.writes, 1)

    def test_gap_marker_fails_closed_without_evidence(self):
        for state in (
            "request_pending",
            "posted",
            "receipt_unknown",
            "receipt_confirmed",
        ):
            self.assertEqual(
                _gap_injection_resume_action({"gap_injection": {"state": state}}, None),
                "reconcile_required",
            )
        self.assertEqual(_gap_injection_resume_action({}, None), "inject")
        self.assertEqual(
            _gap_injection_resume_action(
                {"gap_injection": {"state": "unexpected"}}, None
            ),
            "reconcile_required",
        )
        self.assertEqual(
            _gap_injection_resume_action({}, {"state": "injected_waiting_rollback"}),
            "reuse",
        )

    def test_gap_evidence_requires_identity_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            path.write_text(
                json.dumps(
                    {
                        "state": "injected_waiting_rollback",
                        "migration_id": "m1",
                        "source": "gap",
                        "source_port": 61001,
                        "raw_index_receipt": 100,
                        "index_slice": [0, 300],
                        "rollup_id": "a" * 64,
                        "expected_row": self._expected_row(),
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            self.assertEqual(_read_gap_evidence(path, "m1")["source"], "gap")
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "other")
            value = json.loads(path.read_text(encoding="utf-8"))
            value.pop("migration_id")
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "m1")

    def test_gap_evidence_rejects_bad_receipt_and_rollup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            value = {
                "state": "injected_waiting_rollback",
                "migration_id": "m1",
                "source": "gap",
                "source_port": 61001,
                "raw_index_receipt": 301,
                "index_slice": [0, 300],
                "rollup_id": "not-a-rollup",
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "m1")

    def test_completed_gap_evidence_can_be_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            expected = self._expected_row()
            evidence = {
                "migration_id": "m1",
                "state": "recovered_and_selectors_restored",
                "source": "gap",
                "source_port": 61001,
                "raw_index_receipt": 100,
                "index_slice": [0, 300],
                "rollup_id": "a" * 64,
                "expected_row": expected,
                "retained_row": expected,
                "selectors_restored": True,
                "manual_recovery": {
                    "slice_key": "0:300",
                    "index_bounds": [0, 300],
                    "writer_sid": "manual_sid",
                },
            }
            path.write_text(json.dumps(evidence))
            path.chmod(0o600)
            self.assertEqual(_read_gap_evidence(path, "m1"), evidence)
            for change in (
                {"selectors_restored": False},
                {"manual_recovery": {}},
                {"retained_row": {}},
                {"index_slice": [0.0, 300]},
                {"index_slice": [1, 301]},
            ):
                with self.subTest(change=change):
                    path.write_text(json.dumps({**evidence, **change}))
                    with self.assertRaises(AssertionError):
                        _read_gap_evidence(path, "m1")

    def test_gap_evidence_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gap.json"
            os.mkfifo(path, 0o600)
            with self.assertRaises(AssertionError):
                _read_gap_evidence(path, "m1")

    def test_gap_evidence_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "gap.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            link.symlink_to(target)
            with self.assertRaises(AssertionError):
                _read_gap_evidence(link, "m1")


class CiscoRestorationCheckpointTest(unittest.TestCase):
    @staticmethod
    def completed_rollback():
        # Actual enabled-origin recovery finished after the empty 20:40 cycle.
        return {
            "migration_id": "completed-enabled-origin",
            "phase": "rolled_back",
            "origin": {
                "saved_searches": {
                    "ADM - Conversation rollup": {"content": {"disabled": False}}
                }
            },
            "rollback": {
                "state": "complete",
                "completed_at": 1792356031,
                "v1_recovery": {
                    "state": "verified",
                    "observation_epoch": 1792356017,
                    "audit_observation_epoch": 1792356017,
                    "completed_at": 1792356018,
                },
            },
        }

    class Controller(Migration):
        def __init__(self, *, start=1792356290, fresh_at=1792356300):
            self.value = {"phase": "coverage_validated", "jobs": []}
            self.now = start
            self.elapsed = 0
            self.clock = lambda: self.now
            self.fresh_at = fresh_at
            self.inventory_calls = []
            self.audit_bounds = []
            self.writes = 0
            self.manual_rows = [{"rollup_id": "a" * 64, "_indextime": 1792356011}]

        def _load(self):
            return self.value

        def _write_journal(self, journal):
            self.value = copy.deepcopy(journal)
            self.writes += 1

        @staticmethod
        def cycle(anchor):
            return {
                "sid": f"scheduler__verified_v1_{anchor}",
                "index_bounds": [anchor - 600, anchor - 300],
                "event_bounds": {
                    "earliest_time": str(anchor - 86400),
                    "latest_time": str(anchor + 900),
                },
                "anchor": anchor,
                "empty_summary_warning": True,
            }

        def _scheduled_writer_cycles(self, name, journal, **bounds):
            self.inventory_calls.append((name, bounds))
            anchors = [1792356000]
            if self.fresh_at is not None and self.now >= self.fresh_at:
                anchors.append(1792356300)
            return [
                self.cycle(anchor)
                for anchor in anchors
                if bounds["lower_epoch"] <= anchor < bounds["upper_epoch"]
            ]

        def _v1_expected_rows(self, *_args):
            return {}

        def _query(self, _journal, _query, start, end, **_kwargs):
            # Exercise the unchanged empty-summary guard against a real row
            # retained from the prior, separately proven manual recovery.
            self.audit_bounds.append((start, end))
            return [row for row in self.manual_rows if start <= row["_indextime"] < end]

        def sleep(self, seconds):
            self.elapsed += seconds
            self.now += seconds

    def wait(self, controller, completed=None, timeout=60):
        return _await_restoration_v1_checkpoint(
            controller,
            completed or self.completed_rollback(),
            controller.elapsed + timeout,
            monotonic=lambda: controller.elapsed,
            sleep=controller.sleep,
        )

    def test_old_empty_checkpoint_refuses_but_later_proven_checkpoint_preserves_row(
        self,
    ):
        controller = self.Controller(start=1792356106)
        before = copy.deepcopy(controller.manual_rows)
        with self.assertRaisesRegex(Refused, "outside validated manifests"):
            controller._capture_v1_pre_pause(controller._load())
        self.assertNotIn("v1_pre_pause", controller._load())
        controller.now = 1792356290
        checkpoint = self.wait(controller)
        self.assertEqual(checkpoint["anchor"], 1792356300)
        self.assertEqual(controller.elapsed, 15)
        self.assertEqual(controller.manual_rows, before)
        self.assertEqual(checkpoint["empty_summary_proof"]["retained_rows"], 0)
        readiness = controller._load()["qualification_restoration_checkpoint"]
        self.assertEqual(readiness["origin"]["boundary"], 1792356031)
        self.assertEqual(readiness["sid"], checkpoint["sid"])
        self.assertEqual(controller.inventory_calls[1][1]["lower_epoch"], 1792356032)
        calls = len(controller.inventory_calls)
        # Resume reuses the validated checkpoint and original durable boundary.
        controller.value["phase"] = "cutover"
        self.assertEqual(self.wait(controller)["sid"], checkpoint["sid"])
        self.assertEqual(len(controller.inventory_calls), calls)

    def test_no_fresh_checkpoint_times_out_without_capture_or_target_mutation(self):
        controller = self.Controller(fresh_at=None)
        before = copy.deepcopy(controller.value)
        rows = copy.deepcopy(controller.manual_rows)
        with self.assertRaisesRegex(AssertionError, "timed out"):
            self.wait(controller, timeout=30)
        self.assertEqual(controller.elapsed, 30)
        self.assertEqual(controller.value, before)
        self.assertEqual(controller.manual_rows, rows)
        self.assertEqual(controller.writes, 0)
        self.assertFalse(controller.audit_bounds)

    def test_fresh_checkpoint_does_not_bypass_unexplained_row_guard(self):
        controller = self.Controller(start=1792356310)
        controller.manual_rows.append({"rollup_id": "b" * 64, "_indextime": 1792356301})
        rows = copy.deepcopy(controller.manual_rows)
        with self.assertRaisesRegex(Refused, "outside validated manifests"):
            self.wait(controller)
        self.assertEqual(controller.manual_rows, rows)
        self.assertEqual(controller.writes, 0)
        self.assertNotIn("v1_pre_pause", controller.value)

    def test_scheduler_refusal_propagates_without_retry_or_capture(self):
        controller = self.Controller()

        def refuse(*_args, **_kwargs):
            raise Refused("scheduled writer evidence has a missing cycle")

        controller._scheduled_writer_cycles = refuse
        with self.assertRaisesRegex(Refused, "missing cycle"):
            self.wait(controller)
        self.assertEqual(controller.elapsed, 0)
        self.assertEqual(controller.writes, 0)

    def test_resume_rejects_old_checkpoint_or_changed_recovery_boundary(self):
        controller = self.Controller()
        controller.value["phase"] = "cutover_in_progress"
        controller.value["v1_pre_pause"] = controller.cycle(1792356000)
        with self.assertRaisesRegex(AssertionError, "does not follow"):
            self.wait(controller)
        self.assertEqual(controller.writes, 0)
        controller = self.Controller(start=1792356310)
        self.wait(controller)
        changed = self.completed_rollback()
        changed["rollback"]["completed_at"] += 1
        with self.assertRaisesRegex(AssertionError, "boundary changed"):
            self.wait(controller, changed)

    def test_aged_preactivation_capture_is_revalidated_and_binding_uses_new_sid(self):
        controller = self.Controller(start=1792356310)
        first = self.wait(controller)
        controller.now = 1792356960
        fresh = controller.cycle(1792356900)
        inventory_calls = []

        def current_cycle(name, journal, **bounds):
            inventory_calls.append(bounds)
            return [fresh]

        controller._scheduled_writer_cycles = current_cycle
        checkpoint = self.wait(controller)
        self.assertGreater(controller.now - first["anchor"], 600)
        self.assertEqual(checkpoint["sid"], fresh["sid"])
        self.assertEqual(len(inventory_calls), 2)
        self.assertEqual(
            controller.value["qualification_restoration_checkpoint"]["sid"],
            fresh["sid"],
        )
        self.assertEqual(controller.value["v1_pre_pause"]["sid"], fresh["sid"])
        # Activation resume preserves the newly validated rollback anchor.
        controller.value["phase"] = "cutover_in_progress"
        self.assertEqual(self.wait(controller)["sid"], fresh["sid"])
        self.assertEqual(len(inventory_calls), 2)

    def test_partial_activation_without_checkpoint_refuses_before_readiness_poll(self):
        controller = self.Controller()
        controller.value["phase"] = "cutover_in_progress"
        with self.assertRaisesRegex(AssertionError, "lacks its durable V1 checkpoint"):
            self.wait(controller)
        self.assertFalse(controller.inventory_calls)
        self.assertEqual(controller.writes, 0)

    def test_boundary_requires_completed_recovery_and_uses_its_latest_evidence(self):
        completed = self.completed_rollback()
        self.assertEqual(
            _restoration_checkpoint_origin(completed)["boundary"], 1792356031
        )
        for mutate in (
            lambda j: j.update(phase="rollback_in_progress"),
            lambda j: j["rollback"].update(state="recovering"),
            lambda j: j["rollback"]["v1_recovery"].pop("observation_epoch"),
            lambda j: j["rollback"]["v1_recovery"].update(completed_at=True),
            lambda j: j["rollback"]["v1_recovery"].update(
                audit_observation_epoch=1792356019
            ),
        ):
            changed = copy.deepcopy(completed)
            mutate(changed)
            with self.assertRaises(AssertionError):
                _restoration_checkpoint_origin(changed)
        completed["origin"]["saved_searches"]["ADM - Conversation rollup"]["content"][
            "disabled"
        ] = True
        controller = self.Controller()
        self.assertIsNone(self.wait(controller, completed))
        self.assertFalse(controller.inventory_calls)
        self.assertEqual(controller.writes, 0)


if __name__ == "__main__":
    unittest.main()
