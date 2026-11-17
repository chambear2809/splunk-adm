import copy
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_baselines_lib.executor import RunBudget, Unavailable, Uncertain, WatchExecutor  # noqa: E402
from adm_baselines_lib.run_store import ExecutionStore  # noqa: E402
from adm_baselines_lib.store import (
    BaselineStore,
    Conflict,
    Forbidden,
    Invalid,
    QuotaExceeded,
    _json,
)  # noqa: E402
from tests.test_baselines import capture  # noqa: E402


class Provider:
    contract_revision = "v1"

    def __init__(self):
        self.rows = {"base": capture()}
        self.calls = 0
        self.tamper = False
        self.denied = False
        self.budgets = []
        self.fail_capture = False

    def capture(self, principal, selection, window, *, budget):
        self.budgets.append(budget)
        self.calls += 1
        if self.fail_capture:
            raise RuntimeError("unknown")
        row = capture(window["start"])
        row["dependencies"] = []
        self.rows["new"] = row
        return {"reference": "new", "capture": copy.deepcopy(row)}

    def resolve(self, principal, reference, *, budget):
        self.budgets.append(budget)
        return copy.deepcopy(self.rows[reference])

    def entitled(self, principal, reference, row, *, budget):
        self.budgets.append(budget)
        return not self.denied

    def attest_selection(self, principal, selection, reference, row, *, budget):
        self.budgets.append(budget)
        c = row["coverage"]
        return {
            "selection": selection,
            "providerContractRevision": self.contract_revision,
            "captureDigest": hashlib.sha256(_json(row).encode()).hexdigest(),
            **{
                k: c[k]
                for k in (
                    "authority",
                    "scope",
                    "sourceRevision",
                    "configRevision",
                    "normalizationRevision",
                )
            },
            "matches": not self.tamper,
        }


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.provider = Provider()
        self.user = "alice"
        self.admin = True
        self.now = 100
        self.journal = ExecutionStore(
            os.path.join(self.tmp.name, "watch_runs.sqlite"), clock=lambda: self.now
        )

        def factory(principal, provider, budget):
            def resolve(user, ref):
                budget.check()
                result = provider.resolve(user, ref, budget=budget)
                budget.check()
                return result

            def entitled(user, ref, row):
                budget.check()
                result = provider.entitled(user, ref, row, budget=budget)
                budget.check()
                return result

            return BaselineStore(
                os.path.join(self.tmp.name, "baseline.db"),
                lambda *_: True,
                resolve,
                source_entitlement=entitled,
                clock=lambda: self.now,
            )

        self.factory = factory
        self.store = factory(self.user, self.provider, RunBudget())
        created = self.store.create("alice", "create", "baseline", "base")
        self.id = created["id"]
        self.store.set_watch(
            "alice",
            "watch",
            self.id,
            1,
            {"id": "w", "threshold": 1, "cooldownSeconds": 0, "expectedWindows": []},
        )
        self.executor = WatchExecutor(
            self.journal,
            factory,
            lambda: self.user,
            lambda _: self.admin,
            self.provider,
            clock=lambda: self.now,
        )
        self.selection = {
            "service": "s",
            "environment": "e",
            "cluster": "c",
            "namespace": "n",
        }
        self.window = {"start": 10, "end": 20}

    def binding(self):
        item = self.executor.create_binding(self.id, "w", self.selection)
        return self.executor.set_enabled(item["id"], item["revision"], True)

    def test_complete_empty_and_redacted_retry(self):
        binding = self.binding()
        self.provider.budgets.clear()
        result = self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(len({id(b) for b in self.provider.budgets}), 1)
        self.assertEqual(result, {"id": self.id, "revision": 3, "resultWithheld": True})
        self.assertEqual(
            self.executor.execute(binding["id"], self.window, "request"), result
        )
        self.assertEqual(self.provider.calls, 1)

    def test_admin_owner_attestation_and_no_source(self):
        self.admin = False
        with self.assertRaises(Forbidden):
            self.executor.create_binding(self.id, "w", self.selection)
        self.admin = True
        self.user = "bob"
        with self.assertRaises(Forbidden):
            self.executor.create_binding(self.id, "w", self.selection)
        self.user = "alice"
        self.provider.tamper = True
        with self.assertRaises(Unavailable):
            self.executor.create_binding(self.id, "w", self.selection)
        no_source = WatchExecutor(
            self.journal,
            lambda *_: self.fail("factory called"),
            lambda: self.fail("principal called"),
            lambda _: True,
        )
        with self.assertRaises(Unavailable):
            no_source.create_binding(self.id, "w", self.selection)

    def test_capture_unknown_never_recaptures(self):
        b = self.binding()
        self.provider.fail_capture = True
        with self.assertRaises(RuntimeError):
            self.executor.execute(b["id"], self.window, "r")
        self.provider.fail_capture = False
        with self.assertRaises(Uncertain):
            self.executor.execute(b["id"], self.window, "r")
        self.assertEqual(self.provider.calls, 1)

    def test_invalid_window_and_disabled(self):
        b = self.binding()
        for window in (
            {"start": 0, "end": 301},
            {"start": 1, "end": 101},
            {"start": True, "end": 10},
        ):
            with self.assertRaises(Invalid):
                self.executor.execute(b["id"], window, "r")
        self.executor.set_enabled(b["id"], b["revision"], False)
        with self.assertRaises(Forbidden):
            self.executor.execute(b["id"], self.window, "r")
        self.assertEqual(self.provider.calls, 0)

    def test_budget(self):
        budget = RunBudget(lambda: 1)
        for _ in range(3):
            budget.claim_search()
        with self.assertRaises(Unavailable):
            budget.claim_search()
        budget.charge_cleanup(2)
        self.assertEqual(budget.cleanup_remaining, 1)
        budget.charge_cleanup(2)
        self.assertEqual(budget.cleanup_remaining, 0)

    def test_lost_evaluation_response_retries_same_reference_and_revision(self):
        binding = self.binding()
        original_factory = self.factory
        attempts = []

        def factory(*args):
            store = original_factory(*args)
            evaluate = store.evaluate_window

            def lost(*params, **kwargs):
                attempts.append((params, kwargs))
                result = evaluate(*params, **kwargs)
                if len(attempts) == 1:
                    raise RuntimeError("response lost")
                return result

            store.evaluate_window = lost
            return store

        self.executor.store_factory = factory
        with self.assertRaises(RuntimeError):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(
            self.executor.execute(binding["id"], self.window, "request"),
            {"id": self.id, "revision": 3, "resultWithheld": True},
        )
        self.assertEqual(attempts[0], attempts[1])
        self.assertEqual(self.provider.calls, 1)

    def test_changed_reference_after_uncertain_evaluation_is_rejected(self):
        binding = self.binding()
        original_factory = self.factory
        attempts = []

        def factory(*args):
            store = original_factory(*args)

            def fail(*params, **kwargs):
                attempts.append((params, kwargs))
                raise RuntimeError("evaluation unavailable")

            store.evaluate_window = fail
            return store

        self.executor.store_factory = factory
        with self.assertRaises(RuntimeError):
            self.executor.execute(binding["id"], self.window, "request")
        self.provider.rows["new"]["dependencies"] = copy.deepcopy(
            self.provider.rows["base"]["dependencies"]
        )
        with self.assertRaises(Unavailable):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.provider.calls, 1)

    def test_reference_changes_inside_store_evaluation(self):
        binding = self.binding()
        original_factory = self.factory

        def factory(*args):
            store = original_factory(*args)
            evaluate = store.evaluate_window

            def mutate(*params, **kwargs):
                self.provider.rows["new"]["dependencies"] = copy.deepcopy(
                    self.provider.rows["base"]["dependencies"]
                )
                return evaluate(*params, **kwargs)

            store.evaluate_window = mutate
            return store

        self.executor.store_factory = factory
        with self.assertRaises((Invalid, Conflict, Unavailable)):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(self.store.occurrences("alice", self.id, "w")["items"], [])
        self.executor.store_factory = original_factory
        with self.assertRaises(Unavailable):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(self.provider.calls, 1)

    def test_disable_reenable_fences_uncertain_retry(self):
        binding = self.binding()
        original_factory = self.factory
        attempts = []

        def factory(*args):
            store = original_factory(*args)

            def fail(*params, **kwargs):
                attempts.append((params, kwargs))
                raise RuntimeError("evaluation unavailable")

            store.evaluate_window = fail
            return store

        self.executor.store_factory = factory
        with self.assertRaises(RuntimeError):
            self.executor.execute(binding["id"], self.window, "request")
        disabled = self.executor.set_enabled(binding["id"], binding["revision"], False)
        self.executor.set_enabled(binding["id"], disabled["revision"], True)
        with self.assertRaises(Conflict):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.provider.calls, 1)

    def test_authority_loss_after_evaluation_withholds_acknowledgment(self):
        binding = self.binding()
        original_factory = self.factory

        def factory(*args):
            store = original_factory(*args)
            evaluate = store.evaluate_window

            def revoke(*params, **kwargs):
                result = evaluate(*params, **kwargs)
                self.admin = False
                return result

            store.evaluate_window = revoke
            return store

        self.executor.store_factory = factory
        with self.assertRaises(Forbidden):
            self.executor.execute(binding["id"], self.window, "request")
        self.admin = True
        self.executor.store_factory = original_factory
        self.assertEqual(
            self.executor.execute(binding["id"], self.window, "request"),
            {"id": self.id, "revision": 3, "resultWithheld": True},
        )
        self.assertEqual(self.provider.calls, 1)

    def test_future_horizon_cannot_be_prepared_or_evaluated(self):
        binding = self.binding()
        capture_source = self.provider.capture

        def future(*args, **kwargs):
            result = capture_source(*args, **kwargs)
            result["capture"]["coverage"]["knowledgeHorizon"] = 101
            self.provider.rows["new"] = copy.deepcopy(result["capture"])
            return result

        self.provider.capture = future
        with self.assertRaises(Invalid):
            self.executor.execute(binding["id"], self.window, "request")
        with self.assertRaises(Uncertain):
            self.executor.execute(binding["id"], self.window, "request")

    def test_changed_principal_or_contract_during_capture_fails_closed(self):
        binding = self.binding()
        capture_source = self.provider.capture

        def changed(*args, **kwargs):
            result = capture_source(*args, **kwargs)
            self.user = "bob"
            return result

        self.provider.capture = changed
        with self.assertRaises(Forbidden):
            self.executor.execute(binding["id"], self.window, "request")
        self.user = "alice"
        self.provider.contract_revision = "v2"
        with self.assertRaises(Unavailable):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(self.provider.calls, 1)

    def test_revoked_source_and_wrong_attestation_prevent_capture(self):
        binding = self.binding()
        self.provider.denied = True
        with self.assertRaises(Forbidden):
            self.executor.execute(binding["id"], self.window, "request")
        self.provider.denied = False
        self.provider.tamper = True
        with self.assertRaises(Unavailable):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(self.provider.calls, 0)

    def test_late_callback_result_is_not_accepted(self):
        binding = self.binding()
        tick = [0]
        self.executor.monotonic = lambda: tick[0]
        capture_source = self.provider.capture

        def late(*args, **kwargs):
            result = capture_source(*args, **kwargs)
            tick[0] = 26
            return result

        self.provider.capture = late
        with self.assertRaises(Unavailable):
            self.executor.execute(binding["id"], self.window, "request")
        tick[0] = 0
        with self.assertRaises(Uncertain):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(self.provider.calls, 1)

    def test_disable_reenable_during_capture_fences_evaluation(self):
        binding = self.binding()
        capture_source = self.provider.capture

        def changed(*args, **kwargs):
            result = capture_source(*args, **kwargs)
            disabled = self.journal.set_enabled(
                binding["id"], binding["revision"], False
            )
            self.journal.set_enabled(binding["id"], disabled["revision"], True)
            return result

        self.provider.capture = changed
        with self.assertRaises(Conflict):
            self.executor.execute(binding["id"], self.window, "request")
        with self.assertRaises(Conflict):
            self.executor.execute(binding["id"], self.window, "request")
        self.assertEqual(self.provider.calls, 1)

    def test_unresolved_capture_consumes_global_quota(self):
        binding = self.binding()
        self.provider.fail_capture = True
        for start in (10, 20, 30):
            with self.assertRaises(RuntimeError):
                self.executor.execute(
                    binding["id"], {"start": start, "end": start + 10}, str(start)
                )
        with self.assertRaises(QuotaExceeded):
            self.executor.execute(binding["id"], {"start": 40, "end": 50}, "40")
        self.assertEqual(self.provider.calls, 3)


if __name__ == "__main__":
    unittest.main()
