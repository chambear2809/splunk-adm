"""One explicitly requested watch run; no scheduling or source qualification.

Trusted providers must enforce transport and cleanup limits themselves. These
checks reject late callback results, but cannot interrupt synchronous Python.
"""

import hashlib
import math
import secrets
import time

from .store import (
    Conflict,
    Forbidden,
    Invalid,
    _json,
    _text,
    compatible,
    validate_capture,
)


class Unavailable(Exception):
    pass


class Uncertain(Exception):
    pass


class RunBudget:
    """One shared collection budget, including all source callbacks."""

    def __init__(self, monotonic=time.monotonic):
        self.monotonic = monotonic
        self.deadline = monotonic() + 25
        self.searches = 0
        self.cleanup_remaining = 3.0

    def check(self):
        if self.monotonic() >= self.deadline:
            raise Unavailable("source budget exhausted")

    def claim_search(self):
        self.check()
        if self.searches >= 3:
            raise Unavailable("source budget exhausted")
        self.searches += 1

    def charge_cleanup(self, seconds):
        if (
            not isinstance(seconds, (int, float))
            or isinstance(seconds, bool)
            or not math.isfinite(seconds)
            or seconds < 0
        ):
            raise Invalid("invalid cleanup time")
        self.cleanup_remaining = max(0.0, self.cleanup_remaining - seconds)


class WatchExecutor:
    def __init__(
        self,
        journal,
        store_factory,
        principal,
        is_admin,
        source_provider=None,
        clock=time.time,
        monotonic=time.monotonic,
    ):
        self.journal = journal
        self.store_factory = store_factory
        self.principal = principal
        self.is_admin = is_admin
        self.source_provider = source_provider
        self.clock = clock
        self.monotonic = monotonic

    def _start(self):
        if self.source_provider is None:
            raise Unavailable("source unavailable")
        budget = RunBudget(self.monotonic)
        budget.check()
        principal = _text(self.principal(), "principal")
        budget.check()
        if self.is_admin(principal) is not True:
            raise Forbidden("administrator required")
        budget.check()
        revision = _text(self.source_provider.contract_revision, "provider revision")
        return (
            principal,
            revision,
            budget,
            self.store_factory(principal, self.source_provider, budget),
        )

    def _current(self, principal, budget):
        budget.check()
        current = self.principal()
        budget.check()
        admin = self.is_admin(principal)
        budget.check()
        if current != principal or admin is not True:
            raise Forbidden("administrator identity changed")

    def _call(self, budget, fn, *args):
        budget.check()
        result = fn(*args, budget=budget)
        budget.check()
        return result

    @staticmethod
    def _selection(selection):
        fields = ("service", "environment", "cluster", "namespace")
        if not isinstance(selection, dict) or set(selection) != set(fields):
            raise Invalid("invalid selection")
        return {key: _text(selection[key], key) for key in fields}

    def _context(self, store, principal, baseline_id, watch_id, budget):
        budget.check()
        context = store._execution_context(principal, baseline_id, watch_id)
        budget.check()
        if not isinstance(context, dict) or set(context) != {
            "baselineId",
            "owner",
            "revision",
            "watchId",
            "baselineVersion",
            "reference",
            "capture",
        }:
            raise Unavailable("invalid execution context")
        if (
            context["owner"] != principal
            or context["baselineId"] != baseline_id
            or context["watchId"] != watch_id
        ):
            raise Forbidden("baseline owner required")
        if (
            type(context["revision"]) is not int
            or context["revision"] < 1
            or type(context["baselineVersion"]) is not int
            or context["baselineVersion"] < 1
        ):
            raise Unavailable("invalid execution context")
        _text(context["reference"], "reference", 4096)
        validate_capture(context["capture"])
        return context

    def _proof(self, principal, selection, reference, capture, revision, budget):
        if self.source_provider.contract_revision != revision:
            raise Unavailable("provider revision changed")
        validate_capture(capture)
        now = self.clock()
        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
            or now < 0
            or capture["coverage"]["knowledgeHorizon"] > now
        ):
            raise Invalid("evidence horizon is in the future")
        resolved = self._call(
            budget, self.source_provider.resolve, principal, reference
        )
        if _json(resolved) != _json(capture):
            raise Unavailable("source evidence changed")
        if (
            self._call(
                budget, self.source_provider.entitled, principal, reference, capture
            )
            is not True
        ):
            raise Forbidden("source access denied")
        attestation = self._call(
            budget,
            self.source_provider.attest_selection,
            principal,
            selection,
            reference,
            capture,
        )
        coverage = capture["coverage"]
        expected = {
            "selection": selection,
            "providerContractRevision": revision,
            "captureDigest": hashlib.sha256(_json(capture).encode("utf-8")).hexdigest(),
            **{
                key: coverage[key]
                for key in (
                    "authority",
                    "scope",
                    "sourceRevision",
                    "configRevision",
                    "normalizationRevision",
                )
            },
            "matches": True,
        }
        if self.source_provider.contract_revision != revision:
            raise Unavailable("provider revision changed")
        if (
            not isinstance(attestation, dict)
            or set(attestation) != set(expected)
            or attestation.get("matches") is not True
            or attestation != expected
        ):
            raise Unavailable("source selection unverified")

    def create_binding(self, baseline_id, watch_id, selection):
        principal, revision, budget, store = self._start()
        selection = self._selection(selection)
        context = self._context(store, principal, baseline_id, watch_id, budget)
        self._proof(
            principal,
            selection,
            context["reference"],
            context["capture"],
            revision,
            budget,
        )
        latest = self._context(store, principal, baseline_id, watch_id, budget)
        if latest != context:
            raise Conflict("baseline changed")
        self._current(principal, budget)
        return self.journal.create_binding(
            {
                "baselineId": baseline_id,
                "watchId": watch_id,
                "baselineVersion": context["baselineVersion"],
                "principal": principal,
                "selection": selection,
                "providerContractRevision": revision,
            }
        )

    def _binding(self, binding_id, principal, provider_revision):
        binding = self.journal.binding(binding_id)
        if binding["definition"]["principal"] != principal:
            raise Forbidden("binding owner required")
        if binding["definition"]["providerContractRevision"] != provider_revision:
            raise Unavailable("provider revision changed")
        return binding

    def set_enabled(self, binding_id, expected_revision, enabled):
        principal, revision, budget, store = self._start()
        binding = self._binding(binding_id, principal, revision)
        context = self._context(
            store,
            principal,
            binding["definition"]["baselineId"],
            binding["definition"]["watchId"],
            budget,
        )
        if context["baselineVersion"] != binding["definition"]["baselineVersion"]:
            raise Conflict("watch version changed")
        self._current(principal, budget)
        return self.journal.set_enabled(binding_id, expected_revision, enabled)

    def execute(self, binding_id, window, request_id):
        principal, revision, budget, store = self._start()
        binding = self._binding(binding_id, principal, revision)
        if binding["enabled"] is not True:
            raise Forbidden("binding disabled")
        if (
            not isinstance(window, dict)
            or set(window) != {"start", "end"}
            or any(type(window[k]) is not int for k in window)
            or window["start"] < 0
            or not 0 < window["end"] - window["start"] <= 300
            or window["end"] > self.clock()
        ):
            raise Invalid("invalid window")
        _text(request_id, "request id", 128)
        context = self._context(
            store,
            principal,
            binding["definition"]["baselineId"],
            binding["definition"]["watchId"],
            budget,
        )
        if context["baselineVersion"] != binding["definition"]["baselineVersion"]:
            raise Conflict("watch version changed")
        self._proof(
            principal,
            binding["definition"]["selection"],
            context["reference"],
            context["capture"],
            revision,
            budget,
        )
        lease = secrets.token_hex(16)
        run = self.journal.begin(
            principal,
            request_id,
            binding_id,
            window,
            lease,
            expected_binding_revision=binding["revision"],
        )
        try:
            if run["state"] == "committed":
                return run["receipt"]
            if run["state"] in ("capture_unknown", "rejected"):
                raise Uncertain("run cannot be resumed")
            if run["state"] == "intent":
                self._current(principal, budget)
                current = self._binding(binding_id, principal, revision)
                if not current["enabled"] or current["revision"] != binding["revision"]:
                    raise Conflict("binding changed")
                if self.source_provider.contract_revision != revision:
                    raise Unavailable("provider revision changed")
                run = self.journal.begin(
                    principal,
                    request_id,
                    binding_id,
                    window,
                    lease,
                    expected_binding_revision=binding["revision"],
                )
                if run["state"] != "intent" or run["leaseOwner"] != lease:
                    raise Uncertain("capture intent unavailable")
                result = self._call(
                    budget,
                    self.source_provider.capture,
                    principal,
                    binding["definition"]["selection"],
                    window,
                )
                if not isinstance(result, dict) or set(result) != {
                    "reference",
                    "capture",
                }:
                    raise Unavailable("invalid source result")
                reference = _text(result["reference"], "reference", 4096)
                candidate = result["capture"]
                self._proof(
                    principal,
                    binding["definition"]["selection"],
                    reference,
                    candidate,
                    revision,
                    budget,
                )
                if candidate["coverage"]["returned"] != window or not compatible(
                    context["capture"], candidate
                ):
                    raise Invalid("incompatible capture")
                run = self.journal.transition(
                    run["id"],
                    principal,
                    lease,
                    run["revision"],
                    "prepared",
                    reference=reference,
                    captureDigest=hashlib.sha256(
                        _json(candidate).encode("utf-8")
                    ).hexdigest(),
                    baselineRevision=context["revision"],
                    evaluationKey=secrets.token_hex(16),
                    binding_revision=binding["revision"],
                )
            candidate = self._call(
                budget, self.source_provider.resolve, principal, run["reference"]
            )
            if hashlib.sha256(_json(candidate).encode("utf-8")).hexdigest() != run.get(
                "captureDigest"
            ):
                raise Unavailable("retained capture changed")
            self._proof(
                principal,
                binding["definition"]["selection"],
                run["reference"],
                candidate,
                revision,
                budget,
            )
            if candidate["coverage"]["returned"] != window or not compatible(
                context["capture"], candidate
            ):
                raise Invalid("incompatible capture")
            self._current(principal, budget)
            fresh_binding = self._binding(binding_id, principal, revision)
            if (
                not fresh_binding["enabled"]
                or fresh_binding["revision"] != binding["revision"]
            ):
                raise Conflict("binding changed")
            fresh_context = self._context(
                store,
                principal,
                binding["definition"]["baselineId"],
                binding["definition"]["watchId"],
                budget,
            )
            if (
                fresh_context["baselineVersion"]
                != binding["definition"]["baselineVersion"]
                or fresh_context["reference"] != context["reference"]
                or _json(fresh_context["capture"]) != _json(context["capture"])
            ):
                raise Conflict("baseline changed")
            if run["state"] == "prepared":
                if fresh_context["revision"] != run["baselineRevision"]:
                    raise Conflict("baseline changed")
            run = self.journal.transition(
                run["id"],
                principal,
                lease,
                run["revision"],
                "evaluation_unknown",
                binding_revision=binding["revision"],
            )
            budget.check()
            receipt = store.evaluate_window(
                principal,
                run["evaluationKey"],
                binding["definition"]["baselineId"],
                run["baselineRevision"],
                binding["definition"]["watchId"],
                binding["definition"]["baselineVersion"],
                run["reference"],
                expected_capture_digest=run["captureDigest"],
            )
            budget.check()
            self._current(principal, budget)
            if (
                not isinstance(receipt, dict)
                or receipt.get("id") != binding["definition"]["baselineId"]
                or type(receipt.get("revision")) is not int
            ):
                raise Uncertain("evaluation result unavailable")
            receipt = {
                "id": receipt["id"],
                "revision": receipt["revision"],
                "resultWithheld": True,
            }
            run = self.journal.transition(
                run["id"],
                principal,
                lease,
                run["revision"],
                "committed",
                receipt=receipt,
            )
            return receipt
        finally:
            if run["leaseOwner"] == lease and run["state"] not in (
                "committed",
                "rejected",
            ):
                try:
                    self.journal.release(run["id"], principal, lease, run["revision"])
                except Conflict:
                    pass
