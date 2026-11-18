"""Fail-closed adapter for retained, independently authorized source records.

This adapter does not manufacture collector evidence or configure a producer.
Its broker is a trusted deployment integration, not caller-controlled input.
"""

import hashlib
import math
import time

from .executor import Unavailable
from .store import Forbidden, Invalid, _json, _text, validate_capture


class RetainedSourceProvider:
    """Resolve already closed captures through a trusted evidence broker.

    Broker methods lookup(principal, selection, window), read(reference), and
    authorize(principal, reference, provenance) must enforce the contract in
    BASELINE_SOURCE_PROVIDER.md. lookup never dispatches collection work.
    """

    contract_revision = "retained-source-v1"

    def __init__(self, broker, producer_revision, clock=time.time):
        self.broker = broker
        self.producer_revision = _text(producer_revision, "producer revision")
        self.contract_revision = "retained-source-v1:" + self.producer_revision
        self.clock = clock

    @staticmethod
    def _check(budget):
        if budget is not None:
            budget.check()

    def _record(self, principal, reference, budget):
        _text(principal, "principal")
        _text(reference, "reference", 4096)
        self._check(budget)
        record = self.broker.read(reference)
        self._check(budget)
        if not isinstance(record, dict) or set(record) != {"capture", "provenance"}:
            raise Unavailable("invalid retained record")
        capture, p = record["capture"], record["provenance"]
        try:
            validate_capture(capture)
            fields = {
                "reference",
                "selection",
                "window",
                "captureDigest",
                "authority",
                "scope",
                "sourceRevision",
                "configRevision",
                "normalizationRevision",
                "signatureVersion",
                "requiredLatenessSeconds",
                "watermark",
                "knowledgeHorizon",
                "coverageStart",
                "coverageEnd",
                "sampling",
                "lostEvents",
                "truncated",
                "capped",
                "producerRevision",
                "windowSemantics",
            }
            if not isinstance(p, dict) or set(p) != fields:
                raise Invalid("invalid provenance")
            selection = p["selection"]
            if not isinstance(selection, dict) or set(selection) != {
                "service",
                "environment",
                "cluster",
                "namespace",
            }:
                raise Invalid("invalid selection")
            for key, value in selection.items():
                _text(value, key)
            if (
                p["producerRevision"] != self.producer_revision
                or p["windowSemantics"] != "half-open"
            ):
                raise Invalid("producer contract mismatch")
            if not isinstance(p["sourceRevision"], str) or not p[
                "sourceRevision"
            ].startswith(self.producer_revision + ":"):
                raise Invalid("source revision does not bind producer")
            c = capture["coverage"]
            for key in (
                "authority",
                "scope",
                "sourceRevision",
                "configRevision",
                "normalizationRevision",
                "signatureVersion",
                "requiredLatenessSeconds",
                "knowledgeHorizon",
            ):
                if type(p[key]) is not type(c[key]) or p[key] != c[key]:
                    raise Invalid("provenance mismatch")
            if p["reference"] != reference or p["window"] != c["requested"]:
                raise Invalid("provenance mismatch")
            if (
                p["captureDigest"]
                != hashlib.sha256(_json(capture).encode()).hexdigest()
            ):
                raise Invalid("capture digest mismatch")
            if (
                p["sampling"] != "none"
                or type(p["lostEvents"]) is not int
                or p["lostEvents"] != 0
                or p["truncated"] is not False
                or p["capped"] is not False
            ):
                raise Invalid("incomplete collection")
            for key in ("watermark", "coverageStart", "coverageEnd"):
                if type(p[key]) not in (int, float) or not math.isfinite(p[key]):
                    raise Invalid("invalid coverage boundary")
            now = self.clock()
            if (
                type(now) not in (int, float)
                or not math.isfinite(now)
                or p["coverageStart"] > p["window"]["start"]
                or p["coverageEnd"] < p["window"]["end"]
                or p["watermark"] < p["window"]["end"]
                or p["knowledgeHorizon"] > now
                or p["knowledgeHorizon"]
                < p["window"]["end"] + p["requiredLatenessSeconds"]
            ):
                raise Invalid("collection not closed")
        except (Invalid, KeyError, TypeError, ValueError) as exc:
            raise Unavailable("source evidence unavailable") from exc
        snapshot = _json(record)
        self._check(budget)
        if self.broker.verify_evidence(reference, record) is not True:
            raise Unavailable("producer evidence unverified")
        self._check(budget)
        if self.broker.authorize(principal, reference, p) is not True:
            raise Forbidden("source access denied")
        self._check(budget)
        if _json(record) != snapshot:
            raise Unavailable("source evidence changed")
        # Freeze callback-owned objects before exposing them or comparing them.
        import json

        return json.loads(_json(record))

    def capture(self, principal, selection, window, *, budget=None):
        self._check(budget)
        reference = self.broker.lookup(principal, selection, window)
        self._check(budget)
        record = self._record(principal, reference, budget)
        if (
            record["provenance"]["selection"] != selection
            or record["provenance"]["window"] != window
        ):
            raise Unavailable("source selection unavailable")
        return {"reference": reference, "capture": record["capture"]}

    def resolve(self, principal, reference, *, budget=None):
        return self._record(principal, reference, budget)["capture"]

    def entitled(self, principal, reference, capture, *, budget=None):
        return _json(self._record(principal, reference, budget)["capture"]) == _json(
            capture
        )

    def attest_selection(
        self, principal, selection, reference, capture, *, budget=None
    ):
        record = self._record(principal, reference, budget)
        if record["provenance"]["selection"] != selection or _json(
            record["capture"]
        ) != _json(capture):
            raise Unavailable("source selection unavailable")
        c = capture["coverage"]
        return {
            "selection": record["provenance"]["selection"],
            "providerContractRevision": self.contract_revision,
            "captureDigest": record["provenance"]["captureDigest"],
            **{
                key: c[key]
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
