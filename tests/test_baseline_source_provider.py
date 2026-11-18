import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.test_baselines import capture
from adm_baselines_lib.executor import Unavailable
from adm_baselines_lib.retained_artifacts import RetainedArtifacts
from adm_baselines_lib.source_provider import RetainedSourceProvider
from adm_baselines_lib.store import Forbidden, _json


class RetainedProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.selection = {
            "service": "s",
            "environment": "e",
            "cluster": "c",
            "namespace": "n",
        }
        row = capture()
        row["dependencies"] = []
        row["coverage"]["sourceRevision"] = "p1:s1"
        c = row["coverage"]
        self.record = {
            "capture": row,
            "provenance": {
                "selection": self.selection,
                "window": c["requested"],
                "captureDigest": hashlib.sha256(_json(row).encode()).hexdigest(),
                **{
                    k: c[k]
                    for k in (
                        "authority",
                        "scope",
                        "sourceRevision",
                        "configRevision",
                        "normalizationRevision",
                        "signatureVersion",
                        "requiredLatenessSeconds",
                        "knowledgeHorizon",
                    )
                },
                "watermark": 10,
                "coverageStart": 0,
                "coverageEnd": 10,
                "sampling": "none",
                "lostEvents": 0,
                "truncated": False,
                "capped": False,
                "producerRevision": "p1",
                "windowSemantics": "half-open",
            },
        }
        self.allowed = True
        self.verified = True
        self.broker = RetainedArtifacts(
            self.directory, lambda *_: self.allowed, lambda *_: self.verified
        )
        self.provider = RetainedSourceProvider(self.broker, "p1", clock=lambda: 20)

    def write_record(self):
        record = copy.deepcopy(self.record)
        reference = hashlib.sha256(_json(record).encode()).hexdigest()
        record["provenance"]["reference"] = reference
        path = self.directory / (reference + ".json")
        path.write_text(_json(record))
        path.chmod(0o600)
        key = hashlib.sha256(
            _json([self.selection, {"start": 0, "end": 10}]).encode()
        ).hexdigest()
        index = self.directory / ("index-" + key + ".json")
        index.write_text(json.dumps({"reference": reference}))
        index.chmod(0o600)
        return reference

    def test_empty_capture_reauthorization_and_selection(self):
        ref = self.write_record()
        result = self.provider.capture("alice", self.selection, {"start": 0, "end": 10})
        self.assertEqual(result["reference"], ref)
        self.assertEqual(result["capture"]["dependencies"], [])
        self.assertTrue(
            self.provider.attest_selection(
                "alice", self.selection, ref, result["capture"]
            )["matches"]
        )
        wrong = dict(self.selection, namespace="other")
        with self.assertRaises(Unavailable):
            self.provider.attest_selection("alice", wrong, ref, result["capture"])
        self.verified = False
        with self.assertRaises(Unavailable):
            self.provider.resolve("alice", ref)
        self.verified = True
        self.allowed = False
        with self.assertRaises(Forbidden):
            self.provider.resolve("alice", ref)

    def test_incomplete_provenance_and_tamper_fail(self):
        for field, value in (
            ("lostEvents", 1),
            ("sampling", "unknown"),
            ("watermark", 9),
            ("coverageStart", 1),
            ("coverageEnd", 9),
            ("capped", True),
            ("knowledgeHorizon", 11),
            ("truncated", True),
        ):
            with self.subTest(field=field):
                original = self.record["provenance"][field]
                self.record["provenance"][field] = value
                ref = self.write_record()
                with self.assertRaises(Unavailable):
                    self.provider.resolve("alice", ref)
                self.record["provenance"][field] = original
        ref = self.write_record()
        path = self.directory / (ref + ".json")
        path.write_text("{}")
        with self.assertRaises(Unavailable):
            self.provider.resolve("alice", ref)

    def test_unsafe_file_rejected(self):
        ref = self.write_record()
        (self.directory / (ref + ".json")).chmod(0o644)
        with self.assertRaises(Unavailable):
            self.provider.resolve("alice", ref)

    def test_fifo_artifact_and_index_are_rejected_without_blocking(self):
        reference = "a" * 64
        window = {"start": 0, "end": 10}
        key = hashlib.sha256(_json([self.selection, window]).encode()).hexdigest()
        script = """
import sys
sys.path.insert(0, sys.argv[1])
from adm_baselines_lib.executor import Unavailable
from adm_baselines_lib.retained_artifacts import RetainedArtifacts
broker = RetainedArtifacts(sys.argv[2], lambda *_: True, lambda *_: True)
try:
    if sys.argv[3] == 'artifact':
        broker.read('a' * 64)
    else:
        broker.lookup('alice', {'service': 's', 'environment': 'e',
                               'cluster': 'c', 'namespace': 'n'},
                      {'start': 0, 'end': 10})
except Unavailable:
    pass
else:
    raise AssertionError('FIFO was accepted')
"""
        app_bin = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin"
        for kind, name in (
            ("artifact", reference + ".json"),
            ("index", "index-" + key + ".json"),
        ):
            with self.subTest(kind=kind):
                os.mkfifo(self.directory / name, 0o600)
                subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        script,
                        str(app_bin),
                        str(self.directory),
                        kind,
                    ],
                    check=True,
                    timeout=3,
                    capture_output=True,
                    text=True,
                )
