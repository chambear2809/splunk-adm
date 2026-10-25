"""Optional real HEC transport/ack/readback checks with an explicitly trusted lab CA."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import urllib.parse
import uuid

import lab
from tools.hec_delivery import (
    _post_json,
    deliver_pending,
    enqueue_capture,
    spool_status,
)

CA_BUNDLE = os.environ.get("ADM_LAB_HEC_CA_BUNDLE")
ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1" and CA_BUNDLE,
    "requires disposable Splunk lab and ADM_LAB_HEC_CA_BUNDLE with verified hostname",
)
class VerifiedHecDeliveryRuntimeTest(unittest.TestCase):
    def test_verified_tls_application_acceptance_ack_and_indexed_readback_are_distinct(
        self,
    ):
        input_name = "atlas-delivery-" + uuid.uuid4().hex[:12]
        token = str(uuid.uuid4())
        path = "/servicesNS/nobody/splunk_httpinput/data/inputs/http"
        with lab._mgmt(
            "POST",
            path + "?output_mode=json",
            {
                "name": input_name,
                "token": token,
                "disabled": "0",
                "index": "atlas_o11y",
                "indexes": "atlas_o11y",
                "useACK": "true",
            },
        ) as response:
            response.read()
        self.addCleanup(self.remove_input, path, input_name)
        configured = lab._json(
            "GET", path + "/" + urllib.parse.quote("http://" + input_name, safe="")
        )
        self.assertIn(
            configured["entry"][0]["content"].get("useACK"),
            (True, "true", "1", 1),
            "Test input did not enable Enterprise acknowledgments",
        )
        now = int(time.time())
        events = copy.deepcopy(
            json.loads((ROOT / "fixtures/o11y/complete.json").read_text())["events"]
        )
        observer, capture_id = input_name, uuid.uuid4().hex
        for envelope in events:
            envelope.update(time=now, host=observer, index="atlas_o11y")
            envelope["event"].update(
                observer_id=observer, capture_id=capture_id, captured_at=now
            )
        with tempfile.TemporaryDirectory(prefix="atlas-hec-runtime-") as directory:
            root = Path(directory)
            source = root / "capture.ndjson"
            source.write_text(
                "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in events)
            )
            source.chmod(0o600)
            spool = root / "queue"
            enqueue_capture(source, spool, source_id="o11y_health")
            response_keys = []

            def observe_response(*args, **kwargs):
                response = _post_json(*args, **kwargs)
                response_keys.extend(json.loads(response.body).keys())
                return response

            summary = deliver_pending(
                spool,
                endpoint=lab.HEC + "/services/collector/event",
                token=token,
                ca_bundle=CA_BUNDLE,
                ack_mode="enterprise",
                timeout_seconds=10,
                ack_wait_seconds=30,
                poll_interval_seconds=1,
                post_json=observe_response,
            )
            checkpoints = list((spool / "checkpoints").glob("*.json"))
            safe_error = (
                json.loads(checkpoints[0].read_text()).get("last_error_code")
                if checkpoints
                else "missing_checkpoint"
            )
            self.assertEqual(
                summary.http_accepted_captures, 1, (safe_error, response_keys)
            )
            self.assertEqual(summary.indexer_acknowledged_captures, 1)
            self.assertEqual(summary.pending_captures, 0)
            # Sender status deliberately does not label an acknowledgment searchable.
            self.assertEqual(spool_status(spool).indexer_acknowledged_not_searchable, 1)
            self.assertTrue(
                source.exists(),
                "Queueing/delivery must retain the original finalized source",
            )
            query = f'search index=atlas_o11y sourcetype="atlas:o11y_health" host="{observer}" | stats count AS count dc(record_id) AS unique_records'
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                rows = lab.search(query, str(now - 60), str(now + 60))
                if rows and int(rows[0].get("count", -1)) == len(events):
                    self.assertEqual(int(rows[0]["unique_records"]), len(events))
                    break
                time.sleep(0.5)
            else:
                self.fail(
                    "Acknowledged capture was not found by indexed readback within the deadline"
                )

    @staticmethod
    def remove_input(path, name):
        encoded = urllib.parse.quote("http://" + name, safe="")
        with lab._mgmt("DELETE", path + "/" + encoded):
            pass
