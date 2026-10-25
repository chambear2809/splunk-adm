"""Public capture/queue recovery behavior under interrupted local handoffs."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import capture_o11y_health as scheduled
from tools import export_o11y_health as exporter
from tools import hec_delivery


ROOT = Path(__file__).resolve().parents[1]
CONFIG = {
    "observer": "o11y-scheduled-test",
    "organization_id": "org-test",
    "realm": "us0",
    "scope": "prod",
    "service_name": "checkout",
    "environment": "production",
    "cluster": "cluster-a",
    "kubernetes_namespace": "commerce",
    "service_namespace": "payments",
    "apm_mms_id": "custom-mms",
    "timeout_seconds": 30,
}


class Interrupted(BaseException):
    """Simulate process death without turning it into an ordinary API failure."""


class Queue:
    def __init__(self):
        self.calls = []
        self.fail = False
        self.interrupt_after_copy = False
        self.status = SimpleNamespace(
            pending_captures=0,
            pending_records=0,
            used_bytes=0,
            capacity_captures=10_000,
            capacity_records=1_000_000,
            capacity_bytes=1_073_741_824,
        )

    def spool_status(self, _path):
        return self.status

    def enqueue_capture(self, path, spool, *, source_id):
        self.calls.append(source_id)
        if self.fail:
            raise RuntimeError("queue unavailable")
        spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        event = json.loads(path.read_text().splitlines()[-1])["event"]
        target = spool / (event["capture_id"] + ".ndjson")
        duplicate = target.exists()
        if not duplicate:
            shutil.copyfile(path, target)
        if self.interrupt_after_copy:
            self.interrupt_after_copy = False
            raise Interrupted()
        return SimpleNamespace(
            record_count=len(path.read_text().splitlines()), duplicate=duplicate
        )


class ScheduledCaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state, self.spool = self.root / "state", self.root / "spool"
        self.queue = Queue()
        self.captures = []

    def capture(self, request, output, *, token):
        self.assertEqual(token, "test-environment-token")
        self.captures.append((request.start, request.end))
        template = json.loads((ROOT / "fixtures/o11y/complete.json").read_text())[
            "events"
        ][-1]["event"]
        template.update(
            schema=exporter.SCHEMA,
            event_type="export_completion",
            capture_id=f"capture-{request.start}-{request.end}",
            captured_at=4000,
            capture_window_start=request.start,
            capture_window_end=request.end,
            observer_id=request.observer,
            organization_id=request.organization_id,
            realm=request.realm,
            routing_scope=request.scope,
            service_name=request.service_name,
            environment=request.environment,
            cluster=request.cluster,
            kubernetes_namespace=request.kubernetes_namespace,
            service_namespace=request.service_namespace,
            apm_mms_id=request.apm_mms_id,
            expected_record_count=0,
            signals_with_data=0,
        )
        exporter.publish_atomic(output, exporter.render_hec_ndjson(request, [template]))

    def run_capture(self, **options):
        arguments = {
            "now": 3301,
            "lag_seconds": 0,
            "token": "test-environment-token",
            "delivery": self.queue,
            "capture": self.capture,
        }
        arguments.update(options)
        return scheduled.run_once(CONFIG, self.state, self.spool, **arguments)

    def test_repeat_schedule_is_idle_then_catches_up_one_contiguous_window(self):
        first = self.run_capture()
        self.assertEqual(first["status"], "captured_to_queue")
        self.assertFalse(first["searchable"])
        self.assertEqual(self.captures, [(3000, 3300)])
        self.assertEqual(self.run_capture()["status"], "idle")
        second = self.run_capture(now=4201)
        self.assertEqual((second["window_start"], second["window_end"]), (3300, 3600))
        self.assertEqual(self.captures, [(3000, 3300), (3300, 3600)])
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state / "state.json").stat().st_mode & 0o777, 0o600)

    def test_actual_common_queue_owns_private_capture_after_handoff(self):
        result = self.run_capture(delivery=hec_delivery)
        self.assertFalse(result["searchable"])
        status = hec_delivery.spool_status(self.spool)
        self.assertEqual((status.pending_captures, status.pending_records), (1, 1))
        self.assertEqual(status.http_accepted_unverified, 0)
        self.assertFalse((self.state / "pending.ndjson").exists())
        queued = list((self.spool / "pending").glob("*.ndjson"))
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.spool.stat().st_mode & 0o777, 0o700)

    def test_actual_common_queue_replay_after_interrupted_receipt(self):
        def interrupted_receipt(*args, **kwargs):
            hec_delivery.enqueue_capture(*args, **kwargs)
            raise Interrupted()

        interrupted_queue = SimpleNamespace(
            spool_status=hec_delivery.spool_status, enqueue_capture=interrupted_receipt
        )
        with self.assertRaises(Interrupted):
            self.run_capture(delivery=interrupted_queue)
        self.assertTrue((self.state / "pending.ndjson").exists())
        result = self.run_capture(delivery=hec_delivery, token="")
        self.assertTrue(result["queue_duplicate"])
        self.assertEqual(hec_delivery.spool_status(self.spool).pending_captures, 1)
        self.assertEqual(len(self.captures), 1)

    def test_corrupt_durable_copy_never_discards_the_last_valid_source(self):
        def interrupted_receipt(*args, **kwargs):
            hec_delivery.enqueue_capture(*args, **kwargs)
            raise Interrupted()

        interrupted_queue = SimpleNamespace(
            spool_status=hec_delivery.spool_status, enqueue_capture=interrupted_receipt
        )
        with self.assertRaises(Interrupted):
            self.run_capture(delivery=interrupted_queue)
        pending = self.state / "pending.ndjson"
        original = pending.read_bytes()
        queued = next((self.spool / "pending").glob("*.ndjson"))
        queued.write_bytes(b"")
        with self.assertRaises(hec_delivery.DeliveryError):
            self.run_capture(delivery=hec_delivery, token="")
        self.assertEqual(pending.read_bytes(), original)
        self.assertEqual(queued.read_bytes(), b"")
        self.assertEqual(len(self.captures), 1)

    def test_capacity_preflight_prevents_source_capture(self):
        for key, value in (
            ("capacity_captures", 0),
            ("capacity_records", 63),
            ("used_bytes", 1_073_741_824),
        ):
            with self.subTest(key=key), patch.object(self.queue.status, key, value):
                with self.assertRaisesRegex(scheduled.CaptureStateError, "capacity"):
                    self.run_capture()
                self.assertFalse((self.state / "pending.ndjson").exists())
                self.assertEqual(self.captures, [])

    def test_enqueue_rejection_retains_completed_capture_and_recovers_without_token(
        self,
    ):
        self.queue.fail = True
        with self.assertRaises(RuntimeError):
            self.run_capture()
        pending = self.state / "pending.ndjson"
        contents = pending.read_bytes()
        self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
        self.queue.fail = False
        recovered = self.run_capture(token="", now=9300)
        self.assertEqual(recovered["status"], "recovered_to_queue")
        self.assertEqual(self.captures, [(3000, 3300)])
        self.assertFalse(pending.exists())
        self.assertEqual(next(self.spool.glob("*.ndjson")).read_bytes(), contents)

    def test_crash_after_durable_queue_copy_replays_same_capture(self):
        self.queue.interrupt_after_copy = True
        with self.assertRaises(Interrupted):
            self.run_capture()
        self.assertTrue((self.state / "pending.ndjson").is_file())
        recovered = self.run_capture(token="")
        self.assertTrue(recovered["queue_duplicate"])
        self.assertEqual(len(list(self.spool.glob("*.ndjson"))), 1)
        self.assertEqual(len(self.captures), 1)

    def test_crash_after_checkpoint_before_unlink_recovers_without_new_export(self):
        unlink = Path.unlink

        def interrupt(path, *args, **kwargs):
            if path.resolve() == (self.state / "pending.ndjson").resolve():
                raise Interrupted()
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupt), self.assertRaises(Interrupted):
            self.run_capture()
        self.assertTrue((self.state / "pending.ndjson").exists())
        self.assertTrue(self.run_capture(token="")["queue_duplicate"])
        self.assertEqual(len(self.captures), 1)

    def test_interrupted_export_retries_original_window(self):
        def interrupted(*_args, **_kwargs):
            raise Interrupted()

        with self.assertRaises(Interrupted):
            self.run_capture(capture=interrupted)
        self.assertFalse((self.state / "pending.ndjson").exists())
        self.run_capture(now=9901)
        self.assertEqual(self.captures, [(3000, 3300)])

    def test_corrupt_checkpoint_or_configuration_change_preserves_state(self):
        self.run_capture()
        checkpoint = self.state / "state.json"
        original = checkpoint.read_bytes()
        with self.assertRaisesRegex(scheduled.CaptureStateError, "configuration"):
            scheduled.run_once(
                {**CONFIG, "realm": "us1"},
                self.state,
                self.spool,
                delivery=self.queue,
                capture=self.capture,
            )
        self.assertEqual(checkpoint.read_bytes(), original)
        value = json.loads(original)
        value["last_enqueued_end"] = 1
        checkpoint.write_text(json.dumps(value))
        with self.assertRaisesRegex(scheduled.CaptureStateError, "integrity"):
            self.run_capture()
        self.assertEqual(len(self.captures), 1)
        checkpoint.write_bytes(b'{"schema_version":')
        with self.assertRaises((scheduled.CaptureStateError, json.JSONDecodeError)):
            self.run_capture()
        self.assertEqual(checkpoint.read_bytes(), b'{"schema_version":')

    def test_orphan_partial_is_never_removed_or_ignored(self):
        self.state.mkdir(mode=0o700)
        orphan = self.state / ".pending.ndjson.interrupted.partial"
        orphan.write_bytes(b"unfinished source output")
        with self.assertRaisesRegex(scheduled.CaptureStateError, "operator recovery"):
            self.run_capture()
        self.assertEqual(orphan.read_bytes(), b"unfinished source output")
        self.assertEqual(self.captures, [])

    def test_untracked_or_wrong_identity_capture_is_not_enqueued(self):
        self.queue.fail = True
        with self.assertRaises(RuntimeError):
            self.run_capture()
        pending = self.state / "pending.ndjson"
        capture = json.loads(pending.read_text())
        capture["event"]["organization_id"] = "another-org"
        pending.write_text(json.dumps(capture) + "\n")
        before = len(self.queue.calls)
        self.queue.fail = False
        with self.assertRaisesRegex(scheduled.CaptureStateError, "identity"):
            self.run_capture()
        self.assertEqual(len(self.queue.calls), before)
        self.assertTrue(pending.exists())

    def test_same_state_lock_rejects_overlapping_capture(self):
        def overlap(request, path, *, token):
            with self.assertRaisesRegex(scheduled.CaptureStateError, "Another capture"):
                self.run_capture()
            self.capture(request, path, token=token)

        self.run_capture(capture=overlap)
        self.assertEqual(len(self.captures), 1)

    def test_checkout_and_nested_spool_paths_are_rejected_before_capture(self):
        with self.assertRaisesRegex(scheduled.CaptureStateError, "outside checkouts"):
            scheduled.run_once(
                CONFIG, ROOT / "unused-state", self.spool, delivery=self.queue
            )
        with self.assertRaisesRegex(scheduled.CaptureStateError, "separate"):
            scheduled.run_once(
                CONFIG, self.state, self.state / "spool", delivery=self.queue
            )

    def test_config_rejects_secrets_unknown_keys_and_duplicate_keys(self):
        path = self.root / "config.json"
        path.write_text(json.dumps({"schema_version": 1, **CONFIG}))
        self.assertEqual(scheduled.read_config(path), CONFIG)
        for content in (
            json.dumps({"schema_version": 1, **CONFIG, "token": "test-private-value"}),
            '{"schema_version":1,"schema_version":1}',
        ):
            path.write_text(content)
            with self.assertRaises(scheduled.CaptureStateError):
                scheduled.read_config(path)
        error = io.StringIO()
        with (
            patch.dict(os.environ, {"ATLAS_HEC_SPOOL_DIR": str(self.spool)}),
            contextlib.redirect_stderr(error),
        ):
            self.assertEqual(
                scheduled.main(["--config", str(path), "--state-dir", str(self.state)]),
                75,
            )
        self.assertNotIn("test-private-value", error.getvalue())


if __name__ == "__main__":
    unittest.main()
