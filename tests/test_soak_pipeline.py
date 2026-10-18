"""Pure correctness and safety checks for the local soak harness."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import soak_pipeline as soak
import lab_lock


class SoakPipelineTest(unittest.TestCase):
    def setUp(self):
        self._lock_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._lock_directory.cleanup)
        lock_path = Path(self._lock_directory.name) / "lab.lock"
        self._lock_path_patch = patch.object(
            lab_lock, "default_lock_path", return_value=lock_path
        )
        self._lock_path_patch.start()
        self.addCleanup(self._lock_path_patch.stop)

    def test_batch_is_deterministic_and_token_scoped(self):
        config = soak.Workload(pods=2, flow_copies=1)
        first, digest = soak.batch_events(config, "cycle-a")
        second, digest2 = soak.batch_events(config, "cycle-a")
        self.assertEqual(first, second)
        self.assertEqual(digest, digest2)
        event = json.loads(first[0])
        self.assertEqual(event["source"], "adm-soak:cycle-a")
        self.assertEqual(event["fields"]["adm.soak_token"], "cycle-a")

    def test_post_batches_converts_lines_to_bounded_hec_calls(self):
        lines = [b"a", b"b", b"c"]
        with patch.object(soak.lab, "_hec_post") as post:
            self.assertEqual(soak.post_batches(lines, workers=1), 3)
        self.assertEqual([call.args[0] for call in post.call_args_list], [b"a\nb\nc"])

    def test_post_batches_splits_at_lab_limit(self):
        lines = [b"x" * (soak.lab.MAX_BATCH_BYTES - 1), b"y"]
        with patch.object(soak.lab, "_hec_post") as post:
            self.assertEqual(soak.post_batches(lines, workers=1), 2)
        self.assertEqual(len(post.call_args_list), 2)

    def test_replay_waits_for_both_physical_writes_before_dedup_check(self):
        runner = object()
        with (
            patch.object(
                soak,
                "checked_search",
                side_effect=[
                    [{"count": "4"}],
                    [{"id": "a"}, {"id": "b"}],
                    [{"id": "a"}, {"id": "b"}],
                ],
            ) as search,
            patch.object(soak, "wait_count") as visible,
            patch.object(soak, "wait_summary") as summary,
        ):
            soak.rollup(runner, 100, 110, 12, 30)
        self.assertEqual([call.args[2] for call in visible.call_args_list], [6, 8])
        self.assertEqual(summary.call_count, 2)
        self.assertEqual(search.call_args_list[1].kwargs["index_window"], (100, 110))
        self.assertEqual(search.call_args_list[2].kwargs["index_window"], (100, 110))

    def test_cli_rejects_invalid_fault_cycle_before_preflight(self):
        with patch.object(soak, "preflight") as preflight:
            with self.assertRaises(SystemExit) as exited:
                soak.main(["--cycles", "2", "--fault-cycle", "3"])
        self.assertEqual(exited.exception.code, 2)
        preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()
