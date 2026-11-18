"""Controller interface/ownership regressions; no Docker behavior is simulated."""

import json
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "splunk"))
import case_request_lab as owned

FIXTURE = Path(__file__).parent / "splunk/case_request_native.py"
spec = importlib.util.spec_from_file_location(
    "case_request_native_diagnostics", FIXTURE
)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class RequestLabGuardTests(unittest.TestCase):
    def test_request_diagnostics_accepts_bounded_four_frame_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frames = [
                {
                    "file": "x" * 128,
                    "line": 12345,
                    "function": "f" * 128,
                }
                for _ in range(4)
            ]
            path = root / "diagnostic-1234-topology.json"
            path.write_text(
                json.dumps(
                    {
                        "phase": "topology",
                        "status": "error",
                        "error_type": "FileNotFoundError",
                        "frames": frames,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            path.chmod(0o600)
            self.assertGreater(path.stat().st_size, 256)
            self.assertLessEqual(path.stat().st_size, 4096)
            with patch.object(native, "CONTROL", root):
                self.assertEqual(
                    native.request_diagnostics(),
                    [
                        {
                            "phase": "topology",
                            "error_type": "FileNotFoundError",
                            "frames": frames,
                        }
                    ],
                )

    def test_memory_reserve_uses_actual_bytes_with_large_peer_limit(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from rehearse_case_requests import memory_reserve

        with self.assertRaisesRegex(RuntimeError, "peer memory reserve"):
            memory_reserve(["12GiB / 64GiB"], 15 * 1024**3)
        self.assertEqual(
            memory_reserve(["512MiB / 64GiB", "256MiB / 1GiB"], 15 * 1024**3),
            768 * 1024**2,
        )
        with self.assertRaisesRegex(RuntimeError, "unknown peer"):
            memory_reserve(["18.75%"], 15 * 1024**3)

    def test_positive_guard_passes_exact_tuple_to_recorded_identity_reader(self):
        info = {
            "State": {"Running": True},
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": owned.NAME + "-" + s,
                    "Destination": "/opt/splunk/" + s,
                }
                for s in ("etc", "var")
            ],
            "HostConfig": {
                "PortBindings": {p: [] for p in ("8000/tcp", "8089/tcp", "8088/tcp")}
            },
        }
        with (
            patch.dict(
                os.environ, {"ADM_LAB_REQUEST_BOUNDS": "1", "ADM_LAB_WEB_TLS": "1"}
            ),
            patch.object(
                owned.lab, "task_identity", return_value=(owned.TASK, owned.NAME)
            ),
            patch.object(owned.LabLock, "check_owned", return_value=True),
            patch.object(owned.lab, "verify_target") as verify,
            patch.object(
                owned.lab.lab_tls, "read_container", return_value="a" * 64
            ) as recorded,
            patch.object(
                owned.subprocess,
                "check_output",
                side_effect=lambda *_args, **_kwargs: json.dumps([info]).encode(),
            ),
        ):
            self.assertEqual(owned.guard(), "a" * 64)
            recorded.assert_called_once_with(
                owned.lab.SECRETS, (owned.TASK, owned.NAME)
            )
            verify.assert_called_once()
            info["Mounts"].append(
                {"Type": "bind", "Source": "/other", "Destination": "/other"}
            )
            with self.assertRaisesRegex(RuntimeError, "exact-volume"):
                owned.guard()

    def test_missing_lock_or_task_refuses_before_docker(self):
        with (
            patch.dict(
                os.environ, {"ADM_LAB_REQUEST_BOUNDS": "1", "ADM_LAB_WEB_TLS": "1"}
            ),
            patch.object(
                owned.lab, "task_identity", return_value=(owned.TASK, owned.NAME)
            ),
            patch.object(owned.LabLock, "check_owned", return_value=False),
            patch.object(owned.lab, "verify_target") as verify,
        ):
            with self.assertRaisesRegex(RuntimeError, "inherited live lock"):
                owned.guard()
            verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
