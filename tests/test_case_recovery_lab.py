"""Cold transfer safety boundaries; these mocks do not qualify Docker behavior."""

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "splunk"))
import case_recovery_lab as recovery  # noqa: E402


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as handle:
        root = tarfile.TarInfo(recovery.DIRECTORY)
        root.type, root.mode, root.uid, root.gid = tarfile.DIRTYPE, 0o700, 41812, 41812
        handle.addfile(root)
        for name, kind in entries:
            item = tarfile.TarInfo(recovery.DIRECTORY + "/" + name)
            item.mode, item.uid, item.gid = 0o600, 41812, 41812
            if kind == "link":
                item.type, item.linkname = tarfile.SYMTYPE, "../../other"
                handle.addfile(item)
            else:
                item.size = len(kind)
                handle.addfile(item, io.BytesIO(kind))
    return out.getvalue()


def owned_info(state):
    name = recovery.TASKS["source"][1]
    return {
        "State": state,
        "Mounts": [
            {
                "Destination": "/opt/splunk/" + suffix,
                "Type": "volume",
                "Name": name + "-" + suffix,
            }
            for suffix in ("etc", "var")
        ],
        "HostConfig": {
            "PortBindings": {key: [] for key in ("8000/tcp", "8089/tcp", "8088/tcp")}
        },
    }


class RecoveryTransferTests(unittest.TestCase):
    def test_restore_stream_retains_service_ids_without_image_user_override(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            database = directory / "cases.sqlite"
            database.write_bytes(b"sealed fixture")
            database.chmod(0o600)
            summary = {
                "files": {
                    "cases.sqlite": {
                        "size": database.stat().st_size,
                        "sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
                    }
                }
            }
            with (
                patch.object(
                    recovery.lab, "task_identity", return_value=recovery.TASKS["target"]
                ),
                patch.object(recovery, "target", return_value=("a" * 64, {})),
                patch.object(recovery, "path_present", side_effect=[False, True]),
                patch.object(
                    recovery.subprocess, "run", return_value=Mock(returncode=0)
                ) as copy,
            ):
                recovery.restore_prepared(directory, summary, uid=41812, gid=41812)
            self.assertEqual(
                copy.call_args.args[0],
                ["docker", "cp", "-", "a" * 64 + ":" + recovery.DB_PARENT],
            )
            payload = copy.call_args.kwargs["input"]
            self.assertEqual(
                recovery._read_tar(payload, {"cases.sqlite"}, 41812, 41812),
                {"cases.sqlite": b"sealed fixture"},
            )

    def test_inspection_staging_uses_service_read_identity_and_private_modes(self):
        sources = {
            p.name: p
            for p in (
                recovery.HERE / "case_recovery_native.py",
                recovery.ROOT / "tools/case_recovery_snapshot.py",
            )
        }

        def checksum(argv, **_kwargs):
            self.assertEqual(argv[:5], ["docker", "exec", "--user", "splunk", "a" * 64])
            source = sources[Path(argv[-1]).name]
            return hashlib.sha256(source.read_bytes()).hexdigest() + "  file\n"

        with (
            patch.object(recovery, "target", return_value=("a" * 64, {})),
            patch.object(
                recovery.lab, "task_identity", return_value=recovery.TASKS["source"]
            ),
            patch.object(recovery.subprocess, "check_output", side_effect=checksum),
            patch.object(
                recovery.subprocess,
                "run",
                return_value=Mock(returncode=0, stdout=b"{}"),
            ) as run,
        ):
            self.assertEqual(recovery.native("identity"), {})
        commands = [call.args[0] for call in run.call_args_list]
        for name in sources:
            path = "/tmp/" + recovery.TASKS["source"][0] + "-inspection/" + name
            self.assertIn(
                [
                    "docker",
                    "exec",
                    "--user",
                    "root",
                    "a" * 64,
                    "chown",
                    "splunk:splunk",
                    path,
                ],
                commands,
            )
            self.assertIn(
                ["docker", "exec", "--user", "root", "a" * 64, "chmod", "600", path],
                commands,
            )

    def test_exact_task_and_direct_lock_required_before_docker(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(recovery.lab, "verify_target") as verify,
        ):
            with self.assertRaises(recovery.RecoveryLabError):
                recovery.target(stopped=True)
            verify.assert_not_called()
        with (
            patch.dict(os.environ, {"ADM_LAB_CASE_RECOVERY": "1"}),
            patch.object(
                recovery.lab, "task_identity", return_value=recovery.TASKS["source"]
            ),
            patch.object(recovery.LabLock, "check_owned", return_value=False),
            patch.object(recovery.lab, "verify_target") as verify,
        ):
            with self.assertRaisesRegex(recovery.RecoveryLabError, "direct lock"):
                recovery.target(stopped=True)
            verify.assert_not_called()

    def test_running_container_refused_before_cold_operations(self):
        info = owned_info({"Running": True, "Status": "running", "Pid": 2})
        with (
            patch.dict(os.environ, {"ADM_LAB_CASE_RECOVERY": "1"}),
            patch.object(
                recovery.lab, "task_identity", return_value=recovery.TASKS["source"]
            ),
            patch.object(recovery.LabLock, "check_owned", return_value=True),
            patch.object(recovery.lab, "verify_target"),
            patch.object(recovery.lab.lab_tls, "read_container", return_value="a" * 64),
            patch.object(
                recovery.subprocess,
                "check_output",
                return_value=json.dumps([info]).encode(),
            ),
        ):
            with self.assertRaisesRegex(
                recovery.RecoveryLabError, "complete container stopped"
            ):
                recovery.target(stopped=True)

    def test_nested_or_extra_mount_refused_before_filesystem_access(self):
        info = owned_info({"Running": False, "Status": "exited", "Pid": 0})
        info["Mounts"].append(
            {"Destination": recovery.DB_PARENT, "Type": "bind", "Source": "/other"}
        )
        with (
            patch.dict(os.environ, {"ADM_LAB_CASE_RECOVERY": "1"}),
            patch.object(
                recovery.lab, "task_identity", return_value=recovery.TASKS["source"]
            ),
            patch.object(recovery.LabLock, "check_owned", return_value=True),
            patch.object(recovery.lab, "verify_target"),
            patch.object(recovery.lab.lab_tls, "read_container", return_value="a" * 64),
            patch.object(
                recovery.subprocess,
                "check_output",
                return_value=json.dumps([info]).encode(),
            ),
        ):
            with self.assertRaisesRegex(
                recovery.RecoveryLabError, "two owned volume mounts"
            ):
                recovery.target(stopped=True)

    def test_only_local_unix_socket(self):
        for endpoint in (
            "tcp://127.0.0.1:2375",
            "ssh://host",
            "http://localhost",
            "unix:///tmp/socket?x=1",
        ):
            with (
                self.subTest(endpoint=endpoint),
                self.assertRaises(recovery.RecoveryLabError),
            ):
                recovery._UnixHTTP(endpoint)

    def test_tar_rejects_link_traversal_and_wrong_owner(self):
        for name, kind in (
            ("cases.sqlite", "link"),
            ("../outside", b"x"),
            ("unexpected", b"x"),
        ):
            with self.subTest(name=name), self.assertRaises(recovery.RecoveryLabError):
                recovery._read_tar(
                    archive([(name, kind)]), {"cases.sqlite"}, 41812, 41812
                )
        with self.assertRaisesRegex(recovery.RecoveryLabError, "service-owned"):
            recovery._read_tar(
                archive([("cases.sqlite", b"x")]), {"cases.sqlite"}, 501, 501
            )
        self.assertEqual(
            recovery._read_tar(
                archive([("cases.sqlite", b"x")]), {"cases.sqlite"}, 41812, 41812
            ),
            {"cases.sqlite": b"x"},
        )

    def test_existing_target_and_changed_prepared_bytes_never_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            path.chmod(0o700)
            db = path / "cases.sqlite"
            db.write_bytes(b"owned fixture")
            db.chmod(0o600)
            summary = {
                "files": {
                    db.name: {
                        "size": db.stat().st_size,
                        "sha256": hashlib.sha256(db.read_bytes()).hexdigest(),
                    }
                }
            }
            with (
                patch.object(
                    recovery.lab, "task_identity", return_value=recovery.TASKS["target"]
                ),
                patch.object(recovery, "target", return_value=("a" * 64, {})),
                patch.object(recovery, "path_present", return_value=True),
                patch.object(recovery.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(recovery.RecoveryLabError, "existing"):
                    recovery.restore_prepared(path, summary, uid=41812, gid=41812)
                run.assert_not_called()
                db.write_bytes(b"changed bytes")
                with self.assertRaisesRegex(recovery.RecoveryLabError, "changed"):
                    recovery.restore_prepared(path, summary, uid=41812, gid=41812)
                run.assert_not_called()

    def test_404_means_absence_only_after_exact_container_recheck(self):
        response = Mock(status=404)
        response.getheader.return_value = None
        response.read.return_value = b""
        connection = Mock()
        connection.getresponse.return_value = response
        with (
            patch.object(
                recovery,
                "target",
                side_effect=[
                    ("a" * 64, {}),
                    recovery.RecoveryLabError("container replaced"),
                ],
            ),
            patch.object(
                recovery.lab, "local_docker_endpoint", return_value="unix:///tmp/socket"
            ),
            patch.object(recovery, "_UnixHTTP", return_value=connection),
        ):
            with self.assertRaisesRegex(recovery.RecoveryLabError, "replaced"):
                recovery.path_present()


if __name__ == "__main__":
    unittest.main()
