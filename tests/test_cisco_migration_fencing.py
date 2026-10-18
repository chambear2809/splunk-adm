"""Local controller fencing: verified target identity, no distributed claim."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.cisco_contract_migration import Journal, Migration, Refused, main


class IdentityApi:
    def __init__(self, guid="same-target", uri="https://localhost:8089"):
        self.guid, self.uri = guid, uri

    def request(self, method, path, **kwargs):
        if method != "GET" or path != "/services/server/info":
            raise AssertionError("fencing must not mutate or read unrelated state")
        return {"entry": [{"content": {"guid": self.guid}}]}


class MigrationLocalFencingTest(unittest.TestCase):
    def test_process_with_different_journal_same_guid_and_uri_alias_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migration = Migration(
                IdentityApi(),
                Journal(root / "one/journal.json"),
                qualifier=lambda: None,
            )
            child = """
import sys
from pathlib import Path
from tools.cisco_contract_migration import Journal, Migration, Refused
class Api:
    uri="https://127.0.0.1:8089"
    def request(self,*args,**kwargs):
        return {"entry":[{"content":{"guid":"same-target"}}]}
try:
    with Migration(Api(),Journal(Path(sys.argv[1])),qualifier=lambda:None).operation_locked(lock_directory=Path(sys.argv[2])):
        raise SystemExit(9)
except Refused:
    raise SystemExit(2)
"""
            with migration.operation_locked(lock_directory=root / "locks"):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        child,
                        str(root / "two/journal.json"),
                        str(root / "locks"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((root / "two/journal.json").exists())
            # Releasing the controller lock allows a different journal to run.
            with Migration(
                IdentityApi(),
                Journal(root / "two/journal.json"),
                qualifier=lambda: None,
            ).operation_locked(lock_directory=root / "locks"):
                pass

    def test_different_targets_can_be_fenced_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            one = Migration(
                IdentityApi("one"), Journal(root / "one.json"), qualifier=lambda: None
            )
            two = Migration(
                IdentityApi("two"), Journal(root / "two.json"), qualifier=lambda: None
            )
            with (
                one.operation_locked(lock_directory=root / "locks"),
                two.operation_locked(lock_directory=root / "locks"),
            ):
                pass

    def test_missing_guid_and_unsafe_directory_or_lock_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migration = Migration(
                IdentityApi(""), Journal(root / "j.json"), qualifier=lambda: None
            )
            with self.assertRaisesRegex(Refused, "GUID"):
                with migration.operation_locked(lock_directory=root / "locks"):
                    pass
            migration.api = IdentityApi()
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            with self.assertRaises(Refused):
                with migration.operation_locked(lock_directory=unsafe):
                    pass
            target = root / "target"
            target.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(Refused):
                with migration.operation_locked(lock_directory=link):
                    pass
            lock = Journal(root / "plain.json")
            lock.lock_path.write_text("")
            lock.lock_path.chmod(0o644)
            with self.assertRaises(Refused):
                with lock.locked(blocking=False):
                    pass

    def test_status_uses_atomic_journal_read_without_credentials_or_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "j.json"
            Journal(path).write({"schema": 2, "phase": "cutover_in_progress"})
            output = io.StringIO()
            with (
                patch(
                    "tools.cisco_contract_migration._api_from_stdin",
                    side_effect=AssertionError("network/auth must stay unused"),
                ),
                patch.object(
                    Journal,
                    "locked",
                    side_effect=AssertionError("status must not wait"),
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(main(["--journal", str(path), "status"]), 0)
            self.assertEqual(
                json.loads(output.getvalue())["phase"], "cutover_in_progress"
            )

    def test_finalizing_writer_does_not_count_as_drained_or_inactive(self):
        migration = Migration(
            IdentityApi(),
            Journal(Path("unused")),
            qualifier=lambda: None,
            sleep=lambda _: None,
        )
        active = {
            "name": "writer",
            "content": {
                "sid": "writer",
                "label": "ADM - Conversation rollup",
                "dispatchState": "FINALIZING",
                "isDone": True,
            },
        }
        finished = {
            "name": "writer",
            "content": {
                "sid": "writer",
                "label": "ADM - Conversation rollup",
                "dispatchState": "DONE",
                "isDone": True,
            },
        }
        journal = {"cutover": {}}
        with (
            patch.object(migration, "_entries", side_effect=[[active], [finished]]),
            patch.object(migration, "_write_journal") as write,
        ):
            migration._drain_legacy_writer(journal, timeout=2)
            write.assert_called_once()
        active["content"]["label"] = "ADM - Conversation rollup v2"
        with patch.object(migration, "_entries", return_value=[active]):
            with self.assertRaisesRegex(Refused, "competing staged"):
                migration._assert_no_competing_staged_jobs({"jobs": []})

    def test_capped_short_collection_page_cannot_masquerade_as_complete(self):
        from urllib.parse import parse_qs, urlsplit

        class CappedApi:
            def request(self, method, path, **kwargs):
                params = parse_qs(urlsplit(path).query)
                self_sort = params.get("sort")
                if self_sort != ["_key:1"]:
                    raise AssertionError("paging must use documented stable key sort")
                offset = int(params["skip"][0])
                return [{"_key": str(i)} for i in range(offset, min(offset + 100, 200))]

        migration = Migration(
            CappedApi(), Journal(Path("unused")), qualifier=lambda: None
        )
        with self.assertRaisesRegex(Refused, "capped or changed"):
            migration._collection_rows("fixture")

    def test_completed_cutover_rechecks_live_mutations_before_success(self):
        migration = Migration(
            IdentityApi(), Journal(Path("unused")), qualifier=lambda: None
        )
        journal = {
            "phase": "cutover",
            "migration_id": "test",
            "cutover": {
                "mutations": [{"kind": "macro_definition", "before": "1", "after": "2"}]
            },
        }
        with (
            patch.object(migration, "_load", return_value=journal),
            patch.object(migration, "_assert_cutover_origin_compatible") as compatible,
            patch.object(migration, "_mutation_target", return_value={"value": "1"}),
        ):
            with self.assertRaisesRegex(Refused, "no longer fully active"):
                migration.cutover()
            compatible.assert_called_once_with(journal)


if __name__ == "__main__":
    unittest.main()
