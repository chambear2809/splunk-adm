"""Prune safety checks against the disposable Splunk lab.

These tests exercise the default maintenance gate while a prune's collection
snapshot is being taken.  The injected row models a builder upsert arriving
between the paged read and the rewrite; a safe default must leave it intact.
"""

from __future__ import annotations

import os
import subprocess
import unittest
import uuid
import urllib.parse

import lab


COLLECTIONS = {
    "adm_ip_identity": ("adm_identity_prune", "valid_end"),
    "adm_service_workload": ("adm_service_binding_prune", "last_seen"),
    "adm_service_backends": ("adm_service_backends_prune", "valid_to"),
    "adm_service_routes": ("adm_service_routes_prune", "valid_to"),
    "adm_aci_policy": ("adm_aci_policy_prune", "last_seen"),
}
CONTAINER = "adm-splunk-lab"
APP_DIR = "/opt/splunk/etc/apps/splunk_adm"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class PruneRecoveryTest(unittest.TestCase):
    token = uuid.uuid4().hex[:12]

    @classmethod
    def setUpClass(cls):
        cls.backups: dict[str, tuple[str, int]] = {}

    @classmethod
    def set_macros(cls, overrides: dict[str, str]) -> None:
        text = "".join(
            f"[{name}]\ndefinition = {definition}\n\n"
            for name, definition in overrides.items()
        )
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "-u",
                "splunk",
                CONTAINER,
                "sh",
                "-c",
                f"mkdir -p {APP_DIR}/local && cat > {APP_DIR}/local/macros.conf",
            ],
            input=text.encode(),
            check=True,
        )
        lab._mgmt("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

    @classmethod
    def restore_macros(cls) -> None:
        subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "splunk",
                CONTAINER,
                "rm",
                "-f",
                f"{APP_DIR}/local/macros.conf",
            ],
            check=True,
        )
        lab._mgmt("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

    def backup(self, collection: str) -> tuple[str, int]:
        name = f"prune_recovery_{self.token}_{collection}.csv"
        lab.search(f"| inputlookup {collection} | outputlookup {name}")
        count = int(lab.search(f"| inputlookup {collection} | stats count")[0]["count"])
        return name, count

    def restore(self, collection: str, backup: str, count: int) -> None:
        # outputlookup does not clear a collection from an empty result.
        if count == 0:
            lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/"
                + urllib.parse.quote(collection, safe=""),
            )
        else:
            lab.search(f"| inputlookup {backup} | outputlookup {collection}")

    def injected_reader(self, collection: str, key: str, expiry_field: str) -> str:
        # The appendpipe executes after the complete snapshot is read and
        # before the prune's outputlookup rewrite.  The inserted row models a
        # builder upsert in precisely that lost-update window.
        return (
            "inputlookup $collection$ start=0 max=10000 | eval adm_page=1 "
            "| inputlookup append=true $collection$ start=1 max=10000 "
            "| eval adm_page=coalesce(adm_page, 0) "
            "| appendpipe [| stats count "
            f'| eval _key="{key}", {expiry_field}=now() '
            f"| fields _key {expiry_field} "
            "| outputlookup append=true key_field=_key $collection$ | where false()] "
            "| `adm_kv_complete`"
        )

    def test_default_gate_refuses_all_prunes_and_preserves_mid_snapshot_upsert(self):
        overrides = {}
        expected_keys = []
        try:
            for collection, (macro, expiry_field) in COLLECTIONS.items():
                backup, count = self.backup(collection)
                expected_keys.append((collection, backup, count))
                retained = f"prune-retained-{self.token}-{collection}"
                expired = f"prune-expired-{self.token}-{collection}"
                lab.search(
                    "| makeresults count=2 | streamstats count AS n "
                    f'| eval _key=if(n==1, "{retained}", "{expired}"), '
                    f"{expiry_field}=if(n==1, now(), 1) "
                    f"| fields _key {expiry_field} | outputlookup {collection}"
                )
                key = f"prune-recovery-{self.token}-{collection}"
                overrides["adm_kv_read_all(1)"] = self.injected_reader(
                    collection, key, expiry_field
                )
                self.set_macros(overrides)

                result = lab.search(f"| `{macro}`", "0", "now")[0]
                self.assertEqual(result.get("complete"), "1", result)
                self.assertEqual(result.get("rows_expired"), "1", result)
                self.assertEqual(result.get("rows_pruned"), "0", result)
                self.assertIn(
                    "Maintenance mode", str(result.get("warnings", "")), result
                )
                rows = lab.search(
                    f'| inputlookup {collection} where _key="{key}" | stats count'
                )
                self.assertEqual(rows[0].get("count"), "1", (collection, result))
                self.assertEqual(
                    int(
                        lab.search(f"| inputlookup {collection} | stats count")[0][
                            "count"
                        ]
                    ),
                    3,
                    (collection, result),
                )
        finally:
            self.restore_macros()
            for collection, backup, count in expected_keys:
                self.restore(collection, backup, count)


if __name__ == "__main__":
    unittest.main()
