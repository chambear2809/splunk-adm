"""Identity lookup provenance and maintenance-preservation regressions."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

import lab


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class IdentityProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.token = "identity-provenance-" + uuid.uuid4().hex[:12]
        self.cluster = self.token + "-cluster"
        self.scope = self.token + "-scope"
        self.source = self.token + "-source"
        self.keys: list[tuple[str, str]] = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        # Every row created here carries this unique cluster.  A scoped query
        # cleanup avoids issuing one REST delete per row in the cap regression.
        for collection in ("adm_ip_identity", "adm_observer_scope"):
            query = urllib.parse.urlencode(
                {"query": json.dumps({"cluster": self.cluster})}
            )
            path = (
                "/servicesNS/nobody/splunk_adm/storage/collections/data/"
                + collection
                + "?"
                + query
            )
            try:
                with lab._mgmt("DELETE", path) as response:
                    response.read()
            except lab.LabError:
                pass

    def rest_batch_save(self, collection, rows):
        secrets = lab.read_secrets()
        auth = base64.b64encode(f"admin:{secrets['SPLUNK_PASSWORD']}".encode()).decode()
        path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            + collection
            + "/batch_save?output_mode=json"
        )
        # Splunk KV Store rejects batches over max_documents_per_batch_save
        # (normally 1000), so chunk large cap-regression fixtures while
        # registering each successful chunk for failure-safe cleanup.
        for start in range(0, len(rows), 1000):
            chunk = rows[start : start + 1000]
            request = urllib.request.Request(
                lab.MGMT + path,
                data=json.dumps(chunk).encode(),
                method="POST",
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(
                    request, context=lab._CTX, timeout=120
                ) as response:
                    response.read()
            except urllib.error.HTTPError as error:
                with error:
                    self.fail(
                        f"batch_save failed: HTTP {error.code}: {error.read(2000)!r}"
                    )
            self.keys.extend((collection, row["_key"]) for row in chunk)

    def identity_row(
        self,
        key,
        *,
        scope="default",
        verified=0,
        uid=None,
        ip=None,
        valid_end=4102444800,
    ):
        uid = uid or self.token + "-uid"
        ip = ip or "10.254.0.10"
        return {
            "_key": key,
            "ip": ip,
            "scope": scope,
            "scope_mapping_verified": verified,
            "entity_kind": "pod",
            "entity_id": uid,
            "entity_name": "identity-provenance",
            "cluster": self.cluster,
            "namespace": "provenance",
            "valid_from": 100,
            "valid_end": valid_end,
            "first_seen": 100,
            "last_seen": 100,
            "priority": 1,
            "source": "k8s_pods",
            "desc": json.dumps(
                {
                    "ip": ip,
                    "sc": scope,
                    "sm": verified,
                    "kind": "pod",
                    "id": uid,
                }
            ),
        }

    def test_public_readers_exclude_legacy_default_and_include_proven_rows(self):
        legacy_key = self.token + "-legacy"
        verified_key = self.token + "-verified"
        scoped_key = self.token + "-scoped"
        uid = self.token + "-same-uid"
        self.rest_batch_save(
            "adm_ip_identity",
            [
                self.identity_row(legacy_key, uid=uid),
                self.identity_row(verified_key, verified=1, uid=uid),
                self.identity_row(scoped_key, scope=self.scope, uid=uid),
            ],
        )
        ids = lab.search(
            f'| inputlookup adm_ip_identity where cluster="{self.cluster}" '
            "| stats values(_key) AS keys"
        )[0]["keys"]
        self.assertNotIn(legacy_key, ids)
        self.assertIn(verified_key, ids)
        self.assertIn(scoped_key, ids)

        paged = lab.search(
            f"| inputlookup adm_ip_identity start=0 max=1000 "
            f'| search cluster="{self.cluster}" | stats values(_key) AS keys'
        )[0]["keys"]
        self.assertNotIn(legacy_key, paged)
        self.assertIn(verified_key, paged)
        self.assertIn(scoped_key, paged)

        ip_lookup = lab.search(
            '| makeresults | eval ip="10.254.0.10", scope="default" '
            "| lookup adm_ip_identity ip scope OUTPUT _key | table _key"
        )
        self.assertEqual(ip_lookup[0]["_key"], verified_key)

        raw_ids = lab.search(
            f'| inputlookup adm_ip_identity_all where cluster="{self.cluster}" '
            "| stats values(_key) AS keys"
        )[0]["keys"]
        self.assertEqual(set(raw_ids), {legacy_key, verified_key, scoped_key})

        key_lookup = lab.search(
            f'| makeresults | eval _key="{legacy_key}" '
            "| lookup adm_ip_identity _key OUTPUT entity_id | table entity_id"
        )
        self.assertEqual(key_lookup[0].get("entity_id"), None)
        verified_lookup = lab.search(
            f'| makeresults | eval _key="{verified_key}" '
            "| lookup adm_ip_identity _key OUTPUT entity_id | table entity_id"
        )
        self.assertEqual(verified_lookup[0]["entity_id"], uid)

        service_alias = lab.search(
            f'| makeresults | eval entity_id="{uid}", cluster="{self.cluster}", '
            f'scope="default" | lookup adm_ip_identity_service entity_id cluster scope '
            "OUTPUT _key scope_mapping_verified | table _key scope_mapping_verified"
        )
        self.assertEqual(service_alias[0]["_key"], verified_key)
        self.assertEqual(str(service_alias[0]["scope_mapping_verified"]), "1")

    def test_public_readers_filter_legacy_rows_before_lookup_cap(self):
        legacy = [
            self.identity_row(
                f"{self.token}-legacy-cap-{index:04d}",
                uid=self.token + "-cap-uid",
                ip="10.254.0.30",
            )
            for index in range(1001)
        ]
        verified_key = self.token + "-verified-cap"
        verified = self.identity_row(
            verified_key,
            verified=1,
            uid=self.token + "-cap-uid",
            ip="10.254.0.30",
        )
        self.rest_batch_save("adm_ip_identity", legacy + [verified])

        public = lab.search(
            f'| inputlookup adm_ip_identity where cluster="{self.cluster}" '
            "| stats values(_key) AS keys"
        )[0]["keys"]
        self.assertEqual(
            set(public if isinstance(public, list) else [public]), {verified_key}
        )

        ip_lookup = lab.search(
            '| makeresults | eval ip="10.254.0.30", scope="default" '
            "| lookup adm_ip_identity ip scope OUTPUT _key "
            "| table _key"
        )
        self.assertEqual(ip_lookup[0]["_key"], verified_key)

        alias = lab.search(
            f'| makeresults | eval entity_id="{self.token}-cap-uid", '
            f'cluster="{self.cluster}", scope="default" '
            "| lookup adm_ip_identity_service entity_id cluster scope OUTPUT _key "
            "| table _key"
        )
        self.assertEqual(alias[0]["_key"], verified_key)

        paged = lab.search(
            f"| inputlookup adm_ip_identity start=0 max=1000 "
            f'| search cluster="{self.cluster}" | stats values(_key) AS keys'
        )[0]["keys"]
        self.assertEqual(
            set(paged if isinstance(paged, list) else [paged]), {verified_key}
        )

    def test_identity_build_adds_verified_default_without_overwriting_legacy_key(self):
        uid = self.token + "-pod"
        ip = "10.254.0.20"
        legacy_key = hashlib.sha256(
            f"k8s_pods|pod|{uid}|{ip}|default".encode()
        ).hexdigest()
        self.rest_batch_save(
            "adm_ip_identity", [self.identity_row(legacy_key, uid=uid, ip=ip)]
        )
        observer_key = self.token + "-observer"
        self.rest_batch_save(
            "adm_observer_scope",
            [
                {
                    "_key": observer_key,
                    "observer_kind": "cluster",
                    "observer": self.cluster,
                    "scope": "default",
                    "cluster": self.cluster,
                }
            ],
        )
        event_time = int(time.time()) - 300
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_time))
        expected_key = hashlib.sha256(
            f"k8s_pods|pod|{uid}|{ip}|default|scope-verified-v1".encode()
        ).hexdigest()
        self.keys.append(("adm_ip_identity", expected_key))
        event = {
            "time": event_time,
            "source": self.source,
            "host": "identity-provenance-node",
            "index": "k8s",
            "sourcetype": "kube:object:pods",
            "fields": {"k8s.cluster.name": self.cluster},
            "event": {
                "type": "ADDED",
                "object": {
                    "metadata": {
                        "uid": uid,
                        "name": "provenance-pod",
                        "namespace": "provenance",
                        "creationTimestamp": stamp,
                    },
                    "spec": {"hostNetwork": False},
                    "status": {
                        "phase": "Running",
                        "podIP": ip,
                        "podIPs": [{"ip": ip}],
                        "hostIP": "192.0.2.20",
                        "startTime": stamp,
                    },
                },
            },
        }
        lab._hec_post((json.dumps(event) + "\n").encode())
        for _ in range(30):
            if int(
                lab.search(
                    f'index=k8s source="{self.source}" | stats count', "0", "now"
                )[0]["count"]
            ):
                break
            time.sleep(1)
        rows = lab.search(
            "| `adm_identity_build`",
            event_time - 5,
            event_time + 5,
        )
        self.assertEqual(len(rows), 1)
        raw = lab.search(
            f'| inputlookup adm_ip_identity_all where cluster="{self.cluster}" '
            f'| search _key IN ("{legacy_key}","{expected_key}") '
            "| table _key scope scope_mapping_verified entity_id"
        )
        self.assertEqual({row["_key"] for row in raw}, {legacy_key, expected_key})
        proof = next(row for row in raw if row["_key"] == expected_key)
        self.assertEqual(proof["scope"], "default")
        self.assertEqual(str(proof["scope_mapping_verified"]), "1")

    def test_prune_full_rewrite_preserves_unexpired_hidden_legacy_row(self):
        legacy_key = self.token + "-legacy-prune"
        expired_key = self.token + "-expired-prune"
        self.rest_batch_save(
            "adm_ip_identity",
            [
                self.identity_row(legacy_key),
                self.identity_row(expired_key, ip="10.254.0.11", valid_end=1),
            ],
        )
        path = "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_prune_maintenance"
        original = lab._json("GET", path)["entry"][0]["content"].get("definition", "0")
        self.addCleanup(lab._json, "POST", path, {"definition": original})
        lab._json("POST", path, {"definition": "1"})
        result = lab.search("| `adm_identity_prune`")[0]
        self.assertEqual(str(result["complete"]), "1")
        retained = lab.search(
            f'| inputlookup adm_ip_identity_all where _key="{legacy_key}" | stats count'
        )
        self.assertEqual(retained[0]["count"], "1")
        expired = lab.search(
            f'| inputlookup adm_ip_identity_all where _key="{expired_key}" | stats count'
        )
        self.assertEqual(expired[0]["count"], "0")

    def test_identity_acl_metadata_keeps_public_readers_and_raw_alias_admin_only(self):
        from pathlib import Path

        metadata = (
            Path(__file__).resolve().parents[2]
            / "splunk_app/splunk_adm/metadata/default.meta"
        ).read_text()
        app_default = metadata.split("[]", 1)[1].split("\n[", 1)[0]
        public_access = "access = read : [ * ], write : [ admin, sc_admin ]"
        for stanza in ("adm_ip_identity", "adm_ip_identity_service"):
            marker = f"[transforms/{stanza}]"
            if marker in metadata:
                section = metadata.split(marker, 1)[1].split("\n[", 1)[0]
                effective = section if "access =" in section else app_default
            else:
                effective = app_default
            self.assertIn(public_access, effective)
        raw = metadata.split("[transforms/adm_ip_identity_all]", 1)[1].split("\n[", 1)[
            0
        ]
        self.assertIn(
            "access = read : [ admin, sc_admin ], write : [ admin, sc_admin ]", raw
        )


if __name__ == "__main__":
    unittest.main()
