"""Regressions for ACI action provenance across the Cisco TA and graph stages."""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import unittest
import uuid

import lab


def results(rows):
    return "| makeresults format=json data=" + json.dumps(json.dumps(rows))


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class AciPolicyActionTest(unittest.TestCase):
    def setUp(self):
        self.token = "aci-action-" + uuid.uuid4().hex[:12]
        self.apic = "aci-action-" + uuid.uuid4().hex[:12]
        self.keys: list[tuple[str, str]] = []
        deadline = time.monotonic() + 180
        while True:
            try:
                lab._json(
                    "GET",
                    "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_aci_policy?limit=1",
                )
                break
            except lab.LabError as error:
                if (
                    "HTTP 503" not in str(error)
                    or "initializ" not in str(error).lower()
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(1)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        # The builder derives keys from apic_host and DN; a scoped KV delete
        # removes all rows produced by this test without touching lab fixtures.
        query = urllib.parse.urlencode({"query": json.dumps({"apic_host": self.apic})})
        path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            "adm_aci_policy?" + query
        )
        try:
            with lab._mgmt("DELETE", path) as response:
                response.read()
        except lab.LabError as error:
            if "HTTP 404" not in str(error):
                raise
        for collection, key in reversed(self.keys):
            try:
                with lab._mgmt(
                    "DELETE",
                    "/servicesNS/nobody/splunk_adm/storage/collections/data/"
                    + collection
                    + "/"
                    + urllib.parse.quote(key, safe=""),
                ) as response:
                    response.read()
            except lab.LabError as error:
                if "HTTP 404" not in str(error):
                    raise

    def send_raw(self, rows):
        now = time.time()
        body = b"\n".join(
            json.dumps(
                {
                    "time": now,
                    "index": "cisco_dc",
                    "sourcetype": "cisco:dc:aci:class",
                    "source": self.token,
                    "event": row,
                }
            ).encode()
            for row in rows
        )
        lab._hec_post(body)
        for _ in range(60):
            indexed = lab.search(
                f'index=cisco_dc source="{self.token}" | stats count',
                "0",
                "now",
            )
            if indexed and int(indexed[0].get("count", 0)) == len(rows):
                return now
            time.sleep(1)
        self.fail("ACI action events were not indexed")

    def test_builder_preserves_raw_action_when_ta_rewrites_action(self):
        """Explicit raw deny/permit survive EVAL-action; absent is unknown."""
        prefix = "uni/tn-" + self.token
        rows = []
        for name, action in (("deny", "deny"), ("permit", "permit"), ("missing", None)):
            dn = prefix + "/brc-web/subj-s" + name + "/rssubjFiltAtt-f" + name
            fields = [
                'component="vzRsSubjFiltAtt"',
                f'dn="{dn}"',
                f'tDn="{prefix}/flt-{name}"',
                'tnVzFilterName="web"',
                'directives="log"',
                f'apic_host="{self.apic}"',
            ]
            if action is not None:
                fields.insert(3, f'action="{action}"')
            rows.append("\t".join(fields))
        escaped_dn = prefix + "/brc-web/subj-sescaped/rssubjFiltAtt-fescaped"
        rows.append(
            "\t".join(
                [
                    'component="vzRsSubjFiltAtt"',
                    f'dn="{escaped_dn}"',
                    f'tDn="{prefix}/flt-escaped"',
                    r"action=\"permit\"",
                    'tnVzFilterName="web"',
                    f'apic_host="{self.apic}"',
                ]
            )
        )
        conflict_dn = prefix + "/brc-web/subj-sconflict/rssubjFiltAtt-fconflict"
        rows.append(
            "\t".join(
                [
                    'component="vzRsSubjFiltAtt"',
                    f'dn="{conflict_dn}"',
                    f'tDn="{prefix}/flt-conflict"',
                    'action="permit"',
                    'action="deny"',
                    'tnVzFilterName="web"',
                    f'apic_host="{self.apic}"',
                ]
            )
        )
        deceptive_dn = prefix + "/brc-web/subj-sdeceptive/rssubjFiltAtt-fdeceptive"
        rows.append(
            "\t".join(
                [
                    'component="vzRsSubjFiltAtt"',
                    f'dn="{deceptive_dn}"',
                    f'tDn="{prefix}/flt-deceptive"',
                    'some_action="deny"',
                    'tnVzFilterName="web"',
                    f'apic_host="{self.apic}"',
                ]
            )
        )
        malformed_dn = prefix + "/brc-web/subj-smalformed/rssubjFiltAtt-fmalformed"
        rows.append(
            "\t".join(
                [
                    'component="vzRsSubjFiltAtt"',
                    f'dn="{malformed_dn}"',
                    f'tDn="{prefix}/flt-malformed"',
                    'action="drop"',
                    'tnVzFilterName="web"',
                    f'apic_host="{self.apic}"',
                ]
            )
        )
        for name, action_field in (
            ("empty", 'action=""'),
            ("unquoted", "action=permit"),
            ("junk", 'action="permit"junk'),
            ("quoted-text", 'description="action=\\"deny\\""'),
            ("duplicate-empty", 'action="permit"\taction=""'),
            ("duplicate-unquoted", 'action="permit"\taction=deny'),
            ("mismatched-escape", r'action=\"permit"'),
        ):
            dn = prefix + "/brc-web/subj-s" + name + "/rssubjFiltAtt-f" + name
            rows.append(
                "\t".join(
                    [
                        'component="vzRsSubjFiltAtt"',
                        f'dn="{dn}"',
                        f'tDn="{prefix}/flt-{name}"',
                        action_field,
                        'tnVzFilterName="web"',
                        f'apic_host="{self.apic}"',
                    ]
                )
            )
        now = self.send_raw(rows)
        lab.search("`adm_aci_policy_build`", now - 5, now + 5)
        got = lab.search(
            f'| inputlookup adm_aci_policy where apic_host="{self.apic}" '
            "| search object_kind=filtatt | table dn action action_verified"
        )
        actions = {
            row["dn"].split("/rssubjFiltAtt-f", 1)[1]: row.get("action") for row in got
        }
        verified = {
            row["dn"].split("/rssubjFiltAtt-f", 1)[1]: row.get("action_verified")
            for row in got
        }
        self.assertEqual(actions.get("deny"), "deny")
        self.assertEqual(actions.get("permit"), "permit")
        self.assertEqual(actions.get("missing"), "unknown")
        self.assertEqual(actions.get("malformed"), "unknown")
        self.assertEqual(actions.get("escaped"), "permit")
        self.assertEqual(actions.get("conflict"), "unknown")
        self.assertEqual(actions.get("deceptive"), "unknown")
        for name in (
            "empty",
            "unquoted",
            "junk",
            "quoted-text",
            "duplicate-empty",
            "duplicate-unquoted",
            "mismatched-escape",
        ):
            self.assertEqual(actions.get(name), "unknown")
        self.assertEqual(verified.get("deny"), "1")
        self.assertEqual(verified.get("permit"), "1")
        self.assertEqual(verified.get("escaped"), "1")
        for name in (
            "missing",
            "malformed",
            "conflict",
            "deceptive",
            "empty",
            "unquoted",
            "junk",
            "quoted-text",
            "duplicate-empty",
            "duplicate-unquoted",
            "mismatched-escape",
        ):
            self.assertEqual(verified.get(name), "0")

    def seed(self, collection, rows):
        for index, row in enumerate(rows):
            row.setdefault("_key", self.token + "-" + str(index))
        self.keys.extend((collection, row["_key"]) for row in rows)
        lab.search(
            results(rows) + " | outputlookup append=true key_field=_key " + collection
        )

    def test_graph_refuses_unverified_legacy_permit_as_confident_intent(self):
        prefix = "uni/tn-" + self.token
        contract = prefix + "/brc-web"
        filt = prefix + "/flt-web"
        self.seed(
            "adm_observer_scope",
            [{"observer_kind": "apic", "observer": self.apic, "scope": self.token}],
        )
        rows = [
            {
                "object_kind": "cons",
                "class_dn": prefix + "/ap-app/epg-client",
                "contract_dn": contract,
            },
            {
                "object_kind": "prov",
                "class_dn": prefix + "/ap-app/epg-server",
                "contract_dn": contract,
            },
            {
                "object_kind": "filtatt",
                "contract_dn": contract,
                "subject": "web",
                "filter_dn": filt,
                "action": "permit",
            },
            {
                "object_kind": "entry",
                "filter_dn": filt,
                "prot": "tcp",
                "d_from": "443",
                "d_to": "443",
                "ether_t": "ip",
            },
            {"object_kind": "contract", "dn": contract, "contract_scope": "tenant"},
        ]
        for index, row in enumerate(rows):
            row.update(
                apic_host=self.apic, first_seen=900, last_seen=1500, tenant=self.token
            )
            row.setdefault("dn", prefix + "/object-" + str(index))
        self.seed("adm_aci_policy", rows)
        edge = {
            "id": self.token,
            "adm_row": "edge",
            "relationship": "communicates_with",
            "transport": "tcp",
            "server_port": 443,
            "adm_c_aciepg": prefix + "/ap-app/epg-client",
            "adm_s_aciepg": prefix + "/ap-app/epg-server",
            "adm_src_node": json.dumps(
                {
                    "kind": "endpoint",
                    "endpoint_kind": "vm",
                    "addr": "10.253.1.1",
                    "attr_scope": self.token,
                }
            ),
            "adm_dst_node": json.dumps(
                {
                    "kind": "endpoint",
                    "endpoint_kind": "vm",
                    "addr": "10.253.1.2",
                    "attr_scope": self.token,
                }
            ),
        }
        got = lab.search(
            results([edge])
            + f' | `adm_graph_contracts("svc", "prod", "{self.token}", "boundary")`'
            + " | table contract_basis contract",
            1000,
            2000,
        )
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].get("contract_basis"), "not_evaluated")
        self.assertFalse(got[0].get("contract"))
