"""Offline graph-address extraction regressions for the native Cisco browser test."""

import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch
import urllib.parse

from tests.splunk.test_cisco_browser import _exact_client_ipv4

ROOT = Path(__file__).resolve().parents[1]


def browser_test_class():
    from tests.splunk.test_cisco_browser import CiscoV2BrowserTest

    return CiscoV2BrowserTest


def macro_arg_count(value):
    if isinstance(value, str):
        return len([item for item in value.split(",") if item.strip()])
    if isinstance(value, (list, tuple)):
        return len([item for item in value if str(item).strip()])
    return 0


class CiscoBrowserGraphAddressTests(unittest.TestCase):
    def test_committed_cisco_graph_captures_provide_the_exact_find_addresses(self):
        for capture, mac, expected_ip, device_prefix, basis in (
            (
                "demo-networking-aci.json",
                "02:61:00:00:00:20",
                "10.61.0.20",
                "catalyst:",
                "catalyst_client_snapshot",
            ),
            (
                "demo-networking-nxos.json",
                "02:71:00:00:00:20",
                "10.71.0.20",
                "meraki:",
                "meraki_association_flow",
            ),
        ):
            with self.subTest(capture=capture):
                payload = json.loads(
                    (ROOT / "fixtures" / capture).read_text(encoding="utf-8")
                )
                clients = [
                    row
                    for row in payload["rows"]
                    if row.get("row_type") == "node"
                    and row.get("endpoint_kind") == "network_client"
                    and row.get("attr_client_mac") == mac
                ]
                self.assertEqual(len(clients), 1)
                client = clients[0]
                self.assertEqual(_exact_client_ipv4(client), expected_ip)
                self.assertTrue(
                    str(client.get("attr_attachment_device_id", "")).startswith(
                        device_prefix
                    )
                )
                self.assertEqual(client.get("attr_attachment_basis"), basis)

    def test_find_address_selection_rejects_missing_ambiguous_and_non_ipv4_values(self):
        for addresses in (None, "", "10.0.0.1|10.0.0.2", "2001:db8::1"):
            with self.subTest(addresses=addresses), self.assertRaises(AssertionError):
                _exact_client_ipv4({"addresses": addresses})


class FakeMacroLab:
    def __init__(self, macros, fail_updates=(), fail_reads=(), ignore_updates=False):
        self.macros = {name: dict(state) for name, state in macros.items()}
        self.fail_updates = set(fail_updates)
        self.fail_reads = set(fail_reads)
        self.ignore_updates = ignore_updates
        self.posts = []
        self.reads = []
        self.reloads = 0

    def _json(self, method, path, data=None):
        if path.endswith("/admin/macros/_reload"):
            self.reloads += 1
            return {}
        name = urllib.parse.unquote(path.rsplit("/", 1)[-1])
        if method == "POST":
            self.posts.append((name, dict(data or {})))
            match = re.search(r"\((\d+)\)$", name)
            if match and macro_arg_count(data.get("args")) != int(match.group(1)):
                raise RuntimeError(
                    "HTTP 400: number of provided macro args does not match name"
                )
            if name in self.fail_updates:
                raise RuntimeError(f"simulated update failure for {name}")
            if not self.ignore_updates:
                self.macros[name].update(data or {})
                if "args" in self.macros[name]:
                    value = self.macros[name]["args"]
                    if isinstance(value, str):
                        self.macros[name]["args"] = value
                    elif isinstance(value, list):
                        self.macros[name]["args"] = ", ".join(value)
            return {}
        if method == "GET":
            self.reads.append(name)
            if name in self.fail_reads:
                raise RuntimeError(f"simulated readback failure for {name}")
            return {"entry": [{"content": dict(self.macros[name])}]}
        raise AssertionError(f"unexpected REST method {method}")


class CiscoBrowserMacroOverrideTests(unittest.TestCase):
    def test_parameterized_macro_arguments_survive_override_and_restore(self):
        for original_args, expected_wire_args in (
            (
                "service, environment, cluster, namespace",
                "service, environment, cluster, namespace",
            ),
            (
                ["service", "environment", "cluster", "namespace"],
                "service, environment, cluster, namespace",
            ),
        ):
            with self.subTest(original_args=original_args):
                macro = "adm_graph(4)"
                original = {
                    "definition": "original graph definition",
                    "args": original_args,
                }
                fake_lab = FakeMacroLab({macro: original})
                browser_test = browser_test_class()
                with patch.object(browser_test, "lab", fake_lab, create=True):
                    browser_test._write_and_verify_macro_states(
                        {
                            macro: {
                                "definition": "v2 graph definition",
                                "args": original_args,
                            }
                        }
                    )
                    browser_test._restore_public_selectors({macro: original})

                self.assertEqual(len(fake_lab.posts), 2)
                self.assertEqual(
                    [payload["args"] for _, payload in fake_lab.posts],
                    [expected_wire_args, expected_wire_args],
                )
                self.assertEqual(
                    fake_lab.macros[macro]["definition"], original["definition"]
                )
                self.assertEqual(fake_lab.reloads, 2)

    def test_macro_override_refuses_definition_drift_on_readback(self):
        macro = "adm_graph(4)"
        fake_lab = FakeMacroLab(
            {
                macro: {
                    "definition": "original graph definition",
                    "args": "service, environment, cluster, namespace",
                }
            },
            ignore_updates=True,
        )
        browser_test = browser_test_class()
        with patch.object(browser_test, "lab", fake_lab, create=True):
            with self.assertRaisesRegex(AssertionError, "definition did not match"):
                browser_test._write_and_verify_macro_states(
                    {
                        macro: {
                            "definition": "v2 graph definition",
                            "args": "service, environment, cluster, namespace",
                        }
                    }
                )
        self.assertEqual(fake_lab.reloads, 1)
        self.assertEqual(fake_lab.reads, [macro])

    def test_cleanup_attempts_all_macro_updates_and_readbacks_after_failures(self):
        graph_macro = "adm_graph(4)"
        find_macro = "adm_find(1)"
        originals = {
            graph_macro: {
                "definition": "original graph definition",
                "args": "service, environment, cluster, namespace",
            },
            find_macro: {"definition": "original Find definition", "args": "query"},
        }
        fake_lab = FakeMacroLab(
            {
                graph_macro: {
                    "definition": "modified graph definition",
                    "args": originals[graph_macro]["args"],
                },
                find_macro: {"definition": "modified Find definition", "args": "query"},
            },
            fail_updates={graph_macro},
            fail_reads={graph_macro},
        )
        browser_test = browser_test_class()
        with patch.object(browser_test, "lab", fake_lab, create=True):
            with self.assertRaises(AssertionError) as caught:
                browser_test._restore_public_selectors(originals)
        self.assertIn("simulated update failure", str(caught.exception))
        self.assertIn("simulated readback failure", str(caught.exception))
        self.assertEqual(
            [name for name, _ in fake_lab.posts], [graph_macro, find_macro]
        )
        self.assertEqual(fake_lab.reloads, 1)
        self.assertEqual(fake_lab.reads, [graph_macro, find_macro])
        self.assertEqual(
            fake_lab.macros[find_macro]["definition"],
            originals[find_macro]["definition"],
        )


if __name__ == "__main__":
    unittest.main()
