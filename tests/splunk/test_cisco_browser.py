"""Native Splunk browser qualification for the two combined Cisco V2 paths."""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import unittest
import urllib.parse
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def _exact_client_ipv4(client: dict) -> str:
    """Select the single IPv4 observed in a graph client's address field."""
    addresses = client.get("addresses")
    if not isinstance(addresses, str):
        raise AssertionError("graph client addresses must be a delimited string")
    values = [value.strip() for value in addresses.split("|") if value.strip()]
    if len(values) != 1:
        raise AssertionError("graph client must expose exactly one address for Find")
    try:
        parsed = ipaddress.ip_address(values[0])
    except ValueError as error:
        raise AssertionError(
            "graph client address is not a valid IP address"
        ) from error
    if parsed.version != 4:
        raise AssertionError("network-client Find requires an IPv4 address or MAC")
    return str(parsed)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoV2BrowserTest(unittest.TestCase):
    """Exercise live V2 data through the packaged app as a search-only viewer."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "tools"))
        sys.path.insert(0, str(HERE))
        from lab_lock import LabLock
        from load_networking_lab import initialize
        import lab
        from test_cisco_permissions import CiscoV2RestrictedViewerTest

        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")

        cls.lab = lab
        cls.restricted = CiscoV2RestrictedViewerTest
        cls.initialized = initialize(
            ROOT / "dist/networking-path-tests",
            ROOT / "dist/networking-path-tests/initialization.json",
            regenerate=True,
        )
        cls.window = tuple(
            int(cls.initialized["window"][key]) for key in ("earliest", "latest")
        )
        try:
            CiscoV2RestrictedViewerTest.setUpClass()
        except Exception as setup_error:
            try:
                cls._cleanup_restricted_viewer()
            except Exception as cleanup_error:
                raise AssertionError(
                    "restricted viewer setup and cleanup both failed: "
                    f"setup={setup_error}; cleanup={cleanup_error}"
                ) from setup_error
            raise
        cls.addClassCleanup(cls._cleanup_restricted_viewer)

        cls.scenarios = cls._read_scenarios()
        cls._override_public_selectors()

    @classmethod
    def _cleanup_restricted_viewer(cls) -> None:
        helper = cls.restricted
        helper.doClassCleanups()
        failures = list(getattr(helper, "tearDown_exceptions", ()))
        helper.tearDown_exceptions = []
        if failures:
            details = "; ".join(
                f"{failure[0].__name__}: {failure[1]}" for failure in failures
            )
            raise AssertionError(
                f"restricted viewer cleanup failed: {details}"
            ) from failures[0][1]

    @classmethod
    def _read_scenarios(cls) -> list[dict]:
        scenarios = []
        for label, cluster, scope, mac, prefix, basis in (
            (
                "Catalyst wired to ACI",
                "cilium-aci-east",
                "campus-aci",
                "02:61:00:00:00:20",
                "catalyst:",
                "catalyst_client_snapshot",
            ),
            (
                "Meraki wireless to NXOS",
                "cilium-nxos-west",
                "meraki-nxos",
                "02:71:00:00:00:20",
                "meraki:",
                "meraki_association_flow",
            ),
        ):
            graph = cls.lab.search(
                f'| search `adm_graph_v2("checkout","demo","{cluster}","shop")`',
                *cls.window,
            )
            metas = [row for row in graph if row.get("row_type") == "meta"]
            nodes = [row for row in graph if row.get("row_type") == "node"]
            edges = [row for row in graph if row.get("row_type") == "edge"]
            if len(metas) != 1 or str(metas[0].get("root_present")) != "1":
                raise AssertionError(f"{label}: admin V2 graph was incomplete")
            if metas[0].get("warnings"):
                raise AssertionError(f"{label}: admin V2 graph reported warnings")
            clients = [
                node
                for node in nodes
                if node.get("endpoint_kind") == "network_client"
                and node.get("attr_client_mac") == mac
            ]
            if len(clients) != 1:
                raise AssertionError(f"{label}: expected one scoped network client")
            client = clients[0]
            device_id = str(client.get("attr_attachment_device_id", ""))
            device_name = str(client.get("attr_attachment_device_name", ""))
            if not device_id.startswith(prefix) or not device_name:
                raise AssertionError(
                    f"{label}: attachment identity was not source-qualified"
                )
            if client.get("attr_attachment_basis") != basis:
                raise AssertionError(f"{label}: unexpected attachment evidence basis")

            topology = cls.lab.search("| search `adm_topology_v2`", *cls.window)
            devices = [
                row
                for row in topology
                if row.get("row_type") == "device"
                and row.get("device_id") == device_id
                and row.get("scope") == scope
                and row.get("cluster") == cluster
            ]
            if len(devices) != 1:
                raise AssertionError(
                    f"{label}: exact attachment inventory device was absent"
                )

            client_ip = _exact_client_ipv4(client)
            find_rows = cls.lab.search(
                f'| `adm_find_network_client("{client_ip}")`', *cls.window
            )
            client_rows = [
                row
                for row in find_rows
                if row.get("row_type") == "network_client"
                and row.get("client_mac") == mac
                and row.get("cluster") == cluster
                and row.get("scope") == scope
            ]
            if not client_rows:
                raise AssertionError(
                    f"{label}: live Find had no matching client evidence"
                )
            evidence = client_rows[0]
            source = str(evidence.get("source", ""))
            authority = str(evidence.get("source_authority", ""))
            if not source or not authority:
                raise AssertionError(f"{label}: Find evidence lacks source authority")
            find_basis = str(evidence.get("attachment_basis", ""))
            if not find_basis:
                raise AssertionError(f"{label}: Find evidence lacks attachment basis")

            scenario = {
                "label": label,
                "cluster": cluster,
                "scope": scope,
                "nodes": len(nodes),
                "edges": len(edges),
                "clientMac": mac,
                "clientIp": client_ip,
                "attachmentDeviceId": device_id,
                "attachmentDeviceName": device_name,
                "attachmentBasis": basis,
                "source": source,
                "sourceLabel": str(evidence.get("access_platform") or source),
                "sourceAuthority": authority,
                "findAttachmentBasis": find_basis,
                "earliest": str(cls.window[0]),
                "latest": str(cls.window[1]),
            }
            if cluster == "cilium-nxos-west":
                ssid_number = str(client.get("attr_ssid_number", ""))
                if not ssid_number or client.get("attr_ssid_name"):
                    raise AssertionError(
                        "Meraki association must expose only observed SSID number"
                    )
                scenario["ssidNumber"] = ssid_number
            scenarios.append(scenario)
        return scenarios

    @classmethod
    def _override_public_selectors(cls) -> None:
        overrides = {
            "adm_graph(4)": '`adm_graph_v2("$service$","$environment$","$cluster$","$namespace$")`',
            "adm_topology": "`adm_topology_v2`",
            "adm_find(1)": '`adm_find_v2("$query$")`',
        }
        originals: dict[str, dict] = {}
        for name in overrides:
            content = cls._macro_content(name)
            originals[name] = {
                "definition": content["definition"],
                "args": content.get("args"),
            }
            if name.endswith(")") and not cls._macro_args(originals[name]["args"]):
                raise AssertionError(f"parameterized macro {name} has no declared args")
        cls.addClassCleanup(cls._restore_public_selectors, originals)

        expected = {
            name: {"definition": definition, "args": originals[name]["args"]}
            for name, definition in overrides.items()
        }
        cls._write_and_verify_macro_states(expected)

    @classmethod
    def _macro_path(cls, name: str) -> str:
        return "/servicesNS/nobody/splunk_adm/admin/macros/" + urllib.parse.quote(
            name, safe=""
        )

    @classmethod
    def _macro_content(cls, name: str) -> dict:
        response = cls.lab._json("GET", cls._macro_path(name))
        return response["entry"][0]["content"]

    @staticmethod
    def _macro_args(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        if isinstance(value, (list, tuple)):
            return tuple(str(item).strip() for item in value if str(item).strip())
        return ()

    @classmethod
    def _write_and_verify_macro_states(cls, states: dict[str, dict]) -> None:
        failures = []
        for name, state in states.items():
            payload = {"definition": state["definition"]}
            args = state.get("args")
            if args is not None:
                payload["args"] = (
                    args if isinstance(args, str) else ", ".join(cls._macro_args(args))
                )
            try:
                cls.lab._json("POST", cls._macro_path(name), payload)
            except Exception as error:
                failures.append(f"update {name}: {error}")
        try:
            cls.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")
        except Exception as error:
            failures.append(f"reload macro definitions: {error}")
        for name, expected in states.items():
            try:
                actual = cls._macro_content(name)
                if actual.get("definition") != expected["definition"]:
                    failures.append(f"verify {name}: definition did not match")
                if cls._macro_args(actual.get("args")) != cls._macro_args(
                    expected.get("args")
                ):
                    failures.append(f"verify {name}: declared args did not match")
            except Exception as error:
                failures.append(f"verify {name}: {error}")
        if failures:
            raise AssertionError("; ".join(failures))

    @classmethod
    def _restore_public_selectors(cls, originals: dict[str, dict]) -> None:
        cls._write_and_verify_macro_states(originals)

    def _readline(self, process: subprocess.Popen[str], timeout: float = 1200) -> dict:
        ready = selectors.DefaultSelector()
        try:
            ready.register(process.stdout, selectors.EVENT_READ)
            if not ready.select(timeout):
                self.fail("Cisco browser produced no evidence before timeout")
            line = process.stdout.readline()
        finally:
            ready.close()
        self.assertTrue(line, "Cisco browser exited without evidence")
        try:
            return json.loads(line)
        except json.JSONDecodeError as error:
            self.fail(f"Cisco browser returned non-JSON evidence: {error}")

    def test_native_viewer_uses_both_live_v2_paths_without_demo_fallback(self) -> None:
        browser_env = dict(
            os.environ,
            ADM_VIEWER_USER=self.restricted.username,
            ADM_VIEWER_PASS=self.restricted.password,
        )
        process = subprocess.Popen(
            ["node", str(HERE / "cisco-browser.mjs"), json.dumps(self.scenarios)],
            cwd=ROOT,
            env=browser_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            login = self._readline(process, timeout=60)
            self.assertEqual(login.get("login"), "ok", login)
            process.stdin.write("run\n")
            process.stdin.flush()
            evidence = self._readline(process)
            self.assertNotIn("error", evidence, evidence)
            self.assertEqual(evidence.get("demoRequests"), 0, evidence)
            self.assertEqual(len(evidence.get("scenarios", [])), 2, evidence)
            for scenario in evidence["scenarios"]:
                self.assertEqual(
                    scenario.get("nodeCount"), scenario.get("expectedNodes"), evidence
                )
                self.assertEqual(
                    scenario.get("edgeCount"), scenario.get("expectedEdges"), evidence
                )
                self.assertEqual(
                    scenario.get("reload", {}).get("nodeCount"),
                    scenario.get("expectedNodes"),
                    evidence,
                )
                self.assertEqual(
                    scenario.get("reload", {}).get("edgeCount"),
                    scenario.get("expectedEdges"),
                    evidence,
                )
                self.assertTrue(scenario.get("attachmentDevice"), evidence)
                self.assertTrue(scenario.get("liveFind"), evidence)
            meraki = next(
                item
                for item in evidence["scenarios"]
                if item["cluster"] == "cilium-nxos-west"
            )
            self.assertTrue(meraki.get("associationBasis"), evidence)
            self.assertTrue(meraki.get("ssidNumber"), evidence)
            self.assertFalse(meraki.get("inventedSsidName"), evidence)
        finally:
            try:
                process.stdin.write("quit\n")
                process.stdin.flush()
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass
        self.assertEqual(process.returncode, 0, "Cisco browser exited unsuccessfully")
        summary = {
            "captured_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "synthetic_local_scope": True,
            "demoRequests": evidence["demoRequests"],
            "scenarios": evidence["scenarios"],
        }
        evidence_path = ROOT / "dist" / "cisco-native-browser-evidence.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
