"""Exercise production protocol lens SPL and KV Store ACLs in the Splunk lab."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_FIXTURES = ROOT / "fixtures/protocols"
NAMESPACE = "/servicesNS/nobody/splunk_adm"
COLLECTION = f"{NAMESPACE}/storage/collections/data/adm_protocol_profiles"

FRONTEND_SPL_RUNNER = """
import { createServer } from 'vite';
import { readFileSync } from 'node:fs';
const input = JSON.parse(readFileSync(0, 'utf8'));
const vite = await createServer({
  configFile: false, appType: 'custom', logLevel: 'silent',
  define: { __ADM_SPLUNK_BUILD__: 'false' },
  server: { middlewareMode: true },
});
try {
  if (input.kind === 'drops_nd') {
    const { buildDropsNdSearch } = await vite.ssrLoadModule('/frontend/src/protocols/lenses/drops/adapter.ts');
    console.log(JSON.stringify(buildDropsNdSearch(input.options)));
  } else if (input.kind === 'dns_hubble') {
    const { buildDnsOpsSearch } = await vite.ssrLoadModule('/frontend/src/protocols/lenses/dns_ops/adapter.ts');
    console.log(JSON.stringify(buildDnsOpsSearch(input.options)));
  } else {
    throw new Error(`Unsupported kind: ${input.kind}`);
  }
} finally {
  await vite.close();
}
"""


def _build_spl(kind: str, options: dict) -> str:
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", FRONTEND_SPL_RUNNER],
        cwd=ROOT,
        input=json.dumps({"kind": kind, "options": options}),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Frontend SPL builder failed ({completed.returncode}): {completed.stderr}"
        )
    return json.loads(completed.stdout)


def _poll_search(
    spl: str,
    earliest: int,
    latest: int,
    min_rows: int,
    timeout: float = 30.0,
) -> list[dict]:
    deadline = time.monotonic() + timeout
    rows: list[dict] = []
    while True:
        rows = lab.search(spl, earliest, latest)
        if len(rows) >= min_rows or time.monotonic() >= deadline:
            return rows
        time.sleep(1.5)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class ProtocolLensesRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        deadline = time.monotonic() + 90
        while True:
            try:
                with lab._mgmt("GET", COLLECTION):
                    return
            except lab.LabError as error:
                if (
                    "KV Store is initializing" not in str(error)
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(1)

    def setUp(self):
        self.token = uuid.uuid4().hex[:10]
        self.latest = int(time.time()) + 10
        self.earliest = self.latest - 300

    def test_drops_nd_brace_field_search_returns_only_drop_rows(self):
        """Confirm Splunk executes unquoted stats{}.dropPktCount>0 pre-head filter."""
        nd_host = f"nd-lab-{self.token}"
        fixture_lines = (
            (PROTOCOL_FIXTURES / "drops" / "nd_aci_drops.ndjson")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        envelopes: list[dict] = []
        offset = 0
        for line in fixture_lines:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("sourcetype") != "cisco:dc:nd:flows":
                continue
            event = dict(rec["event"])
            event["nd_host"] = nd_host
            envelopes.append(
                {
                    "time": self.earliest + 60 + offset,
                    "host": nd_host,
                    "source": "flows",
                    "sourcetype": "cisco:dc:nd:flows",
                    "index": "cisco_dc",
                    "event": event,
                }
            )
            offset += 10
        # Add a zero-drop ND flow row that MUST be filtered out before | head.
        envelopes.append(
            {
                "time": self.earliest + 100,
                "host": nd_host,
                "source": "flows",
                "sourcetype": "cisco:dc:nd:flows",
                "index": "cisco_dc",
                "event": {
                    "flowId": f"999000-{self.token}",
                    "ts": "2026-10-07T11:54:00.000Z",
                    "srcIp": "10.42.0.88",
                    "dstIp": "10.42.0.89",
                    "srcPort": 44300,
                    "dstPort": 443,
                    "protocolName": "TCP",
                    "stats": [
                        {
                            "nodeNames": ["leaf-101"],
                            "ingressVif": ["eth1/11"],
                            "egressVif": ["eth1/12"],
                            "ingressByteCount": 1500,
                            "egressByteCount": 1500,
                            "ingressPktCount": 10,
                            "egressPktCount": 10,
                            "dropPktCount": 0,
                            "dropReasons": [],
                        }
                    ],
                    "nd_host": nd_host,
                    "fabricName": "dc1-vxlan",
                },
            }
        )
        payload = ("\n".join(json.dumps(e) for e in envelopes) + "\n").encode("utf-8")
        lab._hec_post(payload)

        # Wait until all 3 ingested events (2 drop rows + 1 zero-drop row) are searchable
        # so the assertion below proves pre-head filtering rather than indexing lag.
        raw_check = (
            f'search index="cisco_dc" sourcetype="cisco:dc:nd:flows" nd_host="{nd_host}"'
            " | head 10 | table flowId"
        )
        ingested = _poll_search(raw_check, self.earliest, self.latest, min_rows=3)
        self.assertEqual(
            len(ingested),
            3,
            f"Expected all 3 synthetic ND flow events indexed, got {ingested!r}",
        )

        spl = _build_spl(
            "drops_nd",
            {
                "index": "cisco_dc",
                "filter": {"device": nd_host},
                "maxRows": 256,
            },
        )
        self.assertIn("stats{}.dropPktCount>0", spl)
        rows = _poll_search(spl, self.earliest, self.latest, min_rows=2)
        self.assertEqual(len(rows), 2, f"Expected 2 ND drop rows, got {rows!r}")
        src_ips = {row.get("srcIp") for row in rows}
        self.assertEqual(src_ips, {"10.42.0.20", "10.42.0.25"})
        self.assertNotIn("10.42.0.88", src_ips)

    def test_dns_ops_hubble_search_returns_l7_dns_fields(self):
        """Confirm production Hubble DNS SPL extracts flow.l7.dns.* fields in Splunk."""
        hubble_host = f"hubble-lab-{self.token}"
        fixture_lines = (
            (PROTOCOL_FIXTURES / "dns_ops" / "hubble_dns.ndjson")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        envelopes: list[dict] = []
        for idx, line in enumerate(fixture_lines):
            if not line.strip():
                continue
            rec = json.loads(line)
            event = dict(rec)
            event.pop("_time", None)
            event["host"] = hubble_host
            envelopes.append(
                {
                    "time": self.earliest + 40 + idx * 10,
                    "host": hubble_host,
                    "source": "hubble",
                    "sourcetype": "cilium:hubble:flow",
                    "index": "cilium_hubble",
                    "event": event,
                }
            )
        payload = ("\n".join(json.dumps(e) for e in envelopes) + "\n").encode("utf-8")
        lab._hec_post(payload)

        spl = _build_spl(
            "dns_hubble",
            {
                "index": "cilium_hubble",
                "sourcetype": "cilium:hubble:flow",
                "filter": {"device": hubble_host},
                "maxRows": 256,
            },
        )
        self.assertIn('sourcetype="cilium:hubble:flow"', spl)
        rows = _poll_search(spl, self.earliest, self.latest, min_rows=4)
        self.assertEqual(len(rows), 4, f"Expected 4 Hubble DNS rows, got {rows!r}")
        queries = {row.get("query") or row.get("flow.l7.dns.query") for row in rows}
        self.assertIn("orders.prod.svc.cluster.local.", queries)
        self.assertIn("legacy-db.corp.internal.", queries)
        self.assertIn("missing.prod.svc.cluster.local.", queries)

    def test_protocol_profiles_kvstore_acl_admin_write_viewer_read(self):
        """Confirm adm_protocol_profiles allows admin CRUD, adm_viewer read-only, and denies bare users."""
        doc_key = f"labcheck-{self.token}"
        doc = {
            "_key": doc_key,
            "version": 1,
            "profiles": [
                {
                    "id": f"tcp-{self.token}",
                    "source": "protocol_tcp_tls",
                    "lens": "tcp_tls",
                    "scope": "lab:dc1",
                    "index": "netflow",
                    "observer": "stream-01",
                    "validFrom": self.earliest - 3600,
                    "validUntil": self.latest + 3600,
                }
            ],
        }
        headers = {
            "Authorization": "Basic "
            + base64.b64encode(
                f"admin:{lab.read_secrets()['SPLUNK_PASSWORD']}".encode()
            ).decode(),
            "Content-Type": "application/json",
        }
        create_req = urllib.request.Request(
            f"{lab.MGMT}{COLLECTION}",
            data=json.dumps(doc).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        with lab.urlopen(create_req) as resp:
            self.assertIn(resp.status, (200, 201))

        viewer_user = f"adm_proto_viewer_{self.token}"
        bare_user = f"adm_proto_bare_{self.token}"
        password = f"LabPass!{secrets.token_hex(8)}"
        try:
            with lab._mgmt(
                "POST",
                "/services/authentication/users",
                {"name": viewer_user, "password": password, "roles": "adm_viewer"},
            ):
                pass
            with lab._mgmt(
                "POST",
                "/services/authentication/users",
                {"name": bare_user, "password": password, "roles": "user"},
            ):
                pass
            viewer_auth = {
                "Authorization": "Basic "
                + base64.b64encode(f"{viewer_user}:{password}".encode()).decode(),
                "Content-Type": "application/json",
            }
            bare_auth = {
                "Authorization": "Basic "
                + base64.b64encode(f"{bare_user}:{password}".encode()).decode(),
                "Content-Type": "application/json",
            }
            read_req = urllib.request.Request(
                f"{lab.MGMT}{COLLECTION}/{urllib.parse.quote(doc_key, safe='')}",
                method="GET",
                headers=viewer_auth,
            )
            with lab.urlopen(read_req) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(body.get("_key"), doc_key)

            write_req = urllib.request.Request(
                f"{lab.MGMT}{COLLECTION}/{urllib.parse.quote(doc_key, safe='')}",
                data=json.dumps(doc).encode("utf-8"),
                method="POST",
                headers=viewer_auth,
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                lab.urlopen(write_req)
            with ctx.exception:
                self.assertEqual(ctx.exception.code, 403)

            create_viewer_req = urllib.request.Request(
                f"{lab.MGMT}{COLLECTION}",
                data=json.dumps({**doc, "_key": f"denied-{self.token}"}).encode(
                    "utf-8"
                ),
                method="POST",
                headers=viewer_auth,
            )
            with self.assertRaises(urllib.error.HTTPError) as create_ctx:
                lab.urlopen(create_viewer_req)
            with create_ctx.exception:
                self.assertEqual(create_ctx.exception.code, 403)

            delete_viewer_req = urllib.request.Request(
                f"{lab.MGMT}{COLLECTION}/{urllib.parse.quote(doc_key, safe='')}",
                method="DELETE",
                headers=viewer_auth,
            )
            with self.assertRaises(urllib.error.HTTPError) as del_ctx:
                lab.urlopen(delete_viewer_req)
            with del_ctx.exception:
                self.assertEqual(del_ctx.exception.code, 403)

            bare_read_req = urllib.request.Request(
                f"{lab.MGMT}{COLLECTION}/{urllib.parse.quote(doc_key, safe='')}",
                method="GET",
                headers=bare_auth,
            )
            with self.assertRaises(urllib.error.HTTPError) as bare_ctx:
                lab.urlopen(bare_read_req)
            with bare_ctx.exception:
                self.assertIn(bare_ctx.exception.code, (403, 404))
        finally:
            try:
                del_req = urllib.request.Request(
                    f"{lab.MGMT}{COLLECTION}/{urllib.parse.quote(doc_key, safe='')}",
                    method="DELETE",
                    headers=headers,
                )
                with lab.urlopen(del_req):
                    pass
            except Exception:
                pass
            for account in (viewer_user, bare_user):
                try:
                    with lab._mgmt(
                        "DELETE",
                        f"/services/authentication/users/{urllib.parse.quote(account, safe='')}",
                    ):
                        pass
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
