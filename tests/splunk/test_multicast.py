"""Exercise the production multicast SPL against synthetic indexed events."""

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
FIXTURES = ROOT / "fixtures/multicast"
NAMESPACE = "/servicesNS/nobody/splunk_adm"
COLLECTION = f"{NAMESPACE}/storage/collections/data/adm_multicast_profiles"
FRONTEND_RUNNER = """
import { createServer } from 'vite';
import { readFileSync } from 'node:fs';
const input = JSON.parse(readFileSync(0, 'utf8'));
const vite = await createServer({
  configFile: false, appType: 'custom', logLevel: 'silent',
  define: { __ADM_SPLUNK_BUILD__: 'false' },
  server: { middlewareMode: true },
});
try {
  const { buildMulticastSearch, loadMulticastSource } = await vite.ssrLoadModule('/frontend/src/multicast/adapters.ts');
  if (input.summary || input.results) {
    const { buildGroupSummarySearch, loadGroupSummary } = await vite.ssrLoadModule('/frontend/src/multicast/groupSummary.ts');
    const { group, sender, ...window } = input.request;
    if (!input.results) {
      console.log(JSON.stringify(buildGroupSummarySearch(input.profile, window)));
    } else {
      const read = ({ search, rows }) => ({
        async search(request) {
          if (request.search !== search) throw new Error("Unexpected multicast search");
          return { rows, warnings: [], errors: [] };
        }
      });
      const signal = new AbortController().signal;
      const overview = await loadGroupSummary(read(input.results.overview), input.profile, window, signal);
      const detail = await loadMulticastSource(read(input.results.detail), input.profile, input.request, signal);
      console.log(JSON.stringify({ overview, detail }));
    }
  } else {
    const { buildForwardingSearch } = await vite.ssrLoadModule('/frontend/src/multicast/forwardingSource.ts');
    const build = input.profile.source === "multicast_nxos" ? buildForwardingSearch : buildMulticastSearch;
    console.log(JSON.stringify(build(input.profile, input.request)));
  }
} finally {
  await vite.close();
}
"""


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class MulticastRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Splunkd can accept searches before the KV Store finishes starting.
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
        self.candidates = json.loads((FIXTURES / "candidates.json").read_text())
        self.igmp, self.flow = json.loads((FIXTURES / "profiles.json").read_text())[
            "profiles"
        ]
        self.igmp["observer"] = f"atlas-multicast-{uuid.uuid4().hex[:12]}"
        self.flow["observer"] = f"192.0.2.{int(uuid.uuid4().hex[:6], 16) % 200 + 30}"
        self.latest = int(time.time()) - 1
        self.earliest = self.latest - 300
        self.request = {
            "version": 1,
            "scope": self.igmp["scope"],
            "group": "239.1.2.3",
            "earliest": self.earliest,
            "latest": self.latest,
        }

    def search(self, spl):
        return lab.search(spl, self.earliest, self.latest)

    def build_query(self, profile, **overrides):
        return self.frontend(profile, self.request | overrides)

    def frontend(self, profile, request, **options):
        command = subprocess.run(
            ["node", "--input-type=module", "-e", FRONTEND_RUNNER],
            cwd=ROOT,
            input=json.dumps({"profile": profile, "request": request, **options}),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(command.returncode, 0, command.stderr)
        return json.loads(command.stdout)

    def run_profile(self, profile, **overrides):
        rows = self.search(self.build_query(profile, **overrides))
        completion = [row for row in rows if row.get("kind") == "completion"]
        self.assertEqual(len(completion), 1)
        payloads = [
            json.loads(row["payload"]) for row in rows if row.get("kind") == "record"
        ]
        self.assertEqual(int(completion[0]["returned_count"]), len(payloads))
        return payloads, int(completion[0]["input_count"])

    def write(self, records, sourcetype):
        def hec_record(payload, timestamp):
            return json.dumps(
                {
                    "event": json.dumps(payload),
                    "time": timestamp,
                    "index": self.igmp["index"],
                    "sourcetype": sourcetype,
                    "host": self.igmp["observer"],
                }
            ).encode()

        lab._hec_post(
            b"\n".join(hec_record(payload, timestamp) for payload, timestamp in records)
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            rows = self.search(
                f'index=netflow host="{self.igmp["observer"]}" sourcetype="{sourcetype}" | stats count'
            )
            if rows and int(rows[0]["count"]) == len(records):
                return
            time.sleep(0.5)
        self.fail("Synthetic multicast records did not finish indexing.")

    def test_native_view_and_opt_in_configuration(self):
        view = lab._json("GET", f"{NAMESPACE}/data/ui/views/multicast")
        self.assertEqual(view["entry"][0]["name"], "multicast")
        with lab._mgmt("GET", COLLECTION) as response:
            self.assertEqual(json.loads(response.read()), [])

    def test_exact_igmp_group_and_interface_survive_unrelated_burst(self):
        report = self.candidates["igmpV3Flat"] | {"network_interface": "eth0"}
        v2 = self.candidates["igmpV2"] | {"network_interface": "eth0"}
        other_interface = report | {"network_interface": "eth1"}
        other_group = report | {
            "group_record_multicast_address": ["239.1.2.30", "239.1.2.4"]
        }
        self.write(
            [(report, self.earliest + 1), (v2, self.earliest + 2)]
            + [(other_interface, self.latest - 1)] * 257
            + [(other_group, self.latest - 1)] * 257,
            "stream:igmp",
        )
        payloads, count = self.run_profile(self.igmp)
        self.assertEqual(count, 2)
        decoded = next(payload for payload in payloads if payload["type"] == 34)
        for field in (
            "group_record_multicast_address",
            "group_record_type",
            "group_record_num_sources",
            "group_record_source_address",
        ):
            self.assertEqual(decoded[field], report[field])
        self.assertEqual(self.run_profile(self.igmp, group="239.1.2.99"), ([], 0))

    def test_netflow_search_respects_exporter_template_monitor_and_sender(self):
        flow = self.candidates["netflow"] | {"exporter_ip": self.flow["observer"]}
        records = [
            flow,
            flow | {"observation_domain_id": 2},
            flow | {"template_id": 257},
            flow | {"flow_dir": 1},
            flow | {"src_ip": "192.0.2.25"},
            flow | {"exporter_ip": "192.0.2.2"},
        ]
        self.write([(row, self.latest - 1) for row in records], "stream:netflow")
        payloads, count = self.run_profile(self.flow, sender=flow["src_ip"])
        self.assertEqual(count, 1)
        self.assertEqual(payloads[0]["bytes"], flow["bytes"])
        self.assertEqual(payloads[0]["packets"], flow["packets"])

    def test_a_negative_counter_is_not_hidden_by_the_group_sum(self):
        self.flow["observer"] = "198.18." + ".".join(map(str, os.urandom(2)))
        flow = self.candidates["netflow"] | {"exporter_ip": self.flow["observer"]}
        self.write(
            [
                (flow | {"bytes": 100, "packets": 10}, self.earliest + 1),
                (flow | {"bytes": -20, "packets": 2}, self.earliest + 2),
            ],
            "stream:netflow",
        )
        overview = self.frontend(self.flow, self.request, summary=True)
        detail = self.build_query(self.flow)
        overview_rows = self.search(overview)
        (group,) = [row for row in overview_rows if row["kind"] == "record"]
        self.assertIn(group.get("bytes"), (None, ""), group)
        result = self.frontend(
            self.flow,
            self.request,
            results={
                "overview": {"search": overview, "rows": overview_rows},
                "detail": {"search": detail, "rows": self.search(detail)},
            },
        )
        self.assertEqual(result["overview"]["outcome"]["state"], "partial", result)
        self.assertEqual(result["detail"]["outcome"]["state"], "partial", result)
        (summary,) = result["overview"]["summaries"]
        (observation,) = result["detail"]["evidence"]
        self.assertNotIn("bytes", summary)
        self.assertEqual(summary["packets"], 12)
        self.assertEqual(observation["bytes"], 100)

    def test_blocking_a_source_does_not_count_as_a_group_leave(self):
        transition = self.candidates["igmpV3Flat"] | {
            "network_interface": "eth0",
            "num_groups": 1,
            "group_record_multicast_address": [self.request["group"]],
            "group_record_type": [3],
            "group_record_num_sources": [1],
            "group_record_source_address": ["192.0.2.20"],
        }
        self.write(
            [
                (transition, self.earliest + 1),
                (transition | {"group_record_type": [6]}, self.earliest + 2),
            ],
            "stream:igmp",
        )
        search = self.frontend(self.igmp, self.request, summary=True)
        (summary,) = [row for row in self.search(search) if row["kind"] == "record"]
        self.assertEqual(summary["group"], self.request["group"])
        self.assertEqual(int(summary["reports"]), 1)
        self.assertEqual(int(summary["leaves"]), 0)

    def test_indexed_point_forwarding_cohort_uses_exact_tuple(self):
        group = self.request["group"]
        cohort = json.loads((FIXTURES / "forwarding-cohort.json").read_text())
        anchor = self.latest - 2
        cohort |= {"observedAt": anchor, "validUntil": anchor}
        profile = self.igmp | {"source": "multicast_nxos"}
        self.write(
            [(cohort, anchor), (cohort | {"sender": "192.0.2.99"}, anchor)],
            "atlas:nxos:multicast:v1",
        )
        payloads, count = self.run_profile(
            profile, sender=cohort["sender"], group=group, latest=anchor
        )
        self.assertEqual(count, 1)
        self.assertEqual(payloads, [cohort])
        exact_rows = self.search(
            self.build_query(
                profile, sender=cohort["sender"], group=group, latest=anchor
            )
        )
        record = next(row for row in exact_rows if row["kind"] == "record")
        self.assertEqual(int(record["mc_epoch"]), anchor)
        self.assertNotIn("_raw", record)

    def test_search_only_viewer_cannot_write_profiles_or_read_unpermitted_index(self):
        payload = self.candidates["igmpV2"] | {"network_interface": "eth0"}
        self.write([(payload, self.latest - 1)], "stream:igmp")
        self.assertEqual(self.run_profile(self.igmp)[1], 1)
        suffix = uuid.uuid4().hex[:12]
        role = f"adm_mc_role_{suffix}"
        user = f"adm_mc_viewer_{suffix}"
        password = secrets.token_urlsafe(24)
        roles = "/services/authorization/roles"
        users = "/services/authentication/users"
        lab._json(
            "POST",
            roles,
            {
                "name": role,
                "capabilities": "search",
                "srchIndexesAllowed": "main",
                "srchIndexesDisallowed": "netflow",
            },
        )
        self.addCleanup(lab._json, "DELETE", f"{roles}/{role}")
        lab._json("POST", users, {"name": user, "password": password, "roles": role})
        self.addCleanup(lab._json, "DELETE", f"{users}/{user}")
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()

        def viewer(method, path, data=None, content_type=None):
            headers = {"Authorization": f"Basic {auth}"}
            if content_type:
                headers["Content-Type"] = content_type
            request = urllib.request.Request(
                lab.MGMT + path, method=method, headers=headers, data=data
            )
            try:
                with lab.urlopen(request, timeout=45) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, {}

        status, _ = viewer("GET", COLLECTION)
        self.assertEqual(status, 200)
        status, _ = viewer(
            "POST",
            COLLECTION,
            b'{"_key":"active","configuration":"{}"}',
            "application/json",
        )
        self.assertEqual(status, 403)
        selector = self.build_query(self.igmp)
        params = urllib.parse.urlencode(
            {
                "search": selector,
                "exec_mode": "blocking",
                "earliest_time": self.earliest,
                "latest_time": self.latest,
            }
        ).encode()
        path = f"/servicesNS/{user}/splunk_adm/search/v2/jobs"
        status, job = viewer(
            "POST",
            f"{path}?output_mode=json",
            params,
            "application/x-www-form-urlencoded",
        )
        if status in (400, 403):
            return  # Splunk can reject the preflight or silently filter the index.
        self.assertIn(status, (200, 201))
        sid = urllib.parse.quote(job["sid"], safe="")
        status, result = viewer("GET", f"{path}/{sid}/results?output_mode=json")
        self.assertEqual(status, 200)
        self.assertFalse(any(row.get("kind") == "record" for row in result["results"]))
