from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import hashlib
import json
import os
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote

from tools.cisco_contract_migration import (
    Journal,
    JOURNAL_SCHEMA,
    SUMMARY_INDEX_WAIT_ATTEMPTS,
    SUMMARY_INDEX_WAIT_BUDGET_SECONDS,
    SUMMARY_INDEX_WAIT_DELAYS,
    SUMMARY_INDEX_WAIT_MAX_SECONDS,
    SUMMARY_CANONICALIZER_VERSION,
    Migration,
    Refused,
    Uncertain,
    _job_sid,
    canonical,
    ensure_state_directory,
    fingerprint,
    main,
    plan_slices,
    rollback_recovery_horizon_seconds,
)


SIDES = {
    "conversation": {
        "rollup_id": "a" * 64,
        "records": "3",
        "contract_version": "2",
        "adm_record": "conversation",
    },
    "hubble_xlate": {
        "rollup_id": "c" * 64,
        "records": "1",
        "contract_version": "2",
        "adm_record": "hubble_xlate",
    },
    "hubble_l7": {
        "rollup_id": "d" * 64,
        "records": "2",
        "contract_version": "2",
        "adm_record": "hubble_l7",
    },
    "traffic": {
        "rollup_id": "b" * 64,
        "records": "1",
        "contract_version": "2",
        "adm_record": "traffic_observation",
    },
}


class FakeApi:
    def __init__(
        self,
        *,
        bad_actual=False,
        unknown_writer=False,
        reject_writer=False,
        delayed_visibility=0,
        mutate_profile_after_dispatch=False,
        live_builder_writes=False,
        history_rows=None,
        catalog_rows=None,
        catalog_invalid=False,
        catalog_update_time=1000,
        sparse_catalog_marker=False,
        extra_catalog_rows=None,
    ):
        self.calls = []
        self.transports = []
        self.writer_dispatch_config = []
        self.sid_count = 0
        self.jobs = {}
        self.persisted_rows = []
        self.bad_actual = bad_actual
        self.unknown_writer = unknown_writer
        self.reject_writer = reject_writer
        self.delayed_visibility = delayed_visibility
        self.mutate_profile_after_dispatch = mutate_profile_after_dispatch
        self.live_builder_writes = live_builder_writes
        self.source_overrides = {}
        self.history_rows = history_rows or []
        self.catalog_rows = catalog_rows or []
        self.catalog_invalid = catalog_invalid
        self.catalog_update_time = catalog_update_time
        self.sparse_catalog_marker = sparse_catalog_marker
        self.extra_catalog_rows = extra_catalog_rows or []
        self.scheduler_logs = []
        self.actual_query_count = 0
        self.collections = {
            name: []
            for name in (
                "adm_observer_scope",
                "adm_network_source_scope",
                "adm_cilium_cluster_settings",
                "adm_ip_identity",
                "adm_interfaces",
                "adm_network_client_history",
                "adm_app_catalog_v2",
            )
        }
        self.macros = {
            "adm_index_summary": "index=adm_summary",
            "adm_summary_index_name": "adm_summary",
            "adm_index_summary_v2": "index=adm_summary_v2",
            "adm_summary_index_v2_name": "adm_summary_v2",
            "adm_data_contract_version": "1",
            "adm_graph(4)": '| `adm_graph_inputs("$service$", "$environment$", "$cluster$", "$namespace$")`',
            "adm_flows_netflow_v2": "index=netflow",
            "adm_flow_enrich_v2": "| lookup adm_network_source_scope",
            "adm_flows_v2": "`adm_flows_netflow_v2` | `adm_flow_enrich_v2`",
            "adm_conversation_rollup_v2": "`adm_flows_v2` | stats count",
            "adm_traffic_observations_v2": "`adm_flows_netflow_v2` | stats count",
            "adm_cilium_lb_mode": '"snat"',
            "adm_cilium_ingress_mode": '"dedicated"',
            "adm_l2announcements_enabled": "0",
            "adm_network_client_history_observations": "multisearch | eval synthetic=1",
            "adm_network_client_history_build": "| `adm_network_client_history_observations` | stats count",
            "adm_catalog_build_status_v2": '| makeresults | eval adm_kind="status", adm_catalog_invalid=0',
            "adm_catalog_build_v2": '| `adm_catalog_build_status_v2` | where adm_kind="result"',
            "adm_catalog_writer_v2": "| `adm_catalog_build_status_v2` | outputlookup adm_app_catalog_v2",
        }
        self.transforms = {
            name: {"external_type": "kvstore", "collection": name}
            for name in (
                "adm_observer_scope",
                "adm_network_source_scope",
                "adm_cilium_cluster_settings",
                "adm_ip_identity",
                "adm_interfaces",
            )
        }
        self.searches = {
            "ADM - Conversation rollup": {
                "search": '| `adm_conversation_rollup` | collect index=`adm_summary_index_name` source="adm:conversation"',
                "dispatchAs": "owner",
                "disabled": "1",
                "is_scheduled": "0",
            },
            "ADM - Conversation rollup v2": {
                "search": '| `adm_conversation_rollup_v2` | collect index=`adm_summary_index_v2_name` source="adm:conversation"',
                "dispatchAs": "owner",
                "disabled": "1",
                "is_scheduled": "0",
            },
            "ADM - Traffic observation rollup v2": {
                "search": '| `adm_traffic_observations_v2` | collect index=`adm_summary_index_v2_name` source="adm:traffic_observation"',
                "dispatchAs": "owner",
                "disabled": "1",
                "is_scheduled": "0",
            },
        }
        interface_path = (
            Path(__file__).resolve().parents[1]
            / "research"
            / "cisco-pipeline-interface.json"
        )
        interface = json.loads(interface_path.read_text())
        writer_contracts = interface["activation"]["writer_contracts"]
        for writer in writer_contracts:
            self.searches[writer["name"]] = dict(writer["fields"])
        for selector in interface["activation"]["cutover_selectors"]:
            self.macros[selector["name"]] = selector["before"]
        self.macro_args = {
            "adm_graph(4)": "service, environment, cluster, namespace",
            "adm_find(1)": "query",
            "adm_flow_evidence(4)": "client, server, port, transport",
        }
        self.return_macro_args_as_list = False

    @staticmethod
    def entry(name, content, acl=True, app="splunk_adm", owner="admin"):
        return {
            "entry": [
                {
                    "name": name,
                    "content": content,
                    "acl": {
                        "app": app,
                        "owner": owner,
                        "perms": {"read": ["admin"], "write": ["admin"]},
                    }
                    if acl
                    else {},
                }
            ]
        }

    @staticmethod
    def _job_entry(sid, job):
        content = {
            "sid": sid,
            "dispatchState": job.get("dispatchState", "DONE"),
            "isDone": job.get("isDone", True),
            "isFinalized": job.get("isFinalized", False),
            "eventIsTruncated": job.get("eventIsTruncated", False),
            "dropCount": job.get("dropCount", 0),
            "resultCount": str(job.get("resultCount", len(job["rows"]))),
            "messages": job.get("messages", []),
            "label": job.get("savedsearch_name", ""),
            "savedsearch_name": job.get("savedsearch_name", ""),
            "isSavedSearch": job.get("saved_search", False),
            "search": job.get("search", ""),
            "request": {
                **job.get("request", {}),
                **(
                    {"search": job.get("search")}
                    if job.get("search") and "search" not in job.get("request", {})
                    else {}
                ),
            },
            "indexEarliestTime": job.get("indexEarliestTime"),
            "indexLatestTime": job.get("indexLatestTime"),
            "searchEarliestTime": job.get("searchEarliestTime"),
            "searchLatestTime": job.get("searchLatestTime"),
            "savedSearchLabel": job.get("savedSearchLabel"),
            "provenance": job.get("provenance"),
        }
        return {
            # Splunk 10.6 represents the endpoint resource as ``name=search``;
            # the actual job identity is content.sid.
            "name": "search",
            "id": f"https://localhost/services/search/v2/jobs/{sid}",
            "content": content,
            "acl": {"app": job.get("app"), "owner": job.get("owner")},
        }

    def request(self, method, path, data=None, json_body=False, timeout=30):
        self.calls.append((method, path, data))
        self.transports.append((method, path, json_body))
        if method == "POST" and json_body:
            raise AssertionError("search/configuration requests must be form encoded")
        if method == "GET" and path == "/services/server/info":
            return self.entry(
                "server", {"guid": "instance-guid", "version": "10.6.0.5"}
            )
        if method == "GET" and path == "/services/authentication/current-context":
            return self.entry(
                "user",
                {
                    "roles": ["admin"],
                    "capabilities": [
                        "search",
                        "schedule_search",
                        "run_collect",
                        "output_file",
                    ],
                    "username": "admin",
                },
                acl=False,
            )
        if (
            method == "GET"
            and path == "/servicesNS/nobody/splunk_adm/configs/conf-macros?count=10000"
        ):
            entries = []
            for name, value in self.macros.items():
                content = {"definition": value}
                if name in self.macro_args:
                    content["args"] = self._macro_args_readback(name)
                entries.append(self.entry(name, content)["entry"][0])
            return {"entry": entries, "paging": {"total": len(entries)}}
        if (
            method == "GET"
            and path
            == "/servicesNS/nobody/splunk_adm/configs/conf-transforms?count=10000"
        ):
            entries = [
                self.entry(name, value)["entry"][0]
                for name, value in self.transforms.items()
            ]
            return {"entry": entries, "paging": {"total": len(entries)}}
        if method == "GET" and "/storage/collections/data/" in path:
            name = unquote(
                path.split("/storage/collections/data/", 1)[1].split("?", 1)[0]
            )
            params = parse_qs(path.split("?", 1)[1]) if "?" in path else {}
            skip = int(params.get("skip", ["0"])[0])
            rows = list(self.collections[name])[skip:]
            if "limit" in params:
                rows = rows[: int(params["limit"][0])]
            return rows
        if method == "GET" and "/configs/conf-macros/" in path:
            name = unquote(path.rsplit("/", 1)[1])
            content = {"definition": self.macros[name]}
            if name in self.macro_args:
                content["args"] = self._macro_args_readback(name)
            return self.entry(name, content)
        if method == "GET" and "/saved/searches/" in path:
            name = unquote(path.split("/saved/searches/", 1)[1])
            name = name.removesuffix("/dispatch")
            return self.entry(name, self.searches[name])
        if method == "POST" and "/configs/conf-macros/" in path:
            name = unquote(path.rsplit("/", 1)[1])
            if name in self.macro_args and "args" not in (data or {}):
                raise Refused(
                    "Splunk requires args when updating a parameterized macro"
                )
            self.macros[name] = data["definition"]
            content = {"definition": self.macros[name]}
            if name in self.macro_args:
                self.macro_args[name] = data["args"]
                content["args"] = self._macro_args_readback(name)
            return self.entry(name, content)
        if (
            method == "POST"
            and "/saved/searches/" in path
            and not path.endswith("/dispatch")
        ):
            name = unquote(path.split("/saved/searches/", 1)[1])
            for key, value in data.items():
                self.searches[name][key] = value
            return self.entry(name, self.searches[name])
        if method == "POST" and path.endswith("/dispatch"):
            if self.reject_writer:

                class Forbidden(Exception):
                    status = 403

                raise Forbidden()
            if self.unknown_writer:
                raise TimeoutError("simulated ambiguous dispatch")
            self.sid_count += 1
            name = unquote(
                path.split("/saved/searches/", 1)[1].removesuffix("/dispatch")
            )
            self.writer_dispatch_config.append(
                (
                    name,
                    self.searches[name].get("disabled"),
                    self.searches[name].get(
                        "is_scheduled", self.searches[name].get("enableSched")
                    ),
                )
            )
            sid = f"writer-{self.sid_count}"
            bounds = {
                key.removeprefix("dispatch."): value
                for key, value in data.items()
                if key.startswith("dispatch.")
            }
            self.jobs[sid] = {
                "rows": [],
                "savedsearch_name": name,
                "search": self.searches[name]["search"],
                "request": bounds,
                "saved_search": True,
                "app": "splunk_adm",
                "owner": "splunk-system-user",
            }
            source = (
                "adm:conversation"
                if "Conversation" in name
                else "adm:traffic_observation"
            )
            if name in {
                "ADM - Conversation rollup v2",
                "ADM - Traffic observation rollup v2",
            }:
                self.persisted_rows.extend(
                    row
                    for row in self._source_rows(source)
                    if row not in self.persisted_rows
                )
            elif name == "ADM - Application catalog v2":
                if self.catalog_rows or self.extra_catalog_rows:
                    self.collections["adm_app_catalog_v2"] = [
                        {**row, "updated": self.catalog_update_time}
                        for row in self.catalog_rows
                    ] + [
                        {**row, "updated": self.catalog_update_time}
                        for row in self.extra_catalog_rows
                    ]
                else:
                    self.collections["adm_app_catalog_v2"] = [
                        {
                            "_key": "adm-catalog-empty",
                            "service": None,
                            "environment": None,
                            "cluster": None,
                            "namespace": None,
                            "pods": None,
                            "first_seen": None,
                            "last_seen": None,
                            "peers": None,
                            "conversations_1h": None,
                            "blocked_1h": None,
                            "unknown_peers_1h": None,
                            "updated": str(self.catalog_update_time),
                            "window_start": None,
                            "window_end": None,
                        }
                    ]
                if self.sparse_catalog_marker and not self.catalog_rows:
                    self.collections["adm_app_catalog_v2"] = [
                        {
                            key: value
                            for key, value in self.collections["adm_app_catalog_v2"][
                                0
                            ].items()
                            if value is not None
                        }
                    ]
            elif name == "ADM - Network client history builder":
                existing = {
                    row["_key"]: row
                    for row in self.collections["adm_network_client_history"]
                }
                index_bounds = (
                    int(data.get("dispatch.index_earliest", -1)),
                    int(data.get("dispatch.index_latest", -1)),
                )
                source_rows = getattr(self, "history_rows_by_bounds", {}).get(
                    index_bounds, self.history_rows
                )
                for row in source_rows:
                    prior = existing.get(row["_key"], {})
                    merged = {**prior, **row}
                    if prior:
                        merged["received_time"] = min(
                            float(prior["received_time"]), float(row["received_time"])
                        )
                        merged["latest_received_time"] = max(
                            float(prior["latest_received_time"]),
                            float(row["latest_received_time"]),
                        )
                    existing[row["_key"]] = merged
                self.collections["adm_network_client_history"] = list(existing.values())
            if self.live_builder_writes:
                self.builder_cycle()
            if self.mutate_profile_after_dispatch:
                self.collections["adm_network_source_scope"].append(
                    {"_key": "changed-profile", "profile": "catalyst_sdwan_ipfix"}
                )
                self.mutate_profile_after_dispatch = False
            return {"sid": sid}
        if method == "POST" and path == "/servicesNS/nobody/splunk_adm/search/v2/jobs":
            query = data["search"]
            if "rollup_id IN (" in query:
                if "index_earliest" in data or "index_latest" in data:
                    raise AssertionError("persisted validation used raw slice bounds")
                self.actual_query_count += 1
                ids = set(__import__("re").findall(r'"([0-9a-f]{64})"', query))
                rows = []
                if self.actual_query_count > self.delayed_visibility:
                    for source_row in self.persisted_rows:
                        if source_row["rollup_id"] not in ids:
                            continue
                        count = int(source_row["records"]) + (
                            6 if self.bad_actual else 0
                        )
                        physical = dict(source_row)
                        physical["records"] = str(count)
                        rows.append(physical)
            elif "index=adm_summary_v2 | fields" in query:
                if "index_earliest" not in data or "index_latest" not in data:
                    raise AssertionError(
                        "initial index audit must have bounded index time"
                    )
                rows = list(self.persisted_rows)
            elif "index=adm_summary_v2 | where _indextime>=" in query:
                if "index_earliest" in data or "index_latest" in data:
                    raise AssertionError(
                        "migration ingestion audit used index request bounds"
                    )
                audit_upper = int(data.get("latest_time", 1_000_060))
                rows = [
                    dict(row)
                    for row in self.persisted_rows
                    if int(row.get("_indextime", 1_000_000)) <= audit_upper
                ]
            elif "| where _indextime>=" in query and 'source="' in query:
                source_match = __import__("re").search(r'source="([^"]+)"', query)
                bounds_match = __import__("re").search(
                    r"_indextime>=(\d+) AND _indextime<=(\d+)", query
                )
                if source_match is None or bounds_match is None:
                    raise AssertionError(
                        "empty summary audit must be source and time bounded"
                    )
                lower, upper = map(int, bounds_match.groups())
                rows = [
                    {
                        key: row[key]
                        for key in (
                            "rollup_id",
                            "records",
                            "adm_record",
                            "contract_version",
                        )
                        if key in row
                    }
                    for row in self.persisted_rows
                    if row.get("source") == source_match.group(1)
                    and lower <= int(row.get("_indextime", 0)) <= upper
                ]
            elif "adm_traffic_observations_v2" in query:
                if "index_earliest" not in data or "index_latest" not in data:
                    raise AssertionError("source query must carry exact index bounds")
                rows = [
                    {**SIDES["traffic"], **self.source_overrides.get("traffic", {})}
                ]
            elif "adm_conversation_rollup_v2" in query:
                if "index_earliest" not in data or "index_latest" not in data:
                    raise AssertionError("source query must carry exact index bounds")
                rows = [
                    {**SIDES[name], **self.source_overrides.get(name, {})}
                    for name in ("conversation", "hubble_xlate", "hubble_l7")
                ]
            elif "adm_network_client_history_observations" in query:
                start = int(data.get("index_earliest", -1))
                end = int(data.get("index_latest", -1))
                rows = list(
                    getattr(self, "history_rows_by_bounds", {}).get(
                        (start, end), self.history_rows
                    )
                )
            elif "adm_catalog_build_status_v2" in query:
                rows = [
                    *[{**row, "adm_kind": "result"} for row in self.catalog_rows],
                    {
                        "adm_kind": "status",
                        "adm_catalog_invalid": "1" if self.catalog_invalid else "0",
                    },
                ]
            elif "inputlookup strict=true adm_app_catalog_v2" in query:
                rows = list(self.collections["adm_app_catalog_v2"])
            elif "source=*scheduler.log*" in query:
                match = __import__("re").search(r'sid="([^"]+)"', query)
                rows = [
                    row
                    for row in self.scheduler_logs
                    if match is None or row.get("sid") == match.group(1)
                ]
            else:
                rows = []
            self.sid_count += 1
            sid = f"search-{self.sid_count}"
            self.jobs[sid] = {
                "rows": rows,
                "search": query,
                "request": {
                    key: value for key, value in data.items() if key != "search"
                },
                "app": "splunk_adm",
                "owner": "admin",
            }
            return {"sid": sid}
        if method == "GET" and path == "/services/search/v2/jobs?count=0":
            entries = [self._job_entry(sid, job) for sid, job in self.jobs.items()]
            return {"entry": entries, "paging": {"total": len(entries)}}
        if method == "POST" and path == "/services/search/v2/jobs":
            raise AssertionError("search jobs must be created in the app namespace")
        if method == "GET" and "/results?" in path:
            sid = path.split("/jobs/", 1)[1].split("/", 1)[0]
            return {"preview": False, "results": self.jobs[sid]["rows"]}
        if method == "GET" and path.startswith("/services/search/v2/jobs/"):
            sid = path.split("/jobs/", 1)[1].split("/", 1)[0]
            if sid not in self.jobs:
                raise AssertionError("unknown SID")
            return {"entry": [self._job_entry(sid, self.jobs[sid])]}
        raise AssertionError((method, path, data))

    def builder_cycle(self):
        """Simulate scheduled identity and interface upserts between phases."""
        cycle = len(self.collections["adm_ip_identity"]) + 1
        self.collections["adm_ip_identity"] = [
            {**row, "updated": str(cycle), "last_seen": str(cycle)}
            for row in self.collections["adm_ip_identity"]
        ] + [{"_key": f"identity-{cycle}", "ip": f"198.51.100.{cycle}"}]
        self.collections["adm_interfaces"] = [
            {**row, "updated": str(cycle)} for row in self.collections["adm_interfaces"]
        ] + [{"_key": f"interface-{cycle}", "ifindex": str(cycle)}]

    def _macro_args_readback(self, name):
        value = self.macro_args[name]
        if self.return_macro_args_as_list:
            if isinstance(value, str):
                return [part.strip() for part in value.split(",") if part.strip()]
            return value
        if isinstance(value, list):
            return ", ".join(part.strip() for part in value)
        return value

    @staticmethod
    def _source_rows(source):
        if source == "adm:conversation":
            return [
                {**SIDES[name], "source": source}
                for name in ("conversation", "hubble_xlate", "hubble_l7")
            ]
        return [{**SIDES["traffic"], "source": source}]


class ContractMigrationTest(unittest.TestCase):
    def test_job_sid_uses_content_identity_when_entry_name_is_search(self):
        self.assertEqual(
            _job_sid(
                {
                    "name": "search",
                    "id": "https://localhost/services/search/v2/jobs/scheduler__true",
                    "content": {"sid": "scheduler__true"},
                }
            ),
            "scheduler__true",
        )

    def test_job_sid_rejects_missing_malformed_or_conflicting_identity(self):
        for entry in (
            {"name": "search", "content": {}},
            {"name": "search", "content": {"sid": "search text"}},
            {
                "name": "search",
                "id": "https://localhost/services/search/v2/jobs/other",
                "content": {"sid": "scheduler__true"},
            },
        ):
            with self.assertRaisesRegex(Refused, "job entry"):
                _job_sid(entry)
        for entry_id in (
            "https://localhost/services/search/v2/jobs/scheduler__true/extra",
            "https://localhost/services/search/jobs/other?sid=scheduler__true",
        ):
            with self.assertRaisesRegex(Refused, "job entry"):
                _job_sid(
                    {
                        "name": "search",
                        "id": entry_id,
                        "content": {"sid": "scheduler__true"},
                    }
                )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = Journal(Path(self.tmp.name) / "migration.json")

    def migration(self, api=None):
        return Migration(
            api or FakeApi(),
            self.journal,
            clock=lambda: 1_000_000,
            sleep=lambda _: None,
            qualifier=lambda: None,
        )

    def sleeping_migration(self):
        sleeps = []
        migration = Migration(
            FakeApi(),
            self.journal,
            clock=lambda: 1_000_000,
            sleep=sleeps.append,
            qualifier=lambda: None,
        )
        return migration, sleeps

    def test_activation_requalifies_before_loading_or_mutating_a_journal(self):
        def unsupported():
            raise RuntimeError("remote search peer added")

        for action in ("cutover", "rollback"):
            with self.subTest(action=action):
                migration = self.migration()
                migration.qualifier = unsupported
                with self.assertRaisesRegex(Refused, "deployment qualification failed"):
                    getattr(migration, action)()
                self.assertFalse(self.journal.path.exists())

    def test_reconcile_qualifies_before_loading_or_writing(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "reconcile-qualification",
            "interface_sha256": migration._interface()[1],
            "phase": "cutover_in_progress",
            "jobs": [{"kind": "search", "state": "dispatch_unknown", "id": "pending"}],
            "temporary_manual_executions": [
                {"name": "ADM - Conversation rollup", "state": "configuration_prepared"}
            ],
        }
        migration._write_journal(journal)
        before = self.journal.path.read_bytes()
        with patch.object(
            Migration,
            "_assert_cutover_origin_compatible",
            side_effect=AssertionError("compatibility check ran before qualification"),
        ):
            migration.qualifier = lambda: (_ for _ in ()).throw(
                RuntimeError("remote search peer added")
            )
            with self.assertRaisesRegex(Refused, "deployment qualification failed"):
                migration.reconcile("sid")
        self.assertEqual(self.journal.path.read_bytes(), before)
        self.assertEqual(api.calls, [])

    def test_api_from_stdin_bootstraps_vendored_sdk_in_clean_process(self):
        script = """
import io
import sys
from unittest.mock import patch
from tools.cisco_contract_migration import _api_from_stdin
sys.path[:] = [entry for entry in sys.path if not entry.endswith('/splunk_adm/bin/lib')]
with patch.object(sys, 'stdin', io.StringIO('token\\n')):
    api = _api_from_stdin('https://localhost:8089', None)
assert api.token == 'token'
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
            env={
                key: value for key, value in os.environ.items() if key != "PYTHONPATH"
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_summary_readback_wait_is_exponential_capped_and_bounded(self):
        self.assertEqual(SUMMARY_INDEX_WAIT_DELAYS[:4], (1.0, 2.0, 4.0, 8.0))
        self.assertLessEqual(
            max(SUMMARY_INDEX_WAIT_DELAYS), SUMMARY_INDEX_WAIT_MAX_SECONDS
        )
        self.assertEqual(
            sum(SUMMARY_INDEX_WAIT_DELAYS), SUMMARY_INDEX_WAIT_BUDGET_SECONDS
        )
        self.assertEqual(
            SUMMARY_INDEX_WAIT_ATTEMPTS, len(SUMMARY_INDEX_WAIT_DELAYS) + 1
        )
        migration, sleeps = self.sleeping_migration()
        for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
            migration._wait_before_summary_retry(attempt)
        self.assertEqual(tuple(sleeps), SUMMARY_INDEX_WAIT_DELAYS)

    def test_persisted_rollup_readback_tolerates_slow_visibility(self):
        migration, sleeps = self.sleeping_migration()
        wanted = {"a" * 64: {"records": "3"}}
        calls = []

        def query(_journal, _spec, expected, _label, attempt):
            calls.append(attempt)
            return dict(expected) if attempt == 7 else {}

        migration._persisted_query = query
        actual = migration._poll_persisted_rows({}, wanted, "conversation", "slow")
        self.assertEqual(actual, wanted)
        self.assertEqual(calls, list(range(1, 8)))
        self.assertEqual(tuple(sleeps), SUMMARY_INDEX_WAIT_DELAYS[:6])

    def test_persisted_rollup_readback_still_refuses_after_budget(self):
        migration, sleeps = self.sleeping_migration()
        calls = []

        def query(_journal, _spec, _expected, _label, attempt):
            calls.append(attempt)
            return {}

        migration._persisted_query = query
        with self.assertRaisesRegex(Refused, "do not match source slice"):
            migration._poll_persisted_rows(
                {}, {"a" * 64: {"records": "3"}}, "conversation", "never"
            )
        self.assertEqual(calls, list(range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1)))
        self.assertEqual(tuple(sleeps), SUMMARY_INDEX_WAIT_DELAYS)

    @staticmethod
    def history_row(received_time=1000):
        return {
            "_key": "e" * 64,
            "contract_version": "1",
            "source": "meraki_association",
            "source_authority": '["org-1","network-1"]',
            "native_id": "00:11:22:33:44:55",
            "event_fingerprint": "f" * 64,
            "client_mac": "00:11:22:33:44:55",
            "client_ip": "192.0.2.10",
            "scope": "lab",
            "cluster": "lab",
            "routing_domain": "network-1",
            "domain_kind": "network",
            "profile": "meraki_association",
            "mapping_status": "mapped",
            "source_time": "900",
            "received_time": str(received_time),
            "latest_received_time": str(received_time),
            "collected_time": None,
            "event_type": "association",
            "client_type": None,
            "connected_device_type": None,
            "attachment_status": "unresolved",
            "attachment_basis": "meraki_association_event",
            "attachment_device_id": None,
            "attachment_device_name": "lab-ap",
            "attachment_device_mac": None,
            "device_serial": "AP-1",
            "ssid_number": "1",
            "interface": None,
            "quality_reason": None,
            "raw_ref": "a" * 64,
        }

    @staticmethod
    def catalog_row():
        return {
            "_key": "b" * 64,
            "service": "checkout",
            "environment": "test",
            "cluster": "lab",
            "namespace": "default",
            "pods": 1,
            "first_seen": 900,
            "last_seen": 990,
            "peers": 1,
            "conversations_1h": 1,
            "blocked_1h": 0,
            "unknown_peers_1h": 0,
            "updated": 1000,
            "window_start": 0,
            "window_end": 1000,
        }

    def test_plan_slices_requires_aligned_bounded_closed_interval(self):
        self.assertEqual(
            plan_slices(900_000, 900_600, now=1_000_000),
            [{"start": 900_000, "end": 900_300}, {"start": 900_300, "end": 900_600}],
        )
        for start, end in (
            (900_001, 900_300),
            (900_300, 900_300),
            (900_000, 1_001_000),
        ):
            with self.subTest(start=start, end=end), self.assertRaises(Refused):
                plan_slices(start, end, now=1_100_000)

    def test_journal_is_owner_only_and_atomic(self):
        with self.journal.locked():
            self.journal.write({"schema": JOURNAL_SCHEMA, "phase": "prepared"})
        self.assertEqual(self.journal.read()["phase"], "prepared")
        self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.journal.lock_path.stat().st_mode & 0o777, 0o600)

    def _state_dir_journal(self, directory: Path, name: str = "j.json") -> Journal:
        return Journal(directory / name)

    def test_journal_creates_missing_directory_owner_only(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "state"
            journal = self._state_dir_journal(target)
            with journal.locked():
                journal.write({"schema": JOURNAL_SCHEMA, "phase": "prepared"})
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            self.assertEqual(journal.path.stat().st_mode & 0o777, 0o600)

    def test_journal_never_changes_existing_directory_mode(self):
        with tempfile.TemporaryDirectory() as root:
            shared = Path(root) / "shared"
            shared.mkdir()
            shared.chmod(0o1777)
            journal = self._state_dir_journal(shared)
            with journal.locked():
                journal.write({"schema": JOURNAL_SCHEMA, "phase": "prepared"})
            Journal.write_artifact(shared / "artifact.json", {"a": 1})
            self.assertEqual(shared.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(journal.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(journal.lock_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((shared / "artifact.json").stat().st_mode & 0o777, 0o600)

            group = Path(root) / "group"
            group.mkdir()
            group.chmod(0o755)
            with self._state_dir_journal(group).locked():
                pass
            self.assertEqual(group.stat().st_mode & 0o7777, 0o755)

    @staticmethod
    def _symlink_owned_by(link, uid):
        real_lstat = Path.lstat

        def fake_lstat(self, *args, **kwargs):
            result = real_lstat(self, *args, **kwargs)
            if self == link:
                values = list(result)
                values[stat.ST_UID] = uid
                return os.stat_result(values)
            return result

        return patch.object(Path, "lstat", fake_lstat)

    def test_journal_refuses_unsafe_existing_directory(self):
        with tempfile.TemporaryDirectory() as root:
            open_dir = Path(root) / "open"
            open_dir.mkdir()
            open_dir.chmod(0o770)
            real = Path(root) / "real"
            real.mkdir()
            link = Path(root) / "link"
            link.symlink_to(real)
            plain = Path(root) / "file"
            plain.write_text("x")
            # A symlink owned by a non-root user, even when the suite runs as root.
            user_link = self._symlink_owned_by(link, os.geteuid() or 1)
            for directory in (open_dir, link, plain / "sub"):
                journal = self._state_dir_journal(directory)
                with self.subTest(directory=directory.name), user_link:
                    with self.assertRaises(Refused), journal.locked():
                        pass
                    with self.assertRaises(Refused):
                        Journal.write_artifact(directory / "a.json", {"a": 1})
            self.assertEqual(open_dir.stat().st_mode & 0o777, 0o770)
            self.assertEqual(list(real.iterdir()), [])

    @unittest.skipIf(os.geteuid() == 0, "ownership check is moot as root")
    def test_journal_refuses_directory_owned_by_another_user(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "state"
            directory.mkdir(mode=0o700)
            with patch(
                "tools.cisco_contract_migration.os.geteuid",
                return_value=os.geteuid() + 1,
            ):
                with (
                    self.assertRaises(Refused),
                    self._state_dir_journal(directory).locked(),
                ):
                    pass

    def test_journal_directory_oserror_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            journal = self._state_dir_journal(Path(root) / "state")
            with patch.object(
                Path, "mkdir", side_effect=PermissionError(13, "Permission denied")
            ):
                with self.assertRaises(Refused), journal.locked():
                    pass
                with self.assertRaises(Refused):
                    Journal.write_artifact(Path(root) / "state" / "a.json", {"a": 1})

    @unittest.skipIf(os.geteuid() == 0, "permission denial is moot as root")
    def test_journal_unwritable_directory_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "state"
            directory.mkdir(mode=0o500)
            try:
                with (
                    self.assertRaises(Refused),
                    self._state_dir_journal(directory).locked(),
                ):
                    pass
            finally:
                directory.chmod(0o700)

    def _write_journal_file(self, directory: Path, mode: int = 0o600) -> Path:
        path = directory / "j.json"
        path.write_text(json.dumps({"schema": JOURNAL_SCHEMA, "phase": "prepared"}))
        path.chmod(mode)
        return path

    def test_journal_read_accepts_owned_owner_only_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write_journal_file(Path(root))
            self.assertEqual(Journal(path).read()["phase"], "prepared")

    def test_journal_read_refuses_file_owned_by_another_user(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write_journal_file(Path(root))
            with patch(
                "tools.cisco_contract_migration.os.geteuid",
                return_value=os.geteuid() + 1,
            ):
                with self.assertRaises(Refused):
                    Journal(path).read()

    def test_journal_read_refuses_symlink_and_loose_mode(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            path = self._write_journal_file(directory)
            link = directory / "link.json"
            link.symlink_to(path)
            with self.assertRaises(Refused):
                Journal(link).read()
            path.chmod(0o640)
            with self.assertRaises(Refused):
                Journal(path).read()

    def test_journal_read_refuses_non_regular_file(self):
        with tempfile.TemporaryDirectory() as root:
            fifo = Path(root) / "j.json"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(Refused):
                Journal(fifo).read()

    def test_journal_read_refuses_oversized_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write_journal_file(Path(root))
            with patch("tools.cisco_contract_migration.MAX_JOURNAL_BYTES", 8):
                with self.assertRaises(Refused):
                    Journal(path).read()

    def test_journal_write_os_errors_are_refusals(self):
        with tempfile.TemporaryDirectory() as root:
            journal = Journal(Path(root) / "j.json")
            with journal.locked():
                with patch(
                    "tools.cisco_contract_migration.os.replace",
                    side_effect=PermissionError(1, "Operation not permitted"),
                ):
                    with self.assertRaises(Refused):
                        journal.write({"schema": JOURNAL_SCHEMA})
                    with self.assertRaises(Refused):
                        Journal.write_artifact(Path(root) / "a.json", {"a": 1})
            self.assertEqual(
                [p.name for p in Path(root).iterdir() if p.name.startswith(".cisco")],
                [],
            )

    def test_journal_creates_missing_parents_owner_only(self):
        with tempfile.TemporaryDirectory() as root:
            old = os.umask(0)
            try:
                journal = Journal(Path(root) / "a" / "b" / "j.json")
                with journal.locked():
                    pass
            finally:
                os.umask(old)
            for part in ("a", "a/b"):
                self.assertEqual((Path(root) / part).stat().st_mode & 0o777, 0o700)

    def test_journal_accepts_root_owned_symlink_directory(self):
        with tempfile.TemporaryDirectory() as root:
            real = Path(root) / "real"
            real.mkdir(mode=0o700)
            link = Path(root) / "link"
            link.symlink_to(real)
            with self._symlink_owned_by(link, 0):
                ensure_state_directory(link)
            with (
                self._symlink_owned_by(link, os.geteuid() or 1),
                self.assertRaises(Refused),
            ):
                ensure_state_directory(link)

    def test_journal_lock_symlink_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "state"
            directory.mkdir(mode=0o700)
            target = directory / "elsewhere"
            target.write_text("")
            journal = Journal(directory / "j.json")
            journal.lock_path.symlink_to(target)
            with self.assertRaises(Refused), journal.locked():
                pass

    def test_journal_lock_owned_by_another_user_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "state"
            directory.mkdir(mode=0o700)
            journal = Journal(directory / "j.json")
            real_fstat = os.fstat

            def foreign_fstat(fd):
                values = list(real_fstat(fd))
                values[stat.ST_UID] = os.geteuid() + 1
                return os.stat_result(values)

            with patch("tools.cisco_contract_migration.os.fstat", foreign_fstat):
                with self.assertRaisesRegex(Refused, "owned by another user"):
                    with journal.locked():
                        pass

    @unittest.skipIf(os.geteuid() == 0, "ownership check is moot as root")
    def test_ancestor_created_concurrently_by_another_user_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            ancestor = Path(root) / "a"
            real_mkdir = Path.mkdir

            def racing_mkdir(self, *args, **kwargs):
                if self == ancestor:
                    real_mkdir(self, mode=0o700)
                    if not kwargs.get("exist_ok"):
                        raise FileExistsError(17, "File exists")
                    return None
                return real_mkdir(self, *args, **kwargs)

            with (
                patch.object(Path, "mkdir", racing_mkdir),
                patch(
                    "tools.cisco_contract_migration.os.geteuid",
                    return_value=os.geteuid() + 1,
                ),
            ):
                with self.assertRaisesRegex(Refused, "owned by another user"):
                    ensure_state_directory(ancestor / "b")
            self.assertFalse((ancestor / "b").exists())

    def test_created_ancestor_with_loose_mode_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            ancestor = Path(root) / "a"
            real_mkdir = Path.mkdir

            def loose_mkdir(self, *args, **kwargs):
                real_mkdir(self, *args, **kwargs)
                if self == ancestor:
                    self.chmod(0o777)

            with patch.object(Path, "mkdir", loose_mkdir):
                with self.assertRaises(Refused):
                    ensure_state_directory(ancestor / "b")

    def test_atomic_write_cleanup_failure_does_not_mask_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "j.json"
            with (
                patch(
                    "tools.cisco_contract_migration.os.replace",
                    side_effect=PermissionError(1, "Operation not permitted"),
                ),
                patch(
                    "tools.cisco_contract_migration.os.unlink",
                    side_effect=PermissionError(1, "Operation not permitted"),
                ),
            ):
                with self.assertRaises(Refused):
                    Journal._atomic_write(path, b"{}", "journal")

    def test_main_turns_unexpected_oserror_into_refused_output(self):
        with tempfile.TemporaryDirectory() as root:
            output = io.StringIO()
            with (
                patch(
                    "tools.cisco_contract_migration._api_from_stdin",
                    return_value=object(),
                ),
                patch.object(
                    Journal,
                    "locked",
                    side_effect=OSError(5, "Input/output error", root),
                ),
                redirect_stdout(output),
            ):
                code = main(["--journal", str(Path(root) / "j.json"), "status"])
            self.assertEqual(code, 2)
            report = json.loads(output.getvalue())
            self.assertEqual(report["status"], "refused")
            self.assertNotIn(root, output.getvalue())

    def test_saved_search_fingerprint_ignores_runtime_rest_metadata(self):
        first = {
            "search": "index=example",
            "disabled": "1",
            "next_scheduled_time": "100",
            "last_run": "99",
        }
        second = {
            **first,
            "next_scheduled_time": "200",
            "last_run": "199",
        }
        self.assertEqual(
            Migration._stable_saved_search_content(first),
            Migration._stable_saved_search_content(second),
        )

    def test_snapshot_accepts_only_journaled_staged_writer_enablement(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        api.searches["ADM - Conversation rollup v2"]["disabled"] = "0"
        migration.snapshot(allow_activation=True)
        api.searches["ADM - Conversation rollup v2"]["search"] += " | eval drift=1"
        with self.assertRaises(Refused):
            migration.snapshot(allow_activation=True)

    def test_snapshot_normalizes_splunk_boolean_config_values(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        for name in (
            "ADM - Conversation rollup v2",
            "ADM - Traffic observation rollup v2",
        ):
            api.searches[name]["disabled"] = True
            api.searches[name]["is_scheduled"] = True
            api.searches[name]["enableSched"] = True
        migration.snapshot()
        api.searches["ADM - Conversation rollup v2"]["is_scheduled"] = "false"
        with self.assertRaises(Refused):
            migration.snapshot()

    def test_snapshot_accepts_is_scheduled_rest_alias_for_enable_sched_contracts(self):
        api = FakeApi()
        for name in (
            "ADM - Network client history builder",
            "ADM - Application catalog",
            "ADM - Application catalog v2",
        ):
            api.searches[name]["is_scheduled"] = api.searches[name].pop("enableSched")
        self.migration(api).snapshot()

    def test_snapshot_refuses_conflicting_schedule_aliases(self):
        api = FakeApi()
        search = api.searches["ADM - Network client history builder"]
        search["is_scheduled"] = "0"
        with self.assertRaisesRegex(Refused, "schedule aliases conflict"):
            self.migration(api).snapshot()

    def test_snapshot_refuses_missing_schedule_evidence(self):
        api = FakeApi()
        search = api.searches["ADM - Network client history builder"]
        search.pop("enableSched")
        with self.assertRaisesRegex(Refused, "schedule evidence is missing"):
            self.migration(api).snapshot()

    def test_writer_query_and_dispatch_accept_rest_schedule_alias(self):
        api = FakeApi()
        migration = self.migration(api)
        stream_spec = {
            "saved_search": "ADM - Conversation rollup",
        }
        api.searches[stream_spec["saved_search"]]["enableSched"] = api.searches[
            stream_spec["saved_search"]
        ].pop("is_scheduled")
        self.assertEqual(
            migration._writer_query(stream_spec),
            "| `adm_conversation_rollup`",
        )
        for name in (
            "ADM - Network client history builder",
            "ADM - Application catalog",
            "ADM - Application catalog v2",
        ):
            api.searches[name]["is_scheduled"] = api.searches[name].pop("enableSched")
        migration._assert_origin_unchanged = lambda _journal: None
        migration._assert_no_competing_staged_jobs = lambda _journal: None
        migration._read_job = lambda _journal, _record: []
        for name in (
            "ADM - Network client history builder",
            "ADM - Application catalog",
            "ADM - Application catalog v2",
        ):
            migration._dispatch_writer(
                {"jobs": []},
                name,
                {"earliest_time": "0", "latest_time": "1"},
                label=name,
            )

    def test_writer_dispatch_refuses_schedule_alias_conflict_or_missing(self):
        for mode in ("conflict", "missing"):
            api = FakeApi()
            migration = self.migration(api)
            search = api.searches["ADM - Network client history builder"]
            if mode == "conflict":
                search["is_scheduled"] = "0"
            else:
                search.pop("enableSched")
            with self.subTest(mode=mode), self.assertRaises(Refused):
                migration._dispatch_writer(
                    {"jobs": []},
                    "ADM - Network client history builder",
                    {"earliest_time": "0", "latest_time": "1"},
                    label="history",
                )

    def test_snapshot_accepts_selector_continuation_newlines_and_preserves_origin(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, _ = migration._interface()
        multiline = {}
        for selector in interface["activation"]["cutover_selectors"]:
            value = selector["before"]
            if " | " in value:
                value = value.replace(" | ", " |\n ", 1)
            multiline[selector["name"]] = value
            api.macros[selector["name"]] = value

        origin = migration.snapshot()
        for name, value in multiline.items():
            self.assertEqual(origin["macros"][name]["definition"], value)
        mutations = migration._build_cutover_mutations({"origin": origin}, interface)
        selector_mutation = next(
            item
            for item in mutations
            if item["kind"] == "macro_definition" and item["name"] == "adm_graph(4)"
        )
        self.assertEqual(selector_mutation["before"], multiline["adm_graph(4)"])

    def test_selector_whitespace_comparison_does_not_change_quoted_literals(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, _ = migration._interface()
        selector = next(
            item
            for item in interface["activation"]["cutover_selectors"]
            if item["name"] == "adm_catalog_build"
        )
        api.macros[selector["name"]] = selector["before"].replace(
            'adm_kind=="result"', 'adm_kind=="different result"'
        )
        with self.assertRaisesRegex(Refused, "public selector"):
            migration.snapshot()

    def test_selector_whitespace_drift_in_single_quoted_field_name_refuses(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, _ = migration._interface()
        selector = next(
            item
            for item in interface["activation"]["cutover_selectors"]
            if item["name"] == "adm_topology"
        )
        api.macros[selector["name"]] = selector["before"].replace(
            "'Row_info{}.hostname'", "'Row_info{}. hostname'"
        )
        with self.assertRaisesRegex(Refused, "public selector"):
            migration.snapshot()

    def test_selector_unterminated_quote_refuses_closed_form_comparison(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, _ = migration._interface()
        selector = next(
            item
            for item in interface["activation"]["cutover_selectors"]
            if item["name"] == "adm_graph(4)"
        )
        api.macros[selector["name"]] = selector["before"][:-1]
        with self.assertRaisesRegex(Refused, "public selector"):
            migration.snapshot()

    def test_history_builder_verifies_additive_rows_and_receipt_merging(self):
        first, replay = self.history_row(1000), self.history_row(1100)
        api = FakeApi(history_rows=[first, replay])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_history_slice(journal, journal["slices"][0])
        stored = self.journal.read()
        self.assertEqual(stored["slices"][0]["history"]["state"], "verified")
        row = api.collections["adm_network_client_history"][0]
        self.assertEqual(row["received_time"], 1000)
        self.assertEqual(row["latest_received_time"], 1100)
        self.assertNotIn("192.0.2.10", json.dumps(stored))

    def test_history_replay_merges_receipts_across_slices_from_immutable_manifests(
        self,
    ):
        first = self.history_row(1000)
        api = FakeApi(history_rows=[first])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_600)
        migration._stage_history_slice(journal, journal["slices"][0])

        api.history_rows = [self.history_row(1100)]
        migration._stage_history_slice(journal, journal["slices"][1])

        stored = self.journal.read()
        actual = api.collections["adm_network_client_history"][0]
        self.assertEqual(actual["received_time"], 1000)
        self.assertEqual(actual["latest_received_time"], 1100)
        self.assertEqual(
            stored["slices"][0]["history"]["expected_receipts"][fingerprint("e" * 64)][
                "received_min"
            ],
            1000,
        )
        self.assertNotIn("192.0.2.10", json.dumps(stored))

    def test_history_retry_reuses_pinned_bounds_and_running_writer_sid(self):
        first = self.history_row(1000)
        api = FakeApi(history_rows=[first])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        original_dispatch = migration._dispatch_writer
        dispatch_calls = []
        expected_windows = []
        original_expected = migration._history_expected

        def expected_with_window(*args, **kwargs):
            expected_windows.append(kwargs.get("event_bounds"))
            return original_expected(*args, **kwargs)

        def dispatch_then_interrupt(*args, **kwargs):
            dispatch_calls.append((args[2], kwargs.get("intent_fingerprint")))
            output = original_dispatch(*args, **kwargs)
            if len(dispatch_calls) == 1:
                # Model process interruption after a durable SID and external
                # writer completion but before the slice readback checkpoint.
                dispatch_record = next(
                    item
                    for item in journal["jobs"]
                    if item.get("label") == "ADM - Network client history builder"
                    and item.get("sid")
                )
                dispatch_record["state"] = "running"
                migration._write_journal(journal)
                raise Uncertain("simulated interruption after history dispatch")
            return output

        migration._history_expected = expected_with_window
        migration._dispatch_writer = dispatch_then_interrupt
        with self.assertRaisesRegex(Uncertain, "simulated interruption"):
            migration._stage_history_slice(journal, journal["slices"][0])

        checkpoint = self.journal.read()
        history = checkpoint["slices"][0]["history"]
        pinned = dict(history["request_bounds"])
        self.assertEqual(pinned["latest_time"], checkpoint["event_latest"])
        checkpoint["event_latest"] = str(int(checkpoint["event_latest"]) + 300)
        self.journal.write(checkpoint)
        journal = self.journal.read()
        migration._dispatch_writer = original_dispatch

        migration._stage_history_slice(journal, journal["slices"][0])

        stored = self.journal.read()
        self.assertEqual(stored["slices"][0]["history"]["state"], "verified")
        self.assertEqual(stored["slices"][0]["history"]["request_bounds"], pinned)
        self.assertEqual(expected_windows[0], expected_windows[1])
        self.assertEqual(dispatch_calls[0][0], dispatch_calls[-1][0])
        self.assertEqual(dispatch_calls[0][1], dispatch_calls[-1][1])
        writer_dispatches = [
            call
            for call in api.calls
            if call[0] == "POST"
            and call[1].endswith(
                "/saved/searches/ADM%20-%20Network%20client%20history%20builder/dispatch"
            )
        ]
        self.assertEqual(len(writer_dispatches), 1)

    def test_history_preexisting_baseline_is_preserved_and_merged_with_replay(self):
        old = self.history_row(1000)
        api = FakeApi(history_rows=[self.history_row(1100)])
        api.collections["adm_network_client_history"] = [
            {
                **old,
                "latest_received_time": "1000",
            }
        ]
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_history_slice(journal, journal["slices"][0])

        actual = api.collections["adm_network_client_history"][0]
        self.assertEqual(actual["received_time"], 1000)
        self.assertEqual(actual["latest_received_time"], 1100)
        self.assertEqual(len(self.journal.read()["history_baseline"]), 1)

    def test_rollback_phase_dispatch_guard_allows_journaled_v1_recovery_writer(self):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        origin = migration.snapshot()
        interface, _ = migration._interface()
        cutover_mutations = migration._build_cutover_mutations(
            {"origin": origin}, interface
        )
        for selector in interface["activation"]["cutover_selectors"]:
            api.macros[selector["name"]] = selector["after"]
        v1_restore = next(
            item
            for item in cutover_mutations
            if item.get("name") == "ADM - Conversation rollup"
            and item.get("field") == "disabled"
        )
        rollback_mutation = {
            **v1_restore,
            "before": v1_restore["after"],
            "after": v1_restore["before"],
            "state": "applied",
            "verified_at": 999_600,
        }
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "rollback-writer-dispatch",
            "phase": "rollback_in_progress",
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "cutover": {"mutations": cutover_mutations},
            "rollback": {"mutations": [rollback_mutation]},
            "created_at": 900_000,
            "event_earliest": "0",
            "event_latest": "1000000",
            "jobs": [],
        }
        migration._write_journal(journal)

        migration._dispatch_writer(
            journal,
            "ADM - Conversation rollup",
            {
                "earliest_time": "900000",
                "latest_time": "900900",
                "index_earliest": "900000",
                "index_latest": "900300",
            },
            label="V1 rollback recovery dispatch",
            intent_fingerprint="rollback-intent",
        )

        self.assertTrue(
            any(
                method == "POST" and path.endswith("/dispatch")
                for method, path, _ in api.calls
            )
        )

    def test_history_invalid_mapping_status_refuses_before_writer(self):
        row = self.history_row()
        row["mapping_status"] = "conflict"
        api = FakeApi(history_rows=[row])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration._stage_history_slice(journal, journal["slices"][0])
        self.assertFalse(any(path.endswith("/dispatch") for _, path, _ in api.calls))

    def test_history_rest_owner_metadata_does_not_bypass_source_contract(self):
        api = FakeApi(history_rows=[self.history_row()])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_history_slice(journal, journal["slices"][0])
        row = api.collections["adm_network_client_history"][0]
        row["_user"] = "nobody"
        migration._validate_history_coverage(journal, migration._interface()[0])
        row["_user"] = {"unexpected": True}
        with self.assertRaisesRegex(Refused, "ownership metadata"):
            migration._validate_history_coverage(journal, migration._interface()[0])
        row["_user"] = "nobody"
        row["invented_field"] = "not in contract"
        with self.assertRaisesRegex(Refused, "outside its contract"):
            migration._validate_history_coverage(journal, migration._interface()[0])

    def test_final_history_validation_detects_post_backfill_tampering(self):
        row = self.history_row()
        api = FakeApi(history_rows=[row])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_history_slice(journal, journal["slices"][0])
        api.collections["adm_network_client_history"][0]["client_ip"] = "192.0.2.99"

        with self.assertRaises(Refused):
            migration._validate_history_coverage(journal, migration._interface()[0])

    def test_final_history_validation_reuses_pinned_slice_event_bounds(self):
        api = FakeApi(history_rows=[self.history_row(1000)])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_history_slice(journal, journal["slices"][0])
        stored = self.journal.read()
        pinned = dict(stored["slices"][0]["history"]["request_bounds"])
        stored["event_latest"] = str(int(stored["event_latest"]) + 300)
        self.journal.write(stored)

        original_expected = migration._history_expected
        observed_bounds = []

        def expected_with_later_key(*args, event_bounds=None, **kwargs):
            observed_bounds.append(dict(event_bounds or {}))
            expected = original_expected(*args, event_bounds=event_bounds, **kwargs)
            if (
                event_bounds
                and event_bounds.get("latest_time") != pinned["latest_time"]
            ):
                expected["unexpected-expanded-window-key"] = {
                    "stable": {"client_ip": "192.0.2.250"},
                    "fingerprint": fingerprint({"client_ip": "192.0.2.250"}),
                    "received_min": 1200,
                    "received_max": 1200,
                }
            return expected

        migration._history_expected = expected_with_later_key
        coverage = migration._validate_history_coverage(
            self.journal.read(), migration._interface()[0]
        )

        self.assertEqual(coverage["keys"], 1)
        self.assertEqual(
            observed_bounds,
            [
                {
                    "earliest_time": pinned["earliest_time"],
                    "latest_time": pinned["latest_time"],
                }
            ],
        )

    def test_final_history_validation_requires_exact_receipt_extrema_across_slices(
        self,
    ):
        first, replay = self.history_row(1000), self.history_row(1100)
        api = FakeApi(history_rows=[first, replay])
        api.collections["adm_network_client_history"] = [
            {**first, "latest_received_time": "1100"}
        ]
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_600)
        migration._validate_history_coverage(journal, migration._interface()[0])

        api.collections["adm_network_client_history"][0]["received_time"] = "1001"
        with self.assertRaises(Refused):
            migration._validate_history_coverage(journal, migration._interface()[0])

    def test_catalog_status_and_full_collection_are_validated_before_cutover(self):
        api = FakeApi(catalog_rows=[self.catalog_row()], catalog_update_time=2000)
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_catalog(journal)
        self.assertEqual(self.journal.read()["catalog"]["state"], "verified")
        self.assertEqual(self.journal.read()["catalog"]["rows"], 1)

    def test_catalog_rest_numbers_match_search_strings_without_rounding(self):
        numeric = {
            "pods",
            "first_seen",
            "last_seen",
            "peers",
            "conversations_1h",
            "blocked_1h",
            "unknown_peers_1h",
            "updated",
            "window_start",
            "window_end",
        }
        large = 1234567890123456789012345678901234
        for invalid in (None, "drift", True, "NaN", "1.5", "1e999999999"):
            with self.subTest(invalid=invalid):
                self.journal.path.unlink(missing_ok=True)
                row = self.catalog_row()
                row["pods"] = str(large)
                api = FakeApi(catalog_rows=[row], catalog_update_time=2000)
                migration = self.migration(api)
                journal = migration.prepare(900_000, 900_300)
                original = api.request

                def request(method, path, data=None, **kwargs):
                    result = original(method, path, data, **kwargs)
                    if (
                        method == "GET"
                        and "/storage/collections/data/adm_app_catalog_v2?" in path
                    ):
                        result = [
                            {
                                field: int(value)
                                if field in numeric and value is not None
                                else value
                                for field, value in item.items()
                            }
                            for item in result
                        ]
                        if invalid is not None and result:
                            result[0]["pods"] = (
                                large + 1 if invalid == "drift" else invalid
                            )
                    return result

                api.request = request
                if invalid is None:
                    migration._stage_catalog(journal)
                    self.assertEqual(
                        self.journal.read()["catalog"]["state"], "verified"
                    )
                else:
                    with self.assertRaises(Refused):
                        migration._stage_catalog(journal)

    def test_empty_catalog_allows_sparse_reserved_marker(self):
        api = FakeApi(sparse_catalog_marker=True)
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)

        migration._stage_catalog(journal)

        self.assertEqual(self.journal.read()["catalog"]["state"], "verified")

    def test_catalog_rejects_extra_valid_stale_collection_key(self):
        expected = self.catalog_row()
        stale = {**self.catalog_row(), "_key": "c" * 64, "service": "stale"}
        api = FakeApi(catalog_rows=[expected], extra_catalog_rows=[stale])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)

        with self.assertRaises(Refused):
            migration._stage_catalog(journal)

    def test_catalog_input_change_gets_a_new_durable_dispatch_intent(self):
        api = FakeApi(catalog_rows=[self.catalog_row()])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_catalog(journal)
        first = self.journal.read()["catalog"]
        journal = self.journal.read()
        journal["slices"][0]["streams"]["conversation"]["expected_fingerprint"] = (
            "changed-input-fingerprint"
        )
        self.journal.write(journal)

        migration._stage_catalog(self.journal.read())

        second = self.journal.read()["catalog"]
        catalog_dispatches = [
            record
            for record in self.journal.read()["jobs"]
            if record.get("label") == "ADM - Application catalog v2"
        ]
        self.assertEqual(second["build_generation"], first["build_generation"] + 1)
        self.assertEqual(len(catalog_dispatches), 2)
        self.assertNotEqual(
            catalog_dispatches[0]["intent_fingerprint"],
            catalog_dispatches[1]["intent_fingerprint"],
        )

    def test_invalid_catalog_status_refuses_before_writer_dispatch(self):
        api = FakeApi(catalog_invalid=True)
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration._stage_catalog(journal)
        self.assertFalse(any(path.endswith("/dispatch") for _, path, _ in api.calls))

    def test_first_scheduled_writer_requires_absolute_complete_job_bounds(self):
        api = FakeApi()
        migration = self.migration(api)
        writer = "ADM - Conversation rollup v2"
        journal = {
            "event_earliest": "0",
            "event_latest": "1000000",
            "cutover": {"started_at": 900000},
            "jobs": [],
            "origin": {"principal": {"username": "admin"}},
        }
        api.jobs["relative"] = {
            "rows": [],
            "savedsearch_name": writer,
            "saved_search": True,
            "request": {"index_earliest": "-10m@m", "index_latest": "@m"},
            "app": "splunk_adm",
            "owner": "splunk-system-user",
        }
        self.assertIsNone(migration._first_scheduled_writer_bounds(writer, journal))
        api.jobs["scheduler__absolute"] = {
            "rows": [],
            "savedsearch_name": writer,
            "label": writer,
            "saved_search": True,
            "request": {"index_earliest": "-10m@m", "index_latest": "-5m@m"},
            "searchEarliestTime": "913500",
            "searchLatestTime": "1000800",
            "savedSearchLabel": '{"owner":"nobody","app":"splunk_adm","sharing":"app"}',
            "provenance": "scheduler",
            "app": "splunk_adm",
            "owner": "splunk-system-user",
        }
        api.scheduler_logs = [
            {
                "sid": "scheduler__absolute",
                "savedsearch_name": writer,
                "scheduled_time": "999900",
                "dispatch_time": "999900",
                "status": "success",
            }
        ]
        self.assertEqual(
            migration._first_scheduled_writer_bounds(writer, journal), (999300, 999600)
        )
        api.scheduler_logs[0]["dispatch_time"] = "999974"
        self.assertTrue(
            migration._scheduler_log_confirms(
                journal,
                "scheduler__absolute",
                writer,
                (999300, 999600),
                upper_epoch=1_000_060,
            )
        )
        api.scheduler_logs[0]["dispatch_time"] = "1000059"
        self.assertTrue(
            migration._scheduler_log_confirms(
                journal,
                "scheduler__absolute",
                writer,
                (999300, 999600),
                upper_epoch=1_000_060,
            )
        )
        for invalid_dispatch in ("999899", "1000060", "1000061", "not-an-epoch", None):
            api.scheduler_logs[0]["dispatch_time"] = invalid_dispatch
            with self.subTest(dispatch_time=invalid_dispatch):
                self.assertFalse(
                    migration._scheduler_log_confirms(
                        journal,
                        "scheduler__absolute",
                        writer,
                        (999300, 999600),
                        upper_epoch=1_000_060,
                    )
                )
        api.scheduler_logs[0]["dispatch_time"] = "999974"
        scheduler_log_request = next(
            body
            for method, path, body in api.calls
            if method == "POST"
            and path.endswith("/search/v2/jobs")
            and "source=*scheduler.log*" in body.get("search", "")
        )
        self.assertEqual(scheduler_log_request["earliest_time"], "900000")
        self.assertEqual(scheduler_log_request["latest_time"], "1000060")
        api.jobs["scheduler__wrong-owner"] = {
            "rows": [],
            "savedsearch_name": writer,
            "label": writer,
            "saved_search": True,
            "request": {"index_earliest": "-10m@m", "index_latest": "-5m@m"},
            "searchEarliestTime": "913200",
            "searchLatestTime": "1000500",
            "savedSearchLabel": '{"owner":"nobody","app":"splunk_adm","sharing":"app"}',
            "provenance": "scheduler",
            "app": "splunk_adm",
            "owner": "admin",
        }
        with self.assertRaises(Refused):
            migration._first_scheduled_writer_bounds(writer)

    def test_empty_summary_warning_requires_exact_saved_writer_and_zero_results(self):
        api = FakeApi()
        migration = self.migration(api)
        name = "ADM - Conversation rollup v2"
        request_bounds = {
            "earliest_time": "0",
            "latest_time": "1000900",
            "index_earliest": "900000",
            "index_latest": "900300",
        }
        search = api.searches[name]["search"]
        api.jobs["empty-summary-writer"] = {
            "rows": [],
            "savedsearch_name": name,
            "search": search,
            "request": request_bounds,
            "saved_search": True,
            "app": "splunk_adm",
            "owner": "splunk-system-user",
            "messages": [{"type": "WARN", "text": "No results to summary index."}],
            "resultCount": 0,
        }
        journal = {"jobs": []}
        record = {
            "kind": "saved_search",
            "label": name,
            "sid": "empty-summary-writer",
            "request_bounds": request_bounds,
            "search_fingerprint": fingerprint(search),
            "expected_empty": True,
        }
        self.assertEqual(migration._read_job(journal, record), [])
        self.assertEqual(record["state"], "complete")
        api.jobs["empty-summary-writer"]["messages"] = [
            {"type": "INFO", "text": "Successfully wrote file to stash"}
        ]
        record["state"] = "running"
        self.assertEqual(migration._read_job(journal, record), [])
        api.jobs["empty-summary-writer"]["messages"] = [
            {"type": "WARN", "text": "another warning"}
        ]
        record["state"] = "running"
        with self.assertRaisesRegex(Refused, "warnings"):
            migration._read_job(journal, record)
        api.jobs["empty-summary-writer"]["messages"] = [
            {"type": "WARN", "text": "No results to summary index."}
        ]
        record["expected_empty"] = False
        with self.assertRaisesRegex(Refused, "warnings"):
            migration._read_job(journal, record)

    def test_read_job_waits_for_parsing_search_identity_then_requires_exact_done_search(
        self,
    ):
        api = FakeApi()
        migration = self.migration(api)
        query = "| makeresults | eval value=1"
        sid = "parsing-then-done"
        api.jobs[sid] = {
            "rows": [],
            "search": None,
            "request": {
                "search": query,
                "earliest_time": "0",
                "latest_time": "1000060",
            },
            "app": "splunk_adm",
            "owner": "admin",
            "dispatchState": "PARSING",
            "isDone": False,
        }
        original = api.request
        reads = 0

        def request(method, path, data=None, **kwargs):
            nonlocal reads
            if method == "GET" and path.endswith("/jobs/" + sid):
                reads += 1
                if reads > 1:
                    api.jobs[sid].update(
                        dispatchState="DONE", isDone=True, search=query
                    )
            return original(method, path, data, **kwargs)

        api.request = request
        record = {
            "kind": "search",
            "label": "adhoc",
            "state": "running",
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1000060"},
            "query_fingerprint": fingerprint(query),
        }
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}
        self.assertEqual(migration._read_job(journal, record), [])
        self.assertGreater(reads, 1)

    def test_read_job_refuses_nonempty_preexecution_search_mismatch(self):
        api = FakeApi()
        migration = self.migration(api)
        query = "| makeresults | eval value=1"
        sid = "parsing-mismatch"
        api.jobs[sid] = {
            "rows": [],
            "search": "| makeresults | eval value=malicious",
            "request": {"search": query, "earliest_time": "0", "latest_time": "1"},
            "app": "splunk_adm",
            "owner": "admin",
            "dispatchState": "PARSING",
            "isDone": False,
        }
        record = {
            "kind": "search",
            "label": "adhoc",
            "state": "running",
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1"},
            "query_fingerprint": fingerprint(query),
        }
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}
        with self.assertRaisesRegex(Refused, "journaled search query"):
            migration._read_job(journal, record)

    def test_read_job_refuses_terminal_missing_search_identity(self):
        api = FakeApi()
        migration = self.migration(api)
        query = "| makeresults"
        sid = "done-missing-search"
        api.jobs[sid] = {
            "rows": [],
            "search": None,
            "request": {"search": query, "earliest_time": "0", "latest_time": "1"},
            "app": "splunk_adm",
            "owner": "admin",
            "dispatchState": "DONE",
            "isDone": True,
        }
        record = {
            "kind": "search",
            "label": "adhoc",
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1"},
            "query_fingerprint": fingerprint(query),
        }
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}
        with self.assertRaisesRegex(Refused, "terminal search job"):
            migration._read_job(journal, record)

    def test_read_job_persists_and_enforces_preexecution_metadata_deadline(self):
        api = FakeApi()
        migration = self.migration(api)
        query = "| makeresults"
        sid = "parsing-timeout"
        api.jobs[sid] = {
            "rows": [],
            "search": None,
            "request": {"search": query, "earliest_time": "0", "latest_time": "1"},
            "app": "splunk_adm",
            "owner": "admin",
            "dispatchState": "PARSING",
            "isDone": False,
        }
        record = {
            "kind": "search",
            "label": "adhoc",
            "state": "running",
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1"},
            "query_fingerprint": fingerprint(query),
        }
        journal = {
            "jobs": [record],
            "origin": {"principal": {"username": "admin"}},
            "event_earliest": "0",
            "event_latest": "1",
        }
        with self.assertRaisesRegex(Uncertain, "deadline expired"):
            migration._read_job(journal, record)
        self.assertIn("metadata_wait_deadline", record)
        self.assertTrue(record["metadata_wait_timed_out"])
        self.assertGreaterEqual(record["metadata_wait_attempts"], 120)
        dispatches = sum(
            method == "POST" and path.endswith("/search/v2/jobs")
            for method, path, _ in api.calls
        )
        with self.assertRaisesRegex(Uncertain, "recorded SID"):
            migration._query(
                journal,
                query,
                None,
                None,
                label="adhoc",
            )
        self.assertEqual(
            dispatches,
            sum(
                method == "POST" and path.endswith("/search/v2/jobs")
                for method, path, _ in api.calls
            ),
        )
        api.jobs[sid].update(search=query, dispatchState="DONE", isDone=True)
        self.assertEqual(
            migration._query(journal, query, None, None, label="adhoc"), []
        )
        self.assertEqual(record["state"], "complete")
        self.assertEqual(
            dispatches,
            sum(
                method == "POST" and path.endswith("/search/v2/jobs")
                for method, path, _ in api.calls
            ),
        )

    def test_read_job_does_not_apply_metadata_deadline_after_search_is_available(self):
        api = FakeApi()
        migration = self.migration(api)
        query = "| makeresults"
        sid = "long-running-with-search"
        api.jobs[sid] = {
            "rows": [],
            "search": query,
            "request": {"search": query, "earliest_time": "0", "latest_time": "1"},
            "app": "splunk_adm",
            "owner": "admin",
            "dispatchState": "RUNNING",
            "isDone": False,
        }
        original = api.request
        reads = 0

        def request(method, path, data=None, **kwargs):
            nonlocal reads
            if method == "GET" and path.endswith("/jobs/" + sid):
                reads += 1
                if reads > 1:
                    api.jobs[sid].update(dispatchState="DONE", isDone=True)
            return original(method, path, data, **kwargs)

        api.request = request
        record = {
            "kind": "search",
            "label": "adhoc",
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1"},
            "query_fingerprint": fingerprint(query),
        }
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}
        self.assertEqual(migration._read_job(journal, record), [])
        self.assertGreater(reads, 1)

    def test_saved_search_identity_waits_for_missing_name_then_accepts_same_sid(self):
        api = FakeApi()
        migration = self.migration(api)
        name = "ADM - Network client history builder"
        query = api.searches[name]["search"]
        sid = "saved-name-late"
        api.jobs[sid] = {
            "rows": [],
            "search": query,
            "request": {"earliest_time": "0", "latest_time": "1"},
            "saved_search": False,
            "app": "splunk_adm",
            "owner": "splunk-system-user",
            "dispatchState": "PARSING",
            "isDone": False,
        }
        original = api.request
        reads = 0

        def request(method, path, data=None, **kwargs):
            nonlocal reads
            if method == "GET" and path.endswith("/jobs/" + sid):
                reads += 1
                if reads > 1:
                    api.jobs[sid].update(
                        savedsearch_name=name,
                        saved_search=True,
                        dispatchState="DONE",
                        isDone=True,
                    )
            return original(method, path, data, **kwargs)

        api.request = request
        record = {
            "kind": "saved_search",
            "label": name,
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1"},
            "search_fingerprint": fingerprint(query),
        }
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}
        self.assertEqual(migration._read_job(journal, record), [])
        self.assertGreater(reads, 1)

    def test_saved_search_wrong_name_or_search_refuses_before_metadata_wait(self):
        api = FakeApi()
        migration = self.migration(api)
        name = "ADM - Network client history builder"
        query = api.searches[name]["search"]
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}

        for field, value, message in (
            ("savedsearch_name", "wrong-name", "journaled saved search"),
            ("search", "| makeresults | eval malicious=1", "writer definition"),
        ):
            sid = "saved-invalid-" + field
            api.jobs[sid] = {
                "rows": [],
                "search": query,
                "request": {"earliest_time": "0", "latest_time": "1"},
                "saved_search": True,
                "app": "splunk_adm",
                "owner": "splunk-system-user",
                "dispatchState": "PARSING",
                "isDone": False,
            }
            api.jobs[sid][field] = value
            record = {
                "kind": "saved_search",
                "label": name,
                "sid": sid,
                "request_bounds": {"earliest_time": "0", "latest_time": "1"},
                "search_fingerprint": fingerprint(query),
            }
            with self.subTest(field=field), self.assertRaisesRegex(Refused, message):
                migration._read_job(journal, record)

    def test_false_saved_search_type_is_only_readiness_for_known_pre_execution_sid(
        self,
    ):
        for mode in (
            "terminal",
            "reconcile",
            "wrong_owner",
            "wrong_name",
            "wrong_search",
            "timeout_recover",
        ):
            with self.subTest(mode=mode):
                api = FakeApi()
                migration = self.migration(api)
                name = "ADM - Network client history builder"
                query = api.searches[name]["search"]
                sid = "saved-type-late"
                api.jobs[sid] = {
                    "rows": [],
                    "search": query,
                    "request": {"earliest_time": "0", "latest_time": "1"},
                    "saved_search": False,
                    "app": "splunk_adm",
                    "owner": "splunk-system-user",
                    "savedsearch_name": name,
                    "dispatchState": "PARSING",
                    "isDone": False,
                }
                record = {
                    "kind": "saved_search",
                    "label": name,
                    "sid": sid,
                    "request_bounds": {"earliest_time": "0", "latest_time": "1"},
                    "search_fingerprint": fingerprint(query),
                    "state": "running",
                }
                journal = {
                    "jobs": [record],
                    "origin": {"principal": {"username": "admin"}},
                }
                if mode == "terminal":
                    api.jobs[sid].update(dispatchState="DONE", isDone=True)
                elif mode == "wrong_owner":
                    api.jobs[sid]["owner"] = "other"
                elif mode == "wrong_name":
                    api.jobs[sid]["savedsearch_name"] = "other"
                elif mode == "wrong_search":
                    api.jobs[sid]["search"] = "| makeresults"
                if mode == "reconcile":
                    entry = api.request("GET", "/services/search/v2/jobs/" + sid)[
                        "entry"
                    ][0]
                    with self.assertRaises(Refused):
                        migration._validate_reconcile_identity(journal, record, entry)
                elif mode == "timeout_recover":
                    with self.assertRaises(Uncertain):
                        migration._read_job(journal, record)
                    self.assertTrue(record["metadata_wait_timed_out"])
                    api.jobs[sid].update(
                        saved_search=True, dispatchState="DONE", isDone=True
                    )
                    self.assertEqual(migration._read_job(journal, record), [])
                    self.assertFalse(
                        any(method == "POST" for method, _, _ in api.calls)
                    )
                else:
                    with self.assertRaises(Refused):
                        migration._read_job(journal, record)

    def test_saved_search_terminal_missing_name_refuses(self):
        api = FakeApi()
        migration = self.migration(api)
        name = "ADM - Network client history builder"
        query = api.searches[name]["search"]
        sid = "saved-terminal-no-name"
        api.jobs[sid] = {
            "rows": [],
            "search": query,
            "request": {"earliest_time": "0", "latest_time": "1"},
            "saved_search": True,
            "app": "splunk_adm",
            "owner": "splunk-system-user",
            "dispatchState": "DONE",
            "isDone": True,
        }
        record = {
            "kind": "saved_search",
            "label": name,
            "sid": sid,
            "request_bounds": {"earliest_time": "0", "latest_time": "1"},
            "search_fingerprint": fingerprint(query),
        }
        journal = {"jobs": [], "origin": {"principal": {"username": "admin"}}}
        with self.assertRaisesRegex(Refused, "terminal saved-search job"):
            migration._read_job(journal, record)

    def test_scheduled_empty_summary_warning_requires_bounded_empty_index_proof(self):
        api = FakeApi()
        migration = self.migration(api)
        anchor = 1_000_500
        sid = "scheduler__empty_conversation"
        api.jobs[sid] = {
            "rows": [],
            "savedsearch_name": "ADM - Conversation rollup v2",
            "label": "ADM - Conversation rollup v2",
            "saved_search": True,
            "request": {
                "index_earliest": "-10m@m",
                "index_latest": "-5m@m",
            },
            "searchEarliestTime": str(anchor - 24 * 60 * 60),
            "searchLatestTime": str(anchor + 15 * 60),
            "savedSearchLabel": '{"owner":"nobody","app":"splunk_adm","sharing":"app"}',
            "provenance": "scheduler",
            "app": "splunk_adm",
            "owner": "splunk-system-user",
            "messages": [{"type": "WARN", "text": "No results to summary index."}],
            "resultCount": 0,
        }
        api.scheduler_logs.append(
            {
                "sid": sid,
                "savedsearch_name": "ADM - Conversation rollup v2",
                "scheduled_time": str(anchor),
                "dispatch_time": str(anchor),
                "status": "success",
            }
        )
        migration.clock = lambda: anchor + 10
        journal = migration.prepare(anchor - 900, anchor - 600)
        journal["slices"] = []
        journal["cutover"] = {
            "started_at": anchor - 1000,
            "scheduled_streams": {},
        }
        migration._write_journal(journal)

        cycles = migration._scheduled_writer_cycles(
            "ADM - Conversation rollup v2",
            journal,
            lower_epoch=anchor - 1,
            upper_epoch=anchor + 1,
        )
        self.assertEqual(len(cycles), 1)
        self.assertTrue(cycles[0]["empty_summary_warning"])
        api.jobs[sid]["resultCount"] = 1
        with self.assertRaisesRegex(Refused, "observation boundary"):
            migration._scheduled_writer_cycles(
                "ADM - Conversation rollup v2",
                journal,
                lower_epoch=anchor - 1,
                upper_epoch=anchor + 1,
            )
        api.jobs[sid]["resultCount"] = 0
        cycle = {
            **cycles[0],
            "expected": {},
            "expected_fingerprint": fingerprint({}),
            "actual_fingerprint": fingerprint({}),
            "rows": 0,
            "empty_summary_proof": migration._assert_empty_summary_index_window(
                journal,
                "adm_summary_v2",
                "adm:conversation",
                anchor,
                anchor + 10,
                "test empty summary audit",
            ),
        }
        journal["cutover"]["scheduled_streams"] = {"conversation": {"cycles": [cycle]}}

        audit = migration._validate_migration_ingestion_window(
            journal, upper_bound=anchor + 10
        )

        self.assertEqual(audit["rows"], 0)
        self.assertEqual(len(audit["empty_summary_proofs"]), 1)
        self.assertEqual(
            cycle["empty_summary_proof"]["expected_rows"],
            cycle["empty_summary_proof"]["retained_rows"],
        )
        nonempty = migration._record_map(
            api._source_rows("adm:conversation"), "conversation"
        )
        api.persisted_rows = api._source_rows("adm:conversation")
        cycle["expected"] = nonempty
        with self.assertRaisesRegex(Refused, "empty output while source rows exist"):
            migration._validate_migration_ingestion_window(
                journal, upper_bound=anchor + 10
            )

    def test_empty_cycle_audit_allows_manifested_later_cycle_and_rejects_extra(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        manifested = {
            "rollup_id": "a" * 64,
            "records": "2",
            "adm_record": "conversation",
            "contract_version": "2",
            "source": "adm:conversation",
            "_indextime": 900_450,
        }
        api.persisted_rows = [manifested]

        proof = migration._assert_empty_summary_index_window(
            journal,
            "adm_summary_v2",
            "adm:conversation",
            900_300,
            900_600,
            "mixed empty and nonempty scheduled cycles",
            allowed_rollup_ids={manifested["rollup_id"]},
        )
        self.assertEqual(proof["retained_rows"], 0)
        self.assertEqual(proof["observed_manifest_rows"], 1)
        self.assertEqual(
            proof["allowed_manifest_fingerprint"],
            fingerprint([manifested["rollup_id"]]),
        )

        api.persisted_rows.append(
            {
                **manifested,
                "rollup_id": "b" * 64,
                "_indextime": 900_500,
            }
        )
        with self.assertRaisesRegex(Refused, "outside validated manifests"):
            migration._assert_empty_summary_index_window(
                journal,
                "adm_summary_v2",
                "adm:conversation",
                900_300,
                900_600,
                "mixed cycles with unexplained retained row",
                allowed_rollup_ids={manifested["rollup_id"]},
            )

    def test_scheduled_history_gap_is_durable_and_included_in_final_coverage(self):
        ahead = {
            **self.history_row(1200),
            "_key": "a" * 64,
            "event_fingerprint": "b" * 64,
        }
        earlier = {
            **self.history_row(1100),
            "_key": "c" * 64,
            "event_fingerprint": "d" * 64,
        }
        api = FakeApi(history_rows=[earlier, ahead])
        api.history_rows_by_bounds = {
            (900_000, 900_300): [earlier],
            (900_300, 900_360): [ahead],
        }
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        journal["slices"] = []
        journal["range"]["end"] = 900_300
        journal["cutover"] = {"started_at": 900_000, "mutations": []}
        migration._write_journal(journal)

        migration._stage_history_gap_before_first_cycle(journal, 900_360)

        saved = self.journal.read()
        self.assertEqual(
            [
                (item["start"], item["end"])
                for item in saved["cutover"]["history_bridge_slices"]
            ],
            [(900_300, 900_360)],
        )
        self.assertEqual(
            saved["cutover"]["history_bridge_slices"][0]["history"]["state"],
            "verified",
        )
        summary_gap = {
            "start": 900_000,
            "end": 900_300,
            "history": {"state": "pending"},
            "handoff_bridge": True,
        }
        saved["slices"].append(summary_gap)
        migration._write_journal(saved)
        migration._stage_history_slice(saved, summary_gap)
        saved = self.journal.read()
        coverage = migration._validate_history_coverage(
            saved, migration._interface()[0]
        )
        self.assertEqual(coverage["keys"], 2)
        self.assertEqual(
            {row["_key"] for row in api.collections["adm_network_client_history"]},
            {"a" * 64, "c" * 64},
        )

    def test_missing_final_history_cycle_gets_nonempty_tail_backfill(self):
        row = self.history_row(1500)
        api = FakeApi(history_rows=[row])
        api.history_rows_by_bounds = {
            (899_760, 900_360): [],
            (900_360, 900_420): [],
            (900_420, 900_480): [],
            (900_480, 900_540): [],
            (900_540, 900_600): [row],
        }
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        journal["slices"] = []
        journal["cutover"] = {
            "started_at": 900_000,
            "mutations": [],
            "scheduled_history": {
                "cycles": [
                    {
                        "sid": "scheduler__history_before_tail",
                        "index_bounds": [899_760, 900_360],
                        "event_bounds": {
                            "earliest_time": "0",
                            "latest_time": "901260",
                        },
                        "expected_receipts": {},
                        "expected_fingerprint": fingerprint({}),
                    }
                ],
                "observation_epoch": 900_600,
            },
        }
        migration._write_journal(journal)

        migration._stage_history_tail_through_summary(journal, 900_600)
        saved = self.journal.read()

        self.assertEqual(
            [
                (item["start"], item["end"])
                for item in saved["cutover"]["history_bridge_slices"]
            ],
            [
                (900_360, 900_420),
                (900_420, 900_480),
                (900_480, 900_540),
                (900_540, 900_600),
            ],
        )
        coverage = migration._validate_history_coverage(
            saved, migration._interface()[0]
        )
        self.assertEqual(coverage["keys"], 1)
        self.assertEqual(
            api.collections["adm_network_client_history"][0]["_key"], row["_key"]
        )

    def test_scheduled_history_new_key_and_receipt_revision_are_covered(self):
        api = FakeApi()
        baseline = self.history_row(1000)
        api.collections["adm_network_client_history"] = [
            {**baseline, "latest_received_time": "1000"}
        ]
        migration = self.migration(api)
        migration.clock = lambda: 1_001_000
        journal = migration.prepare(900_000, 900_300)
        journal["slices"] = []
        journal["cutover"] = {"started_at": 1_000_000, "mutations": []}
        self.journal.write(journal)

        first_anchor, second_anchor = 1_000_260, 1_000_560
        new_event = {
            **self.history_row(1200),
            "_key": "a" * 64,
            "event_fingerprint": "b" * 64,
            "native_id": "00:11:22:33:44:66",
        }
        first_bounds = (first_anchor - 600, first_anchor)
        second_bounds = (second_anchor - 600, second_anchor)
        api.history_rows_by_bounds = {
            first_bounds: [new_event],
            second_bounds: [
                {
                    **new_event,
                    "received_time": "1500",
                    "latest_received_time": "1500",
                }
            ],
        }
        api.collections["adm_network_client_history"].append(
            {**new_event, "received_time": "1200", "latest_received_time": "1500"}
        )
        for index, anchor in enumerate((first_anchor, second_anchor)):
            sid = f"scheduler__history_{index}"
            api.jobs[sid] = {
                "rows": [],
                "savedsearch_name": "ADM - Network client history builder",
                "label": "ADM - Network client history builder",
                "saved_search": True,
                "request": {
                    "earliest_time": "0",
                    "latest_time": "+15m",
                    "index_earliest": "-10m@m",
                    "index_latest": "@m",
                },
                "searchEarliestTime": None,
                "searchLatestTime": str(anchor + 900),
                "savedSearchLabel": '{"owner":"nobody","app":"splunk_adm","sharing":"app"}',
                "provenance": "scheduler",
                "app": "splunk_adm",
                "owner": "splunk-system-user",
            }
            api.scheduler_logs.append(
                {
                    "sid": sid,
                    "savedsearch_name": "ADM - Network client history builder",
                    "scheduled_time": str(anchor),
                    "dispatch_time": str(anchor),
                    "status": "success",
                }
            )

        cycles = migration._scheduled_history_cycles(
            journal, lower_epoch=1_000_000, upper_epoch=1_001_001
        )
        self.assertEqual(
            [cycle["index_bounds"] for cycle in cycles],
            [
                [first_bounds[0], first_bounds[1]],
                [second_bounds[0], second_bounds[1]],
            ],
        )
        migration._stage_scheduled_history_evidence(journal, cycles)
        journal["cutover"]["scheduled_history"]["observation_epoch"] = 1_001_000
        migration._write_journal(journal)

        coverage = migration._validate_history_coverage(
            journal, migration._interface()[0]
        )

        self.assertEqual(coverage["keys"], 1)
        retained = {
            row["_key"]: row for row in api.collections["adm_network_client_history"]
        }
        self.assertEqual(set(retained), {"e" * 64, "a" * 64})
        self.assertEqual(retained["a" * 64]["received_time"], "1200")
        self.assertEqual(retained["a" * 64]["latest_received_time"], "1500")
        self.assertNotIn("00:11:22:33:44:66", json.dumps(self.journal.read()))

    def test_scheduler_index_bounds_ignore_observed_event_extrema(self):
        entry = {
            "content": {
                "request": {
                    "index_earliest": "-10m@m",
                    "index_latest": "-5m@m",
                },
                # These are observed event-time extrema, not dispatch bounds.
                "indexEarliestTime": "1792174789",
                "indexLatestTime": "1792174790",
                "searchEarliestTime": "1792088700",
                "searchLatestTime": "1792176000",
            }
        }
        self.assertEqual(
            Migration._absolute_index_bounds(entry), (1792174500, 1792174800)
        )
        entry["content"]["searchLatestTime"] = "1792176001"
        self.assertIsNone(Migration._absolute_index_bounds(entry))

    def test_cutover_reads_candidate_only_from_a_safe_file_beside_the_journal(self):
        migration = self.migration()
        candidate = {"migration_id": "migration-test", "cutover_eligible": True}
        candidate_path = self.journal.path.with_suffix(".candidate.json")
        digest = self.journal.write_artifact(candidate_path, candidate)
        elsewhere = self.journal.path.with_name("elsewhere.json")
        self.journal.write_artifact(elsewhere, candidate)
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "migration-test",
            "phase": "coverage_validated",
            "origin_fingerprint": "origin",
            "interface_sha256": "interface",
            "candidate_path": str(elsewhere),
            "candidate_sha256": digest,
            "jobs": [],
        }
        self.journal.write(journal)
        migration._interface = lambda: ({}, "interface")
        candidate_path.unlink()
        candidate_path.symlink_to(elsewhere)
        with self.assertRaisesRegex(Refused, "candidate evidence is unavailable"):
            migration.cutover()

    def test_cutover_reloads_mutation_from_durable_journal_after_catchup(self):
        migration = self.migration()
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "migration-test",
            "phase": "coverage_validated",
            "origin_fingerprint": "origin",
            "interface_sha256": "interface",
            "candidate_cutover_eligible": True,
            "jobs": [],
            "cutover": None,
        }
        candidate = {
            "migration_id": "migration-test",
            "interface_sha256": "interface",
            "origin_fingerprint": "origin",
            "cutover_eligible": True,
            "scenario": {},
            "scenario_sha256": fingerprint({}),
        }
        candidate_path = self.journal.path.with_suffix(".candidate.json")
        journal["candidate_path"] = str(candidate_path)
        journal["candidate_sha256"] = self.journal.write_artifact(
            candidate_path, candidate
        )
        self.journal.write(journal)
        mutations = [
            {
                "id": "pause",
                "kind": "saved_search",
                "state": "pending",
                "drain_after": True,
            },
            {"id": "enable", "kind": "macro_definition", "state": "pending"},
        ]
        applied = []

        def apply(current, mutation):
            mutation["state"] = "applied"
            applied.append(mutation["id"])
            migration._write_journal(current)

        def catch_up(current, _scenario):
            # Model validation replacing the journal object on disk.
            current["cutover"]["catchup_marker"] = True
            migration._write_journal(current)

        migration._interface = lambda: ({}, "interface")
        migration._build_cutover_mutations = lambda *_: mutations
        migration._assert_origin_unchanged = lambda *_: None
        migration._assert_cutover_origin_compatible = lambda *_: None
        migration._apply_mutation = apply
        migration._drain_legacy_writer = lambda *_: None
        migration._catch_up_after_pause = catch_up

        def bridge(current, *_):
            current["cutover"]["scheduled_cycle_bounds"] = {"start": 900_300}
            migration._write_journal(current)
            return True

        migration._bridge_to_first_scheduled_cycle = bridge
        migration._public_selector_smoke = lambda *_args, **_kwargs: []
        result = migration.cutover()
        self.assertEqual(result["status"], "cutover")
        stored = self.journal.read()
        self.assertEqual(applied, ["pause", "enable"])
        self.assertTrue(stored["cutover"]["catchup_marker"])
        self.assertEqual(
            [item["state"] for item in stored["cutover"]["mutations"]],
            ["applied", "applied"],
        )

    def test_revalidating_applied_writer_preserves_activation_epoch(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, _ = migration._interface()
        origin = migration.snapshot()
        writer = next(
            mutation
            for mutation in migration._build_cutover_mutations(
                {"origin": origin}, interface
            )
            if mutation.get("name") == "ADM - Conversation rollup v2"
            and mutation.get("field") == "disabled"
        )
        journal = {"jobs": []}
        migration._apply_mutation(journal, writer)
        activation_epoch = writer["verified_at"]
        migration.clock = lambda: activation_epoch + 600

        migration._apply_mutation(journal, writer)

        self.assertEqual(writer["verified_at"], activation_epoch)
        self.assertEqual(writer["revalidated_at"], activation_epoch + 600)

    def test_result_artifact_cache_reuses_verified_evidence_without_dispatch(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        query = "| makeresults | fields count"
        expected = migration._query(journal, query, None, None, label="artifact cache")
        record = next(
            x for x in self.journal.read()["jobs"] if x["label"] == "artifact cache"
        )
        self.assertNotIn("result_rows", record)
        self.assertIn("result_artifact", record)
        count = len(api.calls)
        self.assertEqual(
            migration._query(
                self.journal.read(), query, None, None, label="artifact cache"
            ),
            expected,
        )
        self.assertEqual(len(api.calls), count)
        path = migration._result_artifact_path(journal, record)
        path.write_bytes(b"corrupt")
        with self.assertRaises(Refused):
            migration._query(
                self.journal.read(), query, None, None, label="artifact cache"
            )
        self.assertEqual(len(api.calls), count)

    def test_result_artifact_crash_reuses_sid_and_immutable_orphan(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        query = "| makeresults | fields count"
        original = self.journal.write

        def interrupt(value):
            if any(
                x.get("label") == "artifact crash" and x.get("result_artifact")
                for x in value["jobs"]
            ):
                raise OSError("journal replacement interrupted")
            original(value)

        with patch.object(self.journal, "write", side_effect=interrupt):
            with self.assertRaises(OSError):
                migration._query(journal, query, None, None, label="artifact crash")
        retained = self.journal.read()
        record = next(x for x in retained["jobs"] if x["label"] == "artifact crash")
        self.assertEqual(record["state"], "running")
        self.assertTrue(record["sid"])
        path = migration._result_artifact_path(retained, record)
        self.assertTrue(path.exists())
        prior = path.read_bytes()
        posts = sum(method == "POST" for method, _, _ in api.calls)
        migration._query(retained, query, None, None, label="artifact crash")
        self.assertEqual(sum(method == "POST" for method, _, _ in api.calls), posts)
        self.assertEqual(path.read_bytes(), prior)

    def test_result_artifact_write_failure_keeps_running_sid(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        with patch.object(
            self.journal, "write_artifact", side_effect=OSError("disk full")
        ):
            with self.assertRaises(Refused):
                migration._query(
                    journal, "| makeresults", None, None, label="artifact failure"
                )
        record = next(
            x for x in self.journal.read()["jobs"] if x["label"] == "artifact failure"
        )
        self.assertEqual(record["state"], "running")
        self.assertTrue(record["sid"])

    def test_result_artifact_permissions_symlink_and_budget_fail_closed(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._query(journal, "| makeresults", None, None, label="artifact safety")
        record = next(
            x for x in self.journal.read()["jobs"] if x["label"] == "artifact safety"
        )
        path = migration._result_artifact_path(journal, record)
        path.chmod(0o644)
        with self.assertRaises(Refused):
            migration._cached_result_rows(journal, record)
        path.chmod(0o600)
        original = path.with_suffix(".retained")
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaises(Refused):
            migration._cached_result_rows(journal, record)
        path.unlink()
        original.rename(path)
        with patch("tools.cisco_contract_migration.MAX_RESULT_EVIDENCE_BYTES", 1):
            with self.assertRaises(Refused):
                migration._query(
                    self.journal.read(),
                    "| makeresults",
                    None,
                    None,
                    label="budget failure",
                )

    def test_result_artifact_fifo_is_rejected_without_blocking(self):
        fifo = self.journal.path.with_name("result-fifo")
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(Refused):
            Migration._read_result_artifact_file(fifo)

    def test_public_surface_scenario_rejects_macro_injection(self):
        with self.assertRaises(Refused):
            Migration._scenario_query(
                {
                    "invoke": '| `adm_find_v2("{{query}}")`',
                    "read_only": True,
                },
                {"query": 'x") | delete index=foo | search ("'},
            )

    def test_evidence_manifest_separates_conversation_and_traffic_fields(self):
        interface, _ = Migration._interface()
        surface = next(
            x
            for x in interface["public_surfaces"]
            if x["surface"] == "evidence_drilldown"
        )
        self.assertNotIn("traffic_evidence", surface)
        scenario = {"client_ip": "192.0.2.1", "server_ip": "192.0.2.2"}
        row = {
            "_time": "1",
            "scope": "test",
            **scenario,
            "server_port": "443",
            "transport": "tcp",
        }
        for version in ("v1", "v2"):
            Migration._validate_surface_predicates([row], surface[version], scenario)
        traffic = surface["traffic_v2"]
        self.assertIn("rollup_id", traffic["required_fields"])
        for optional in (
            "source_mac",
            "destination_mac",
            "raw_sampling",
            "traffic_observation_id",
        ):
            self.assertNotIn(optional, traffic["required_fields"])

    def test_public_schema_accepts_captured_mixed_row_types(self):
        interface, _ = Migration._interface()
        surfaces = {x["surface"]: x for x in interface["public_surfaces"]}
        fixtures = Path(__file__).resolve().parents[1] / "fixtures"
        for name, files in {
            "graph": ("demo-networking-aci", "demo-networking-nxos"),
            "topology": ("demo-networking-topology",),
            "catalog": ("demo-networking-catalog",),
        }.items():
            for filename in files:
                with self.subTest(filename=filename):
                    rows = json.loads((fixtures / (filename + ".json")).read_text())[
                        "rows"
                    ]
                    Migration._validate_surface_predicates(
                        rows, surfaces[name]["v2"], {}
                    )
        find = json.loads((fixtures / "demo-networking-find.json").read_text())
        for key, version in (
            ("queries", "v2"),
            ("network_client_queries", "network_client_v2"),
        ):
            for query in find[key]:
                if query["rows"]:
                    Migration._validate_surface_predicates(
                        query["rows"], surfaces["find"][version], {}
                    )

    def test_topology_missing_serial_remains_unscoped_diagnostic_evidence(self):
        interface, _ = Migration._interface()
        contract = next(
            x for x in interface["public_surfaces"] if x["surface"] == "topology"
        )["v2"]
        rows = [
            {
                "row_type": "device",
                "device_id": prefix + ":endpoint-fallback",
                "device_authority": "collector",
                "device_kind": kind,
                "mapping_status": "incomplete_identity",
            }
            for prefix, kind in (("nxos", "switch"), ("ftd", "firewall"))
        ]
        Migration._validate_surface_predicates(rows, contract, {})
        for changes in (
            {"scope": "invented"},
            {"cluster": "invented"},
            {"native_device_id": "invented"},
            {"mapping_status": "mapped"},
        ):
            with self.subTest(changes=changes), self.assertRaises(Refused):
                Migration._validate_surface_predicates(
                    [{**rows[0], **changes}], contract, {}
                )
        with self.assertRaises(Refused):
            Migration._validate_surface_predicates([rows[0], rows[0]], contract, {})

    def test_row_type_contract_rejects_unknown_types_and_missing_identity(self):
        contract = {
            "required_fields": ["row_type"],
            "required_fields_by_row_type": {
                "meta": [],
                "node": ["id"],
                "edge": ["source", "target"],
            },
            "predicates": [],
        }
        Migration._validate_surface_predicates(
            [{"row_type": "meta"}, {"row_type": "node", "id": "n"}], contract, {}
        )
        for row in (
            {"row_type": "other"},
            {"row_type": "node"},
            {"row_type": "edge", "source": "n"},
        ):
            with self.subTest(row=row), self.assertRaises(Refused):
                Migration._validate_surface_predicates([row], contract, {})

    def test_nested_traffic_contract_rejects_invented_scope_and_bad_arrays(self):
        contract = {
            "required_fields": ["traffic_observations"],
            "predicates": [
                {
                    "field": "traffic_observations",
                    "operator": "traffic_observation_contract",
                    "value": True,
                }
            ],
        }
        observation = {
            "source": "stream_ipfix",
            "source_authority": "exporter",
            "mapping_status": "mapped",
            "scope": "campus",
            "cluster": "cluster",
            "domain_kind": "exporter",
            "routing_domain": "",
            "counter_semantics": "unknown",
            "metrics_authoritative": "0",
        }
        Migration._validate_surface_predicates(
            [{"traffic_observations": json.dumps([observation])}], contract, {}
        )
        for bad in (
            [{**observation, "mapping_status": "unmapped"}],
            [{**observation, "source_authority": ""}],
            [{**observation, "metrics_authoritative": "1"}],
            [{**observation, "counter_semantics": "arbitrary"}],
            [{k: v for k, v in observation.items() if k != "counter_semantics"}],
            [{k: v for k, v in observation.items() if k != "metrics_authoritative"}],
            [[observation]],
            ["invented"],
            [],
        ):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                Migration._validate_surface_predicates(
                    [{"traffic_observations": json.dumps(bad)}], contract, {}
                )

    def test_graph_identity_predicate_requires_unique_client_authority_tuple(self):
        surface = {
            "required_fields": ["row_type", "id", "endpoint_kind"],
            "predicates": [
                {
                    "field": "node_id",
                    "operator": "unique_for_source_authority_native",
                    "value": True,
                }
            ],
        }
        rows = [
            {
                "row_type": "node",
                "id": "client-a",
                "endpoint_kind": "network_client",
                "attr_source": "meraki_association",
                "attr_source_authority": "org/network",
                "attr_native_id": "00:11:22:33:44:55",
            },
            {
                "row_type": "node",
                "id": "client-b",
                "endpoint_kind": "network_client",
                "attr_source": "meraki_association",
                "attr_source_authority": "org/network",
                "attr_native_id": "00:11:22:33:44:55",
            },
        ]
        with self.assertRaises(Refused):
            Migration._validate_surface_predicates(rows, surface, {})

    def test_topology_mapping_and_endpoint_predicates_allow_unmapped_inventory(self):
        surface = {
            "required_fields": ["row_type", "mapping_status"],
            "predicates": [
                {
                    "field": "mapping_status",
                    "operator": "topology_mapping_scope_consistency",
                    "value": {
                        "device_allowed_statuses": [
                            "mapped",
                            "unmapped",
                            "ambiguous",
                            "incomplete_identity",
                        ],
                        "mapped_device_requires_one_scope_and_cluster": True,
                        "unmapped_or_ambiguous_device_requires_null_scope_and_cluster": True,
                        "link_requires_mapping_status": "mapped",
                        "link_requires_existing_device_endpoints": True,
                    },
                },
                {
                    "field": "link_endpoints",
                    "operator": "must_resolve_to_device_ids",
                    "value": True,
                },
            ],
        }
        rows = [
            {
                "row_type": "device",
                "device_id": "device-a",
                "mapping_status": "mapped",
                "scope": "prod",
                "cluster": "cluster-a",
            },
            {
                "row_type": "device",
                "device_id": "device-b",
                "mapping_status": "unmapped",
                "scope": None,
                "cluster": None,
            },
            {
                "row_type": "link",
                "mapping_status": "mapped",
                "a_device": "device-a",
                "b_device": "device-b",
            },
        ]
        Migration._validate_surface_predicates(rows, surface, {})
        rows[-1]["b_device"] = "missing"
        with self.assertRaises(Refused):
            Migration._validate_surface_predicates(rows, surface, {})

    def test_cutover_and_rollback_smoke_use_public_wrapper_queries(self):
        migration = self.migration()
        interface, _ = migration._interface()
        scenario = {
            "client_ip": "10.61.0.20",
            "cluster": "pilot-a",
            "environment": "prod",
            "namespace": "checkout",
            "query": "10.61.0.20",
            "server_ip": "10.50.0.20",
            "server_port": "443",
            "service": "checkout",
            "transport": "tcp",
        }
        executed = []

        def query(_journal, query, *_args, **_kwargs):
            executed.append(query)
            return []

        migration._query = query
        migration._validate_surface_predicates = lambda *_args: None
        for phase in ("public_after_invoke", "rollback_before_invoke"):
            evidence = migration._public_selector_smoke(
                {"event_earliest": "0", "event_latest": "1"},
                interface,
                scenario,
                phase=phase,
            )
            self.assertEqual(
                {item["surface"] for item in evidence},
                {
                    "graph",
                    "catalog",
                    "find",
                    "health",
                    "evidence_drilldown",
                    "topology",
                },
            )
        self.assertEqual(sum("adm_traffic_evidence_v2" in item for item in executed), 2)
        self.assertTrue(any("adm_graph_v2" in item for item in executed))
        self.assertTrue(
            any(
                "adm_graph(" in item and "adm_graph_v2" not in item for item in executed
            )
        )

    def test_prepare_records_config_and_backfill_validates_both_streams(self):
        migration = self.migration()
        migration.prepare(900_000, 900_300)
        result = migration.backfill()
        self.assertEqual(result, {"status": "backfilled", "slices": 1})
        validated = migration.validate()
        self.assertEqual(validated["status"], "coverage_validated")
        self.assertEqual(validated["coverage"]["conversation"]["event_records"], 6)
        self.assertEqual(validated["coverage"]["traffic"]["event_records"], 1)
        self.assertEqual(migration.journal.read()["phase"], "coverage_validated")
        self.assertEqual(
            migration.journal.read()["slices"][0]["history"]["state"], "verified"
        )
        self.assertEqual(migration.journal.read()["catalog"]["state"], "verified")
        conversation = migration.journal.read()["slices"][0]["streams"]["conversation"]
        self.assertEqual(
            {value["adm_record"] for value in conversation["expected"].values()},
            {"conversation", "hubble_xlate", "hubble_l7"},
        )

    def test_search_transport_namespace_and_bounds_match_job_metadata(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        posts = [
            (path, json_body)
            for method, path, json_body in api.transports
            if method == "POST"
        ]
        self.assertTrue(posts)
        self.assertTrue(all(not json_body for _, json_body in posts))
        self.assertTrue(
            all(
                path == "/servicesNS/nobody/splunk_adm/search/v2/jobs"
                or path.endswith("/dispatch")
                or ("/saved/searches/" in path and not path.endswith("/dispatch"))
                for path, _ in posts
            )
        )
        journal = self.journal.read()
        self.assertEqual(journal["event_latest"], "1000900")
        for job in journal["jobs"]:
            bounds = job.get("request_bounds", {})
            if bounds:
                self.assertNotIn("+15m", bounds.values())
                self.assertEqual(bounds["latest_time"], "1000900")

    def test_summary_visibility_is_polled_without_raw_index_time_bounds(self):
        api = FakeApi(delayed_visibility=2)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        self.assertGreaterEqual(api.actual_query_count, 4)

    def test_reconcile_rejects_sid_from_another_raw_slice(self):
        api = FakeApi(unknown_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Uncertain) as caught:
            migration.backfill()
        if api.searches["ADM - Conversation rollup v2"]["disabled"] != "1":
            self.fail(
                f"restore failed: {caught.exception}; {self.journal.read().get('temporary_manual_executions')}"
            )
        writer = next(
            job for job in self.journal.read()["jobs"] if job["kind"] == "saved_search"
        )
        for sid, changes in (
            ("wrong-slice", {"index_earliest": "899700"}),
            ("wrong-app", {"app": "other_app"}),
            ("wrong-owner", {"owner": "admin"}),
        ):
            with self.subTest(sid=sid):
                api.jobs[sid] = {
                    "rows": [],
                    "savedsearch_name": writer["label"],
                    "search": api.searches[writer["label"]]["search"],
                    "request": {
                        **writer["request_bounds"],
                        **{
                            key: value
                            for key, value in changes.items()
                            if key in writer["request_bounds"]
                        },
                    },
                    "saved_search": True,
                    "app": changes.get("app", "splunk_adm"),
                    "owner": changes.get("owner", "splunk-system-user"),
                }
                with self.assertRaises(Refused):
                    migration.reconcile(sid)

    def test_reconcile_does_not_adopt_unidentified_or_wrong_search_sid(self):
        api = FakeApi(unknown_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Uncertain):
            migration.backfill()
        before = self.journal.read()
        writer = next(job for job in before["jobs"] if job["kind"] == "saved_search")
        query = api.searches[writer["label"]]["search"]
        for sid, changes in (
            ("unidentified", {"savedsearch_name": None, "label": None}),
            ("wrong-search", {"search": "| makeresults | eval wrong=1"}),
        ):
            with self.subTest(sid=sid):
                api.jobs[sid] = {
                    "rows": [],
                    "savedsearch_name": writer["label"],
                    "label": writer["label"],
                    "search": query,
                    "request": writer["request_bounds"],
                    "saved_search": True,
                    "app": "splunk_adm",
                    "owner": "splunk-system-user",
                    **changes,
                }
                if sid == "unidentified":
                    api.jobs[sid].pop("label", None)
                with self.assertRaises(Refused):
                    migration.reconcile(sid)
                after = self.journal.read()
                self.assertEqual(after["jobs"], before["jobs"])

    def test_mapping_and_transitive_macro_drift_refuse_resume(self):
        for mutation in ("profile", "macro"):
            with self.subTest(mutation=mutation):
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                if mutation == "profile":
                    api.collections["adm_network_source_scope"].append(
                        {"_key": "new-profile", "profile": "catalyst_sdwan_ipfix"}
                    )
                else:
                    api.macros["adm_flow_enrich_v2"] += " | eval drift=1"
                with self.assertRaises(Refused):
                    migration.backfill()

    def test_profile_change_between_staged_writer_dispatches_refuses_next_write(self):
        api = FakeApi(mutate_profile_after_dispatch=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_600)
        with self.assertRaises(Refused):
            migration.backfill()
        self.assertEqual(sum(path.endswith("/dispatch") for _, path, _ in api.calls), 1)

    def test_live_builder_writes_do_not_block_backfill_or_validation(self):
        api = FakeApi(live_builder_writes=True)
        api.builder_cycle()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        api.builder_cycle()
        self.assertEqual(migration.backfill(), {"status": "backfilled", "slices": 1})
        api.builder_cycle()
        self.assertEqual(migration.validate()["status"], "coverage_validated")
        self.assertGreater(len(api.collections["adm_ip_identity"]), 3)

    def test_live_builder_writes_do_not_block_rollback(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, interface_hash = migration._interface()
        origin = migration.snapshot()
        mutations = migration._build_cutover_mutations({"origin": origin}, interface)
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "live-builder-rollback",
            "interface_sha256": interface_hash,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "phase": "cutover_in_progress",
            "cutover": {"state": "in_progress", "mutations": mutations, "scenario": {}},
            "jobs": [],
        }
        migration._write_journal(journal)
        migration._apply_mutation(journal, mutations[0])
        migration._public_selector_smoke = lambda *_args, **_kwargs: []
        api.builder_cycle()
        api.builder_cycle()

        self.assertEqual(migration.rollback()["status"], "rolled_back")
        self.assertEqual(api.macros["adm_data_contract_version"], "1")

    def test_operator_mapping_and_lookup_binding_drift_still_refuse(self):
        for drift in ("observer_scope", "cilium_settings", "identity_binding"):
            with self.subTest(drift=drift):
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                if drift == "observer_scope":
                    api.collections["adm_observer_scope"].append(
                        {"_key": "new-observer", "observer": "apic-2"}
                    )
                elif drift == "cilium_settings":
                    api.collections["adm_cilium_cluster_settings"].append(
                        {"_key": "new-cluster", "lb_mode": "dsr"}
                    )
                else:
                    api.transforms["adm_ip_identity"]["collection"] = "other"
                with self.assertRaises(Refused):
                    migration.backfill()
                self.assertFalse(
                    any(path.endswith("/dispatch") for _, path, _ in api.calls)
                )
                self.journal.path.unlink()

    def test_unreadable_live_builder_collection_refuses(self):
        api = FakeApi()
        api.collections["adm_ip_identity"] = [{"ip": "198.51.100.1"}]
        with self.assertRaisesRegex(Refused, "adm_ip_identity collection read"):
            self.migration(api).prepare(900_000, 900_300)

    def test_resume_does_not_reread_expired_forward_writer_jobs(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        journal = self.journal.read()
        writers = [
            job
            for job in journal["jobs"]
            if job["kind"] == "saved_search" and job["state"] == "complete"
        ]
        self.assertTrue(writers)
        for job in writers:
            self.assertIs(job["persist_result_rows"], False)
            self.assertNotIn("result_artifact", job)
            self.assertNotIn("result_rows", job)
            self.assertEqual(
                job["result_digest"], hashlib.sha256(canonical([])).hexdigest()
            )
        for job in writers:
            api.jobs.pop(job["sid"])
        for stream in journal["slices"][0]["streams"].values():
            stream["state"] = "running"
        migration._write_journal(journal)
        api.calls.clear()

        self.assertEqual(migration.backfill(), {"status": "backfilled", "slices": 1})
        self.assertFalse(
            any(job["sid"] in path for _, path, _ in api.calls for job in writers)
        )
        with self.assertRaisesRegex(Refused, "did not retain"):
            migration._completed_job_rows(self.journal.read(), writers[0])

    def test_rollback_evidence_has_its_own_budget(self):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._query(journal, "| makeresults", None, None, label="forward")
        with patch("tools.cisco_contract_migration.MAX_RESULT_EVIDENCE_BYTES", 1):
            with self.assertRaisesRegex(Refused, "256 MiB budget"):
                migration._query(
                    self.journal.read(), "| makeresults", None, None, label="more"
                )
            journal = self.journal.read()
            journal["phase"] = "rollback_in_progress"
            migration._write_journal(journal)
            migration._query(journal, "| makeresults", None, None, label="recovery")
            record = next(
                x for x in self.journal.read()["jobs"] if x["label"] == "recovery"
            )
            self.assertTrue(record["recovery_evidence"])
            self.assertIn("result_artifact", record)
            self.assertIn(
                ".result-recovery-",
                str(migration._result_artifact_path(journal, record)),
            )
            with patch("tools.cisco_contract_migration.MAX_RECOVERY_EVIDENCE_BYTES", 1):
                with self.assertRaisesRegex(Refused, "256 MiB budget"):
                    migration._query(
                        self.journal.read(), "| makeresults", None, None, label="r2"
                    )

    def test_v1_recovery_writer_rows_are_retained_for_resume(self):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        origin = migration.snapshot()
        interface, _ = migration._interface()
        cutover_mutations = migration._build_cutover_mutations(
            {"origin": origin}, interface
        )
        for selector in interface["activation"]["cutover_selectors"]:
            api.macros[selector["name"]] = selector["after"]
        v1_restore = next(
            item
            for item in cutover_mutations
            if item.get("name") == "ADM - Conversation rollup"
            and item.get("field") == "disabled"
        )
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "rollback-writer-rows",
            "phase": "rollback_in_progress",
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "cutover": {"mutations": cutover_mutations},
            "rollback": {
                "mutations": [
                    {
                        **v1_restore,
                        "before": v1_restore["after"],
                        "after": v1_restore["before"],
                        "state": "applied",
                        "verified_at": 999_600,
                    }
                ]
            },
            "created_at": 900_000,
            "event_earliest": "0",
            "event_latest": "1000000",
            "jobs": [],
        }
        migration._write_journal(journal)
        bounds = {
            "earliest_time": "900000",
            "latest_time": "900900",
            "index_earliest": "900000",
            "index_latest": "900300",
        }

        rows = migration._dispatch_writer(
            journal,
            "ADM - Conversation rollup",
            bounds,
            label="V1 rollback recovery dispatch",
            intent_fingerprint="rollback-intent",
            persist_result_rows=True,
        )

        self.assertEqual(rows, [])
        record = self.journal.read()["jobs"][0]
        self.assertTrue(record["persist_result_rows"])
        self.assertTrue(record["recovery_evidence"])
        self.assertIn("result_artifact", record)
        self.assertNotIn("result_digest", record)
        api.jobs.pop(record["sid"])
        self.assertEqual(migration._completed_job_rows(self.journal.read(), record), [])
        self.assertEqual(
            migration._dispatch_writer(
                self.journal.read(),
                "ADM - Conversation rollup",
                bounds,
                label="V1 rollback recovery dispatch",
                intent_fingerprint="rollback-intent",
                persist_result_rows=True,
            ),
            [],
        )

    def test_enabled_origin_rollback_refuses_before_resume_near_seven_days(self):
        window = 7 * 24 * 3600
        step = 300
        largest_ok = max(
            gap
            for gap in range(0, window, step)
            if rollback_recovery_horizon_seconds(gap) <= window
        )
        self.assertLess(largest_ok, window - 3600)
        for age, refused in (
            (largest_ok, False),
            (largest_ok + step, True),
            (window - 1800, True),
            (window - 3600, True),
        ):
            with self.subTest(age=age):
                api = FakeApi()
                api.searches["ADM - Conversation rollup"]["disabled"] = "0"
                migration = self.migration(api)
                interface, interface_hash = migration._interface()
                origin = migration.snapshot()
                mutations = migration._build_cutover_mutations(
                    {"origin": origin}, interface
                )
                pre_end = 1_000_000 - age
                journal = {
                    "schema": JOURNAL_SCHEMA,
                    "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
                    "migration_id": "rollback-age-bound",
                    "interface_sha256": interface_hash,
                    "origin": origin,
                    "origin_fingerprint": fingerprint(origin),
                    "phase": "cutover",
                    "cutover": {
                        "state": "complete",
                        "started_at": pre_end,
                        "mutations": mutations,
                        "scenario": {},
                    },
                    "created_at": pre_end - 300,
                    "v1_pre_pause": {
                        "index_bounds": [pre_end - 300, pre_end],
                        "event_bounds": {
                            "earliest_time": str(pre_end - 86400),
                            "latest_time": str(pre_end + 900),
                        },
                        "expected": {},
                        "expected_fingerprint": fingerprint({}),
                    },
                    "jobs": [],
                }
                migration._write_journal(journal)
                posts_before = sum(method == "POST" for method, _, _ in api.calls)
                if refused:
                    with self.assertRaisesRegex(Refused, "seven-day bound"):
                        migration.rollback()
                    self.assertEqual(self.journal.read()["phase"], "cutover")
                    self.assertNotIn("rollback", self.journal.read())
                    self.assertEqual(
                        sum(method == "POST" for method, _, _ in api.calls),
                        posts_before,
                    )
                else:
                    try:
                        migration.rollback()
                    except Refused as exc:
                        self.assertNotIn("seven-day bound", str(exc))
                    self.assertEqual(
                        self.journal.read()["phase"], "rollback_in_progress"
                    )
                self.journal.path.unlink()

    def _enabled_origin_rollback_journal(self, api, migration, *, phase, v1_state):
        interface, interface_hash = migration._interface()
        origin = migration.snapshot()
        forward = migration._build_cutover_mutations({"origin": origin}, interface)
        pre_end = 1_000_000 - 8 * 24 * 3600
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "rollback-state-bound",
            "interface_sha256": interface_hash,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "phase": phase,
            "cutover": {
                "state": "complete",
                "started_at": pre_end,
                "mutations": forward,
                "scenario": {},
            },
            "created_at": pre_end - 300,
            "v1_pre_pause": {
                "index_bounds": [pre_end - 300, pre_end],
                "event_bounds": {
                    "earliest_time": str(pre_end - 86400),
                    "latest_time": str(pre_end + 900),
                },
                "expected": {},
                "expected_fingerprint": fingerprint({}),
            },
            "jobs": [],
        }
        if phase == "rollback_in_progress":
            reverse = []
            for mutation in reversed(forward):
                item = {
                    key: mutation[key]
                    for key in ("id", "kind", "name", "rest_target", "field", "acl")
                    if key in mutation
                }
                item.update(
                    before=mutation["after"],
                    after=mutation["before"],
                    state=(
                        v1_state
                        if mutation["name"] == "ADM - Conversation rollup"
                        else "pending"
                    ),
                    drain_after=False,
                )
                reverse.append(item)
            journal["rollback"] = {
                "state": "in_progress",
                "started_at": 999_000,
                "mutations": reverse,
            }
        migration._write_journal(journal)
        return journal

    def test_rollback_preflight_refusal_does_not_claim_a_clean_state_when_in_progress(
        self,
    ):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        self._enabled_origin_rollback_journal(
            api, migration, phase="rollback_in_progress", v1_state="pending"
        )
        api.searches["ADM - Conversation rollup"]["disabled"] = "1"
        with self.assertRaisesRegex(Refused, "stays rollback_in_progress") as caught:
            migration.rollback()
        self.assertNotIn("nothing was changed", str(caught.exception))

    def test_rollback_preflight_defers_to_reconcile_for_possibly_resumed_v1(self):
        for state in ("request_pending", "request_unknown", "readback_failed"):
            with self.subTest(state=state):
                api = FakeApi()
                api.searches["ADM - Conversation rollup"]["disabled"] = "0"
                migration = self.migration(api)
                self._enabled_origin_rollback_journal(
                    api, migration, phase="rollback_in_progress", v1_state=state
                )
                try:
                    migration.rollback()
                except Refused as exc:
                    self.assertNotIn("seven-day bound", str(exc))
                v1 = next(
                    item
                    for item in self.journal.read()["rollback"]["mutations"]
                    if item["name"] == "ADM - Conversation rollup"
                )
                self.assertEqual(v1["state"], "applied")
                self.journal.path.unlink()

    def test_rollback_preflight_treats_rejected_v1_resume_as_still_paused(self):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        self._enabled_origin_rollback_journal(
            api, migration, phase="rollback_in_progress", v1_state="rejected"
        )
        api.searches["ADM - Conversation rollup"]["disabled"] = "1"
        with self.assertRaisesRegex(Refused, "seven-day bound"):
            migration.rollback()

    def test_rollback_preflight_defers_to_reconcile_when_rejected_v1_is_live_enabled(
        self,
    ):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        self._enabled_origin_rollback_journal(
            api, migration, phase="rollback_in_progress", v1_state="rejected"
        )
        try:
            migration.rollback()
        except Refused as exc:
            self.assertNotIn("seven-day bound", str(exc))
        v1 = next(
            item
            for item in self.journal.read()["rollback"]["mutations"]
            if item["name"] == "ADM - Conversation rollup"
        )
        self.assertEqual(v1["state"], "applied")

    def test_journal_records_and_enforces_the_summary_canonicalizer_version(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        self.assertEqual(
            self.journal.read()["canonicalizer_version"],
            SUMMARY_CANONICALIZER_VERSION,
        )
        for recorded in (None, SUMMARY_CANONICALIZER_VERSION - 1):
            with self.subTest(recorded=recorded):
                journal = self.journal.read()
                if recorded is None:
                    journal.pop("canonicalizer_version")
                else:
                    journal["canonicalizer_version"] = recorded
                self.journal.write(journal)
                with self.assertRaisesRegex(Refused, "summary canonicalizer version"):
                    migration.rollback()
                with self.assertRaisesRegex(Refused, "summary canonicalizer version"):
                    migration.prepare(900_000, 900_300)

    def test_validate_tolerates_identity_derived_encapsulation_change(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        api.source_overrides = {"conversation": {"encapsulation": "vxlan"}}

        self.assertEqual(migration.validate()["status"], "coverage_validated")

    def test_validate_still_refuses_genuine_source_drift(self):
        for override in (
            {"bytes_c2s": "9"},
            {"records": "4"},
            {"scope": "other-scope"},
            {"encapsulation": "vxlan", "direction_basis": "port_rule"},
        ):
            with self.subTest(override=override):
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                migration.backfill()
                api.source_overrides = {"conversation": override}
                with self.assertRaises(Refused):
                    migration.validate()
                self.journal.path.unlink()

    def test_stage_dispatch_tolerates_identity_change_before_writer_runs(self):
        api = FakeApi()
        api.source_overrides = {"conversation": {"encapsulation": "geneve"}}
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        original = FakeApi._source_rows
        with patch.object(
            FakeApi,
            "_source_rows",
            staticmethod(
                lambda source: [
                    {**row, "encapsulation": "vxlan"}
                    if source == "adm:conversation"
                    else row
                    for row in original(source)
                ]
            ),
        ):
            self.assertEqual(
                migration.backfill(), {"status": "backfilled", "slices": 1}
            )

    def test_v2_manifest_ignores_only_lookup_derived_columns(self):
        row = {**SIDES["conversation"], "scope": "prod/ns-a", "bytes_c2s": "1"}
        base = Migration._record_map([row], "conversation")
        self.assertEqual(
            base,
            Migration._record_map([dict(row, encapsulation="vxlan")], "conversation"),
        )
        self.assertNotEqual(
            base,
            Migration._record_map([dict(row, bytes_c2s="2")], "conversation"),
        )

    def test_v1_manifest_ignores_looked_up_interface_names_and_encapsulation(self):
        netflow = {
            "rollup_id": "7" * 64,
            "records": "2",
            "adm_record": "conversation",
            "flow_source": "netflow",
            "observer": "netflow:10.0.0.1",
            "scope": "prod/ns-a",
            "bytes_c2s": "10",
            "observations": "aci:apic-1:Eth1/2>Eth1/3|netflow:10.0.0.1:ifIndex 12>ifIndex 3",
            "vlan_observations": json.dumps(
                [
                    {"interface_index": "12", "vlan": 10, "first_seen": 1},
                    {"interface_index": "3", "vlan": 20, "first_seen": 1},
                ]
            ),
            "vlan_observations_truncated": "0",
        }
        learned = dict(
            netflow,
            encapsulation="vxlan",
            observations="aci:apic-1:Eth1/2>Eth1/3|netflow:10.0.0.1:Eth1/1>Eth1/2",
            vlan_observations=json.dumps(
                [
                    {
                        "interface_index": "3",
                        "vlan": 20,
                        "first_seen": 1,
                        "interface": "Eth1/2",
                    },
                    {
                        "interface_index": "12",
                        "vlan": 10,
                        "first_seen": 1,
                        "interface": "Eth1/1",
                    },
                ]
            ),
        )
        base = Migration._v1_record_map([netflow])
        self.assertEqual(base, Migration._v1_record_map([learned]))
        for field, value in (
            ("bytes_c2s", "11"),
            ("scope", "prod/ns-b"),
            ("records", "3"),
            (
                "observations",
                "aci:apic-1:Eth1/2>Eth1/9|netflow:10.0.0.1:ifIndex 12>ifIndex 3",
            ),
            (
                "vlan_observations",
                json.dumps([{"interface_index": "12", "vlan": 11, "first_seen": 1}]),
            ),
            ("observations", "aci:apic-1:Eth1/2>Eth1/3"),
            (
                "observations",
                "aci:apic-1:Eth1/2>Eth1/3|netflow:10.0.0.9:Eth1/1>Eth1/2",
            ),
            (
                "observations",
                "aci:apic-1:Eth1/2>Eth1/3|netflow:10.0.0.1:Eth1/1>Eth1/2"
                "|netflow:10.0.0.2:Eth1/1>Eth1/2",
            ),
        ):
            with self.subTest(field=field, value=value):
                self.assertNotEqual(
                    base, Migration._v1_record_map([dict(learned, **{field: value})])
                )

    def test_v1_manifest_strips_interfaces_containing_colons_and_ipv6_exporters(self):
        for observer, raw, learned in (
            ("netflow:10.0.0.1", "netflow:10.0.0.1:?>?", "netflow:10.0.0.1:eth0:1>?"),
            (
                "netflow:10.0.0.1",
                "netflow:10.0.0.1:ifIndex 4>ifIndex 5",
                "netflow:10.0.0.1:Serial0/0:1>eth0:2",
            ),
            (
                "netflow:2001:db8::1",
                "netflow:2001:db8::1:ifIndex 4>?",
                "netflow:2001:db8::1:Eth1/1>?",
            ),
        ):
            with self.subTest(observer=observer, learned=learned):
                row = {
                    "rollup_id": "9" * 64,
                    "records": "1",
                    "adm_record": "conversation",
                    "flow_source": "netflow",
                    "observer": observer,
                    "observations": raw,
                }
                self.assertEqual(
                    Migration._v1_record_map([row]),
                    Migration._v1_record_map([dict(row, observations=learned)]),
                )

    def test_v1_manifest_merges_vlan_contexts_that_differ_only_by_interface(self):
        row = {
            "rollup_id": "8" * 64,
            "records": "2",
            "adm_record": "conversation",
            "vlan_observations_truncated": "0",
        }
        unnamed = dict(
            row,
            vlan_observations=json.dumps(
                [{"interface_index": "12", "vlan": 10, "first_seen": 5, "last_seen": 6}]
            ),
        )
        split = dict(
            row,
            vlan_observations=json.dumps(
                [
                    {
                        "interface_index": "12",
                        "vlan": 10,
                        "first_seen": 5,
                        "last_seen": 5,
                    },
                    {
                        "interface_index": "12",
                        "vlan": 10,
                        "first_seen": 6,
                        "last_seen": 6,
                        "interface": "Eth1/1",
                    },
                ]
            ),
        )
        self.assertEqual(
            Migration._v1_record_map([unnamed]), Migration._v1_record_map([split])
        )
        other_vlan = dict(
            row,
            vlan_observations=json.dumps(
                [{"interface_index": "12", "vlan": 11, "first_seen": 5, "last_seen": 6}]
            ),
        )
        self.assertNotEqual(
            Migration._v1_record_map([unnamed]),
            Migration._v1_record_map([other_vlan]),
        )

    def test_v1_manifest_truncated_vlan_rows_compare_only_truncation(self):
        def contexts(names):
            return json.dumps(
                [
                    {
                        "interface_index": str(index),
                        "vlan": index,
                        "first_seen": 1,
                        **({"interface": f"Eth1/{index}"} if names else {}),
                    }
                    for index in range(32)
                ]
            )

        row = {
            "rollup_id": "9" * 64,
            "records": "2",
            "adm_record": "conversation",
            "vlan_observations_truncated": "1",
        }
        self.assertEqual(
            Migration._v1_record_map([dict(row, vlan_observations=contexts(False))]),
            Migration._v1_record_map([dict(row, vlan_observations=contexts(True))]),
        )
        self.assertNotEqual(
            Migration._v1_record_map([dict(row, vlan_observations=contexts(True))]),
            Migration._v1_record_map(
                [
                    dict(
                        row,
                        vlan_observations=contexts(True),
                        vlan_observations_truncated="0",
                    )
                ]
            ),
        )

    def test_v1_recovery_rerun_tolerates_interface_learned_after_first_audit(self):
        migration = self.migration(FakeApi())
        old = {
            "rollup_id": "9" * 64,
            "records": "2",
            "adm_record": "conversation",
            "flow_source": "netflow",
            "observer": "netflow:10.0.0.1",
            "observations": "netflow:10.0.0.1:ifIndex 12>ifIndex 3",
        }
        learned = dict(
            old, observations="netflow:10.0.0.1:Eth1/1>Eth1/2", encapsulation="vxlan"
        )
        state = {"source": [old], "retained": [old]}
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "v1-churn-test",
            "interface_sha256": migration._interface()[1],
            "created_at": 900_000,
            "v1_pre_pause": {"index_bounds": [999_000, 999_300]},
            "rollback": {
                "state": "recovering",
                "v1_recovery": {"resume_activation_epoch": 999_600},
            },
            "cutover": {"started_at": 999_000},
            "jobs": [],
        }
        migration._write_journal(journal)
        migration._verify_v1_raw_retention = lambda *_args: {
            "indexes": {"netflow": 1000}
        }
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [
            {
                "sid": "scheduler__v1_resume",
                "index_bounds": [999_300, 999_600],
                "event_bounds": {"earliest_time": "913500", "latest_time": "1000800"},
                "anchor": 999_900,
            }
        ]
        migration._v1_expected_rows = lambda *_args, **_kwargs: (
            migration._v1_record_map(state["source"])
        )
        migration._v1_persisted_rows = lambda *_args, **_kwargs: (
            migration._v1_record_map(state["retained"])
        )
        migration._query = lambda *_args, **_kwargs: state["retained"]

        first = migration._v1_recovery_window(journal, 999_600)
        self.assertEqual(first["state"], "verified")

        state["source"] = [learned]
        rerun = migration._v1_recovery_window(self.journal.read(), 999_600)
        self.assertEqual(rerun["state"], "verified")

        state["source"] = [dict(learned, bytes_c2s="5")]
        with self.assertRaises(Refused):
            migration._v1_recovery_window(self.journal.read(), 999_600)

    def test_catalog_output_change_within_generation_starts_a_new_build(self):
        api = FakeApi(catalog_rows=[self.catalog_row()])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_catalog(journal)
        first = self.journal.read()["catalog"]
        api.catalog_rows = [{**self.catalog_row(), "peers": 2}]

        migration._stage_catalog(self.journal.read())

        second = self.journal.read()["catalog"]
        self.assertEqual(second["state"], "verified")
        self.assertEqual(second["build_generation"], first["build_generation"] + 1)
        self.assertEqual(second["input_fingerprint"], first["input_fingerprint"])
        self.assertEqual(
            second["superseded_generations"][0]["expected_fingerprint"],
            first["expected_fingerprint"],
        )
        self.assertEqual(
            len(
                [
                    job
                    for job in self.journal.read()["jobs"]
                    if job.get("label") == "ADM - Application catalog v2"
                ]
            ),
            2,
        )

    def _unsettled_catalog_writer(self, *, state, keep_sid):
        api = FakeApi(catalog_rows=[self.catalog_row()])
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration._stage_catalog(journal)
        journal = self.journal.read()
        writer = next(
            job
            for job in journal["jobs"]
            if job.get("label") == "ADM - Application catalog v2"
        )
        writer["state"] = state
        if not keep_sid:
            writer.pop("sid")
        migration._write_journal(journal)
        api.catalog_rows = [{**self.catalog_row(), "peers": 2}]
        return api, migration, writer

    def test_catalog_output_change_settles_prior_writer_with_a_sid(self):
        _, migration, writer = self._unsettled_catalog_writer(
            state="running", keep_sid=True
        )

        migration._stage_catalog(self.journal.read())

        journal = self.journal.read()
        self.assertEqual(journal["catalog"]["state"], "verified")
        settled = next(job for job in journal["jobs"] if job["id"] == writer["id"])
        self.assertEqual(settled["state"], "complete")
        self.assertEqual(len(journal["catalog"]["superseded_generations"]), 1)

    def test_catalog_output_change_refuses_prior_writer_without_a_sid(self):
        for state in ("dispatch_unknown", "dispatch_pending"):
            with self.subTest(state=state):
                _, migration, _ = self._unsettled_catalog_writer(
                    state=state, keep_sid=False
                )
                with self.assertRaisesRegex(
                    Refused, "unknown outcome and no recorded SID"
                ):
                    migration._stage_catalog(self.journal.read())
                self.assertNotIn(
                    "superseded_generations", self.journal.read()["catalog"]
                )
                self.journal.path.unlink()

    def test_competing_active_staged_writer_refuses_before_dispatch(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        api.jobs["competitor"] = {
            "rows": [],
            "savedsearch_name": "ADM - Conversation rollup v2",
            "search": api.searches["ADM - Conversation rollup v2"]["search"],
            "request": {},
            "saved_search": True,
            "app": "splunk_adm",
            "owner": "splunk-system-user",
            "dispatchState": "RUNNING",
            "isDone": False,
        }
        with self.assertRaises(Refused):
            migration.backfill()
        self.assertFalse(any(path.endswith("/dispatch") for _, path, _ in api.calls))

    def test_active_unlabeled_query_using_staged_writer_macro_is_competing(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        api.jobs["custom-staged"] = {
            "rows": [],
            "search": "| `adm_conversation_rollup_v2` | collect index=adm_summary_v2",
            "request": {},
            "app": "splunk_adm",
            "owner": "admin",
            "dispatchState": "RUNNING",
            "isDone": False,
        }
        with self.assertRaises(Refused):
            migration.backfill()
        api.jobs["custom-staged"]["search"] = (
            "| makeresults | collect index=adm_summary_v2"
        )
        with self.assertRaises(Refused):
            migration.backfill()
        self.assertFalse(any(path.endswith("/dispatch") for _, path, _ in api.calls))

    def test_wrong_preexisting_contract_refuses_before_writes(self):
        api = FakeApi()
        # Inject malformed v2 rows into the initial index audit.
        original = api.request

        def request(method, path, data=None, **kwargs):
            if (
                method == "POST"
                and path == "/servicesNS/nobody/splunk_adm/search/v2/jobs"
                and "index=adm_summary_v2 | fields" in data["search"]
            ):
                response = original(method, path, data, **kwargs)
                sid = response["sid"]
                api.jobs[sid]["rows"] = [
                    {**SIDES["conversation"], "contract_version": "1"}
                ]
                return response
            return original(method, path, data, **kwargs)

        api.request = request
        with self.assertRaises(Refused):
            self.migration(api).prepare(900_000, 900_300)
        self.assertFalse(
            any(
                method == "POST" and path.endswith("/dispatch")
                for method, path, _ in api.calls
            )
        )

    def test_saved_search_execution_prefix_is_bound_to_exact_origin(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        journal = self.journal.read()
        name = "ADM - Traffic observation rollup v2"
        original = journal["origin"]["saved_searches"][name]["content"]["search"]
        record = {
            "kind": "saved_search",
            "label": name,
            "search_fingerprint": fingerprint(original),
        }
        self.assertTrue(migration._job_search_matches(journal, record, original))
        self.assertTrue(
            migration._job_search_matches(journal, record, "search " + original)
        )
        self.assertFalse(
            migration._job_search_matches(
                journal, record, "search " + original + " | eval drift=1"
            )
        )
        self.assertFalse(
            migration._job_search_matches(
                journal,
                record,
                "search " + original.replace("adm:traffic_observation", "other"),
            )
        )
        journal["origin"]["saved_searches"][name]["content"]["search"] += " "
        self.assertFalse(
            migration._job_search_matches(journal, record, "search " + original)
        )

    def test_implicit_search_is_explicit_before_dispatch_fingerprint(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        journal = self.journal.read()
        expression = "`adm_traffic_observations_v2` | fields rollup_id"
        migration._query(
            journal, expression, 900_000, 900_300, label="implicit traffic"
        )
        record = journal["jobs"][-1]
        self.assertEqual(
            record["query_fingerprint"], fingerprint("search " + expression)
        )
        self.assertEqual(api.jobs[record["sid"]]["search"], "search " + expression)
        before = len(api.calls)
        migration._query(
            journal, expression, 900_000, 900_300, label="implicit traffic"
        )
        self.assertEqual(len(api.calls), before)

    def test_normalization_never_bypasses_legacy_unknown_query_attempt(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        journal = self.journal.read()
        expression = "`adm_traffic_observations_v2`"
        journal["jobs"].append(
            {
                "kind": "search",
                "label": "legacy traffic",
                "state": "dispatch_unknown",
                "query_fingerprint": fingerprint(expression),
                "request_bounds": {
                    "earliest_time": journal["event_earliest"],
                    "latest_time": journal["event_latest"],
                    "index_earliest": "900000",
                    "index_latest": "900300",
                },
            }
        )
        before = len(api.calls)
        with self.assertRaises(Uncertain):
            migration._query(
                journal, expression, 900_000, 900_300, label="legacy traffic"
            )
        self.assertEqual(len(api.calls), before)
        journal["jobs"][-1]["state"] = "rejected"
        migration._query(journal, expression, 900_000, 900_300, label="legacy traffic")
        self.assertEqual(journal["jobs"][-1]["state"], "complete")

    def test_ambiguous_search_dispatch_is_journaled_and_never_retried(self):
        api = FakeApi()
        api.request = lambda method, path, data=None, **kwargs: (
            (_ for _ in ()).throw(TimeoutError())
            if method == "POST"
            and path == "/servicesNS/nobody/splunk_adm/search/v2/jobs"
            else FakeApi.request(api, method, path, data, **kwargs)
        )
        migration = self.migration(api)
        with self.assertRaises(Uncertain):
            migration.prepare(900_000, 900_300)
        before = sum(
            method == "POST" and path == "/servicesNS/nobody/splunk_adm/search/v2/jobs"
            for method, path, _ in api.calls
        )
        with self.assertRaises(Uncertain):
            migration.prepare(900_000, 900_300)
        after = sum(
            method == "POST" and path == "/servicesNS/nobody/splunk_adm/search/v2/jobs"
            for method, path, _ in api.calls
        )
        self.assertEqual(before, after)
        self.assertEqual(self.journal.read()["jobs"][-1]["state"], "dispatch_unknown")

    def test_writer_dispatch_unknown_is_not_retried(self):
        api = FakeApi(unknown_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Uncertain):
            migration.backfill()
        count = sum(path.endswith("/dispatch") for _, path, _ in api.calls)
        with self.assertRaises(Uncertain):
            migration.backfill()
        self.assertEqual(
            sum(path.endswith("/dispatch") for _, path, _ in api.calls), count
        )

    def test_known_writer_permission_denial_is_not_marked_ambiguous(self):
        api = FakeApi(reject_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration.backfill()
        journal = self.journal.read()
        writer = next(job for job in journal["jobs"] if job["kind"] == "saved_search")
        self.assertEqual(writer["state"], "rejected")
        self.assertNotEqual(writer["state"], "dispatch_unknown")

    def test_disabled_writer_uses_unscheduled_manual_window_and_restores(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        name = "ADM - Conversation rollup v2"
        self.assertIn((name, "0", "0"), api.writer_dispatch_config)
        self.assertEqual(api.searches[name]["disabled"], "1")
        self.assertEqual(api.searches[name]["is_scheduled"], "1")
        executions = self.journal.read()["temporary_manual_executions"]
        self.assertTrue(executions)
        self.assertTrue(all(item["state"] == "restored" for item in executions))
        transitions = [
            data
            for method, path, data in api.calls
            if method == "POST"
            and "/saved/searches/" in path
            and not path.endswith("/dispatch")
        ]
        self.assertGreaterEqual(len(transitions), 4)

    def test_known_rejection_can_retry_only_as_a_new_restored_attempt(self):
        api = FakeApi(reject_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration.backfill()
        first = next(
            job
            for job in self.journal.read()["jobs"]
            if job.get("kind") == "saved_search"
        )
        self.assertEqual(first["state"], "rejected")
        api.reject_writer = False
        migration.backfill()
        attempts = [
            job
            for job in self.journal.read()["jobs"]
            if job.get("kind") == "saved_search"
            and job.get("label") == "ADM - Conversation rollup v2"
        ]
        self.assertEqual(attempts[0]["state"], "rejected")
        self.assertEqual(attempts[-1]["state"], "complete")
        self.assertEqual(sum(path.endswith("/dispatch") for _, path, _ in api.calls), 3)

    def test_rejected_then_unknown_attempt_keeps_latest_and_never_retries(self):
        api = FakeApi(reject_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration.backfill()
        api.reject_writer = False
        api.unknown_writer = True
        with self.assertRaises(Uncertain):
            migration.backfill()
        latest = [
            job
            for job in self.journal.read()["jobs"]
            if job.get("kind") == "saved_search"
            and job.get("label") == "ADM - Conversation rollup v2"
        ]
        self.assertEqual(
            [job["state"] for job in latest], ["rejected", "dispatch_unknown"]
        )
        dispatches = sum(path.endswith("/dispatch") for _, path, _ in api.calls)
        with self.assertRaises(Uncertain):
            migration.backfill()
        self.assertEqual(
            sum(path.endswith("/dispatch") for _, path, _ in api.calls), dispatches
        )

    def test_unknown_writer_attempt_is_restored_and_never_redispatched(self):
        api = FakeApi(unknown_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Uncertain):
            migration.backfill()
        first_count = sum(path.endswith("/dispatch") for _, path, _ in api.calls)
        self.assertEqual(api.searches["ADM - Conversation rollup v2"]["disabled"], "1")
        self.assertEqual(
            api.searches["ADM - Conversation rollup v2"]["is_scheduled"], "1"
        )
        with self.assertRaises(Uncertain):
            migration.backfill()
        self.assertEqual(
            sum(path.endswith("/dispatch") for _, path, _ in api.calls), first_count
        )

    def test_direct_writer_rejection_retry_and_unknown_attempt_are_preserved(self):
        for name in (
            "ADM - Network client history builder",
            "ADM - Application catalog v2",
        ):
            for unknown in (False, True):
                with self.subTest(name=name, unknown=unknown):
                    self.journal.path.unlink(missing_ok=True)
                    api = FakeApi(reject_writer=True)
                    migration = self.migration(api)
                    migration.prepare(900_000, 900_300)
                    bounds = {"earliest_time": "0", "latest_time": "1000000"}
                    with self.assertRaises(Refused):
                        migration._dispatch_writer(
                            self.journal.read(), name, bounds, label=name
                        )
                    api.reject_writer = False
                    api.unknown_writer = unknown
                    if unknown:
                        with self.assertRaises(Uncertain):
                            migration._dispatch_writer(
                                self.journal.read(), name, bounds, label=name
                            )
                        before = sum(
                            path.endswith("/dispatch") for _, path, _ in api.calls
                        )
                        with self.assertRaises(Uncertain):
                            migration._dispatch_writer(
                                self.journal.read(), name, bounds, label=name
                            )
                        self.assertEqual(
                            sum(path.endswith("/dispatch") for _, path, _ in api.calls),
                            before,
                        )
                    else:
                        migration._dispatch_writer(
                            self.journal.read(), name, bounds, label=name
                        )
                    attempts = [
                        job
                        for job in self.journal.read()["jobs"]
                        if job.get("label") == name
                    ]
                    self.assertEqual(len(attempts), 2)
                    self.assertEqual(attempts[0]["state"], "rejected")
                    self.assertEqual(attempts[1]["retry_of"], attempts[0]["id"])
                    self.assertEqual(
                        attempts[1]["state"],
                        "dispatch_unknown" if unknown else "complete",
                    )
                    self.assertEqual(api.searches[name]["disabled"], "1")

    def test_direct_writer_pre_dispatch_interruption_can_resume_once(self):
        for name in (
            "ADM - Network client history builder",
            "ADM - Application catalog v2",
        ):
            with self.subTest(name=name):
                self.journal.path.unlink(missing_ok=True)
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                original = api.request

                def crash(method, path, data=None, **kwargs):
                    result = original(method, path, data, **kwargs)
                    if (
                        method == "POST"
                        and "/saved/searches/" in path
                        and data == {"disabled": "0"}
                    ):
                        raise SystemExit("interrupted after enable")
                    return result

                api.request = crash
                bounds = {"earliest_time": "0", "latest_time": "1000000"}
                with self.assertRaises(SystemExit):
                    migration._dispatch_writer(
                        self.journal.read(), name, bounds, label=name
                    )
                self.assertFalse(
                    any(path.endswith("/dispatch") for _, path, _ in api.calls)
                )
                api.request = original
                migration._dispatch_writer(
                    self.journal.read(), name, bounds, label=name
                )
                attempts = [
                    job
                    for job in self.journal.read()["jobs"]
                    if job.get("label") == name
                ]
                self.assertEqual(
                    [job["state"] for job in attempts],
                    ["preparation_aborted", "complete"],
                )
                self.assertEqual(attempts[1]["retry_of"], attempts[0]["id"])
                self.assertEqual(
                    sum(path.endswith("/dispatch") for _, path, _ in api.calls), 1
                )
                self.assertEqual(api.searches[name]["disabled"], "1")

    def test_cutover_guard_restores_interrupted_manual_configuration(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                self.journal.path.unlink(missing_ok=True)
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                journal = self.journal.read()
                journal["phase"] = "cutover_in_progress"
                journal["cutover"] = {"mutations": []}
                migration._write_journal(journal)
                original = api.request

                def crash(method, path, data=None, **kwargs):
                    result = original(method, path, data, **kwargs)
                    if method == "POST" and data == {"disabled": "0"}:
                        raise SystemExit("interrupted after enable")
                    return result

                api.request = crash
                with self.assertRaises(SystemExit):
                    migration._dispatch_writer(
                        journal,
                        "ADM - Network client history builder",
                        {"earliest_time": "0", "latest_time": "1000000"},
                        label="interrupted catch-up",
                    )
                api.request = original
                journal = self.journal.read()
                if ambiguous:
                    journal["jobs"][-1]["state"] = "dispatch_unknown"
                    migration._write_journal(journal)
                    with self.assertRaises(Uncertain):
                        migration._assert_cutover_origin_compatible(journal)
                    self.assertEqual(journal["jobs"][-1]["state"], "dispatch_unknown")
                else:
                    migration._assert_cutover_origin_compatible(journal)
                    self.assertEqual(
                        journal["jobs"][-1]["state"], "preparation_aborted"
                    )
                self.assertEqual(
                    api.searches["ADM - Network client history builder"]["disabled"],
                    "1",
                )
                self.assertEqual(
                    api.searches["ADM - Network client history builder"][
                        "is_scheduled"
                    ],
                    "1",
                )
                self.assertFalse(
                    any(path.endswith("/dispatch") for _, path, _ in api.calls)
                )

    def test_stream_latest_unknown_attempt_blocks_even_without_stream_guard(self):
        api = FakeApi(reject_writer=True)
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration.backfill()
        api.reject_writer = False
        api.unknown_writer = True
        with self.assertRaises(Uncertain):
            migration.backfill()
        journal = self.journal.read()
        slice_record = journal["slices"][0]
        slice_record["streams"]["conversation"]["state"] = "backfill_pending"
        before = sum(path.endswith("/dispatch") for _, path, _ in api.calls)
        with self.assertRaises(Uncertain):
            migration._stage_stream(journal, slice_record, "conversation")
        self.assertEqual(
            sum(path.endswith("/dispatch") for _, path, _ in api.calls), before
        )

    def test_crash_after_enable_write_restores_before_any_retry(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        original_request = api.request

        def crash_after_enable_write(method, path, data=None, **kwargs):
            result = original_request(method, path, data, **kwargs)
            if (
                method == "POST"
                and "/saved/searches/" in path
                and not path.endswith("/dispatch")
                and data == {"disabled": "0"}
            ):
                raise SystemExit("simulated process interruption")
            return result

        api.request = crash_after_enable_write
        with self.assertRaises(SystemExit):
            migration.backfill()
        api.request = original_request
        self.assertEqual(api.searches["ADM - Conversation rollup v2"]["disabled"], "0")
        self.assertEqual(
            sum(
                path.endswith("/dispatch") and "Conversation%20rollup%20v2" in path
                for _, path, _ in api.calls
            ),
            0,
        )
        migration.backfill()
        self.assertEqual(api.searches["ADM - Conversation rollup v2"]["disabled"], "1")
        self.assertEqual(
            sum(
                path.endswith("/dispatch") and "Conversation%20rollup%20v2" in path
                for _, path, _ in api.calls
            ),
            1,
        )

    def test_acl_or_search_drift_during_preparation_refuses_before_dispatch(self):
        for drift in ("acl", "search"):
            with self.subTest(drift=drift):
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                original_request = api.request
                changed = False

                def request(method, path, data=None, **kwargs):
                    nonlocal changed
                    response = original_request(method, path, data, **kwargs)
                    if (
                        method == "POST"
                        and "/saved/searches/ADM%20-%20Conversation%20rollup%20v2"
                        in path
                        and data == {"is_scheduled": "0"}
                    ):
                        changed = True
                    if (
                        changed
                        and method == "GET"
                        and "/saved/searches/ADM%20-%20Conversation%20rollup%20v2"
                        in path
                    ):
                        entry = response["entry"][0]
                        if drift == "acl":
                            entry["acl"]["perms"]["write"] = ["nobody"]
                        else:
                            entry["content"]["search"] += " | eval drift=1"
                    return response

                api.request = request
                with self.assertRaises((Refused, Uncertain)):
                    migration.backfill()
                self.assertFalse(
                    any(
                        path.endswith("/dispatch")
                        and "Conversation%20rollup%20v2" in path
                        for _, path, _ in api.calls
                    )
                )

    def test_running_writer_sid_is_resumed_without_second_dispatch(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        name = "ADM - Conversation rollup v2"
        sid = "writer-existing"
        api.jobs[sid] = {
            "rows": [],
            "savedsearch_name": name,
            "search": api.searches[name]["search"],
            "request": {
                "earliest_time": "0",
                "latest_time": "1000900",
                "index_earliest": "900000",
                "index_latest": "900300",
            },
            "saved_search": True,
            "app": "splunk_adm",
            "owner": "splunk-system-user",
        }
        api.persisted_rows.extend(FakeApi._source_rows("adm:conversation"))
        journal = self.journal.read()
        writer = {
            "id": "persisted",
            "kind": "saved_search",
            "label": name,
            "stream": "conversation",
            "slice_start": 900_000,
            "slice_end": 900_300,
            "request_bounds": {
                "earliest_time": "0",
                "latest_time": "1000900",
                "index_earliest": "900000",
                "index_latest": "900300",
            },
            "search_fingerprint": fingerprint(api.searches[name]["search"]),
            "state": "running",
            "sid": sid,
        }
        journal["jobs"].append(writer)
        slice_state = journal["slices"][0]["streams"]["conversation"]
        slice_state.update(
            state="backfill_pending",
            expected={
                row["rollup_id"]: {
                    "records": int(row["records"]),
                    "adm_record": row["adm_record"],
                }
                for row in FakeApi._source_rows("adm:conversation")
            },
        )
        self.journal.write(journal)
        migration._stage_stream(journal, journal["slices"][0], "conversation")
        self.assertEqual(sum(path.endswith("/dispatch") for _, path, _ in api.calls), 0)
        self.assertEqual(slice_state["state"], "verified")
        self.assertEqual(
            slice_state["expected"][SIDES["conversation"]["rollup_id"]]["copies"], 1
        )

    def test_staged_count_mismatch_blocks_validation(self):
        migration = self.migration(FakeApi(bad_actual=True))
        migration.prepare(900_000, 900_300)
        with self.assertRaises(Refused):
            migration.backfill()
        with self.assertRaises(Refused):
            migration.validate()

    def test_unexpected_summary_in_migration_ingestion_window_blocks_validation(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        api.persisted_rows.append(
            {
                "source": "adm:conversation",
                "adm_record": "conversation",
                "rollup_id": "e" * 64,
                "records": "1",
                "contract_version": "2",
            }
        )
        with self.assertRaises(Refused):
            migration.validate()

    def test_migration_ingestion_window_includes_first_scheduled_cycle(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        migration.backfill()
        journal = self.journal.read()
        scheduled = {}
        for stream, source in (
            ("conversation", "adm:conversation"),
            ("traffic", "adm:traffic_observation"),
        ):
            rollup_id = ("f" if stream == "conversation" else "a") * 64
            stream_name = "conversation" if stream == "conversation" else "traffic"
            expected_row = {
                **SIDES[stream_name],
                "rollup_id": rollup_id,
            }
            expected = migration._record_map([expected_row], stream_name)
            api.persisted_rows.append(
                {
                    **expected_row,
                    "source": source,
                }
            )
            scheduled[stream] = {
                "index_earliest": 999_300,
                "index_latest": 999_600,
                "expected": expected,
            }
        journal["cutover"] = {"scheduled_streams": scheduled}
        self.journal.write(journal)

        evidence = migration._validate_migration_ingestion_window(journal)

        self.assertEqual(evidence["rows"], 6)

    def test_observed_schedule_boundary_catches_unexpected_row_after_expected_output(
        self,
    ):
        api = FakeApi()
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        migration.backfill()
        journal = self.journal.read()
        journal["cutover"] = {"schedule_observation_epoch": 1_000_010}
        api.persisted_rows.append(
            {
                "source": "adm:conversation",
                "adm_record": "conversation",
                "rollup_id": "e" * 64,
                "records": "1",
                "contract_version": "2",
                "_indextime": 1_000_005,
            }
        )

        self.assertEqual(migration._scheduled_output_watermark(journal), 1_000_010)
        with self.assertRaises(Refused):
            migration._validate_migration_ingestion_window(
                journal, upper_bound=migration._scheduled_output_watermark(journal)
            )

    def test_bridge_validates_two_nonempty_scheduled_cycles_for_both_writers(self):
        api = FakeApi()
        migration = self.migration(api)
        first_start, first_end = 999_300, 999_600
        second_start, second_end = 999_600, 999_900
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "two-cycle-bridge",
            "interface_sha256": migration._interface()[1],
            "created_at": 900_000,
            "range": {"start": 999_000, "end": first_start},
            "slices": [],
            "jobs": [],
            "cutover": {
                "started_at": 900_000,
                "mutations": [
                    {
                        "kind": "saved_search",
                        "name": "ADM - Conversation rollup v2",
                        "after": False,
                        "state": "applied",
                        "verified_at": 999_600,
                    },
                    {
                        "kind": "saved_search",
                        "name": "ADM - Traffic observation rollup v2",
                        "after": False,
                        "state": "applied",
                        "verified_at": 999_600,
                    },
                ],
            },
        }
        migration._write_journal(journal)
        cycle_bounds = [(first_start, first_end), (second_start, second_end)]
        migration._scheduled_writer_cycles = lambda name, *_args, **_kwargs: [
            {
                "sid": f"scheduler__{name}__{index}",
                "index_bounds": list(bounds),
                "event_bounds": {"earliest_time": "900", "latest_time": "1000000"},
                "anchor": bounds[0] + 600,
            }
            for index, bounds in enumerate(cycle_bounds)
        ]
        migration._query = lambda _journal, query, *_args, **_kwargs: (
            [SIDES["traffic"]]
            if "adm_traffic_observations_v2" in query
            else [SIDES[name] for name in ("conversation", "hubble_xlate", "hubble_l7")]
        )
        observed_copy_counts = []

        def poll_physical_rows(_journal, expected, *_args, **_kwargs):
            observed_copy_counts.append(
                {rollup_id: item["copies"] for rollup_id, item in expected.items()}
            )
            # The fake retained index contains each identical source row once
            # per distinct scheduled SID. Return the exact physical multiset
            # requested by the bridge's cumulative audit.
            return expected

        migration._poll_persisted_rows = poll_physical_rows
        migration.validate = lambda _scenario=None: None

        self.assertTrue(migration._bridge_to_first_scheduled_cycle(journal, {}))

        repeated = [counts for counts in observed_copy_counts if counts]
        self.assertTrue(any(max(counts.values()) == 2 for counts in repeated))

        bridged = self.journal.read()
        for state in bridged["cutover"]["scheduled_streams"].values():
            self.assertEqual(len(state["cycles"]), 2)
            self.assertTrue(all(cycle["rows"] > 0 for cycle in state["cycles"]))
        self.assertEqual(bridged["range"]["end"], second_end)

    def test_bridge_resumes_after_durable_first_cycle_checkpoint(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.clock = lambda: 1_001_000
        first_start, first_end = 999_300, 999_600
        second_start, second_end = 999_600, 999_900
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "bridge-resume-test",
            "interface_sha256": migration._interface()[1],
            "phase": "cutover_in_progress",
            "created_at": 900_000,
            "range": {"start": 999_000, "end": first_start},
            "slices": [],
            "jobs": [],
            "cutover": {
                "started_at": 900_000,
                "mutations": [
                    {
                        "kind": "saved_search",
                        "name": "ADM - Conversation rollup v2",
                        "after": False,
                        "state": "applied",
                        "verified_at": 999_600,
                    },
                    {
                        "kind": "saved_search",
                        "name": "ADM - Traffic observation rollup v2",
                        "after": False,
                        "state": "applied",
                        "verified_at": 999_600,
                    },
                ],
            },
        }
        migration._write_journal(journal)
        cycle_bounds = [(first_start, first_end), (second_start, second_end)]
        migration._scheduled_writer_cycles = lambda name, *_args, **_kwargs: [
            {
                "sid": f"scheduler__{name}__{index}",
                "index_bounds": list(bounds),
                "event_bounds": {"earliest_time": "900", "latest_time": "1000000"},
                "anchor": bounds[0] + 600,
            }
            for index, bounds in enumerate(cycle_bounds)
        ]
        fail_second_cycle = True

        def query(_journal, query_text, *args, **_kwargs):
            nonlocal fail_second_cycle
            if (
                fail_second_cycle
                and args[:2] == (second_start, second_end)
                and " manifest " not in _kwargs.get("label", "")
                and "adm_traffic_observations_v2" not in query_text
            ):
                raise Refused("simulated interruption after first cycle checkpoint")
            return (
                [SIDES["traffic"]]
                if "adm_traffic_observations_v2" in query_text
                else [
                    SIDES[name]
                    for name in ("conversation", "hubble_xlate", "hubble_l7")
                ]
            )

        migration._query = query
        observed_copy_counts = []

        def poll_physical_rows(_journal, expected, *_args, **_kwargs):
            observed_copy_counts.append(
                {rollup_id: item["copies"] for rollup_id, item in expected.items()}
            )
            return expected

        migration._poll_persisted_rows = poll_physical_rows
        migration.validate = lambda _scenario=None: None

        with self.assertRaisesRegex(Refused, "simulated interruption"):
            migration._bridge_to_first_scheduled_cycle(journal, {})
        checkpoint = self.journal.read()
        self.assertEqual(checkpoint["range"]["end"], first_end)
        self.assertNotIn("scheduled_cycle_bounds", checkpoint["cutover"])
        self.assertEqual(
            len(checkpoint["cutover"]["scheduled_streams"]["conversation"]["cycles"]),
            1,
        )
        # Inventory can already expose both completed scheduled intents while
        # the bridge is processing the first checkpoint. Their physical rows
        # must be included in that cumulative audit.
        self.assertTrue(any(2 in counts.values() for counts in observed_copy_counts))

        fail_second_cycle = False
        self.assertTrue(migration._bridge_to_first_scheduled_cycle(checkpoint, {}))
        resumed = self.journal.read()
        for state in resumed["cutover"]["scheduled_streams"].values():
            self.assertEqual(len(state["cycles"]), 2)
        self.assertEqual(resumed["range"]["end"], second_end)
        self.assertEqual(resumed["phase"], "cutover_in_progress")
        # The durable first-cycle intent is not counted again on resume.
        self.assertTrue(any(2 in counts.values() for counts in observed_copy_counts))
        self.assertFalse(any(3 in counts.values() for counts in observed_copy_counts))

    def test_bridge_gap_resume_reuses_durable_slice_and_later_audit_boundary(self):
        migration = self.migration(FakeApi())
        first_start, first_end = 999_300, 999_600
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "bridge-gap-resume",
            "interface_sha256": migration._interface()[1],
            "phase": "cutover_in_progress",
            "created_at": 900_000,
            "range": {"start": 999_000, "end": 999_000},
            "slices": [],
            "jobs": [],
            "event_earliest": "0",
            "event_latest": "1000000",
            "cutover": {
                "started_at": 900_000,
                "mutations": [
                    {
                        "kind": "saved_search",
                        "name": "ADM - Conversation rollup v2",
                        "after": False,
                        "state": "applied",
                        "verified_at": 999_600,
                    },
                    {
                        "kind": "saved_search",
                        "name": "ADM - Traffic observation rollup v2",
                        "after": False,
                        "state": "applied",
                        "verified_at": 999_600,
                    },
                ],
            },
        }
        migration._write_journal(journal)
        cycle = {
            "sid": "scheduler__conversation__bridge",
            "index_bounds": [first_start, first_end],
            "event_bounds": {"earliest_time": "900", "latest_time": "1000000"},
            "anchor": first_start + 600,
        }
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [cycle]
        migration._query = lambda _journal, query, *_args, **_kwargs: (
            [SIDES["traffic"]]
            if "adm_traffic_observations_v2" in query
            else [SIDES[name] for name in ("conversation", "hubble_xlate", "hubble_l7")]
        )
        migration._poll_persisted_rows = lambda _journal, expected, *_args, **_kwargs: (
            expected
        )
        migration.validate = lambda _scenario=None: None
        clock = [1_001_000]
        migration.clock = lambda: clock[0]
        fail_once = [True]

        def stage_stream(_journal, slice_record, stream, **_kwargs):
            slice_record["streams"][stream].update(
                state="verified",
                expected={},
                expected_fingerprint=fingerprint({}),
                actual_fingerprint=fingerprint({}),
            )
            migration._write_journal(_journal)

        def stage_history(_journal, slice_record):
            if fail_once[0]:
                fail_once[0] = False
                raise Refused("simulated interruption after durable gap intent")
            slice_record["history"].update(
                state="verified",
                expected_fingerprint=fingerprint({}),
                actual_fingerprint=fingerprint({}),
            )
            migration._write_journal(_journal)
            clock[0] += 300

        migration._stage_stream = stage_stream
        migration._stage_history_slice = stage_history
        with self.assertRaisesRegex(Refused, "durable gap intent"):
            migration._bridge_to_first_scheduled_cycle(journal, {})
        interrupted = self.journal.read()
        self.assertEqual(len(interrupted["slices"]), 1)

        self.assertTrue(migration._bridge_to_first_scheduled_cycle(interrupted, {}))
        resumed = self.journal.read()
        self.assertEqual(len(resumed["slices"]), 1)
        self.assertEqual(resumed["cutover"]["schedule_observation_epoch"], 1_001_300)
        self.assertEqual(
            resumed["cutover"]["manual_bridge_writes"][0]["index_bounds"],
            [999_000, first_start],
        )

    def test_stage_counts_observed_scheduled_physical_copies_and_resume(self):
        for physical_copies, should_pass in ((1, False), (2, True), (3, False)):
            with self.subTest(physical_copies=physical_copies):
                self.journal.path.unlink(missing_ok=True)
                api = FakeApi()
                migration = self.migration(api)
                migration.prepare(900_000, 900_300)
                journal = self.journal.read()
                slice_record = journal["slices"][0]
                physical_rows = [
                    {**row, "_indextime": 900_250}
                    for row in FakeApi._source_rows("adm:conversation")
                ]
                expected = migration._record_map(physical_rows, "conversation")
                slice_record["streams"]["conversation"].update(
                    state="backfill_done", expected=expected
                )
                api.persisted_rows.extend(
                    row for _ in range(physical_copies) for row in physical_rows
                )
                migration._write_journal(journal)

                if should_pass:
                    migration._stage_stream(
                        journal,
                        slice_record,
                        "conversation",
                        observed_scheduled_expected=[expected],
                    )
                    self.assertEqual(
                        slice_record["streams"]["conversation"]["state"],
                        "verified",
                    )
                    before_resume = len(api.persisted_rows)
                    migration._stage_stream(
                        journal,
                        slice_record,
                        "conversation",
                        observed_scheduled_expected=[expected],
                    )
                    self.assertEqual(len(api.persisted_rows), before_resume)
                else:
                    with self.assertRaises(Refused):
                        migration._stage_stream(
                            journal,
                            slice_record,
                            "conversation",
                            observed_scheduled_expected=[expected],
                        )

    def test_pending_v1_reconciliation_counts_scheduled_physical_copies(self):
        row = {"rollup_id": "9" * 64, "records": "2", "adm_record": "conversation"}
        expected = Migration._v1_record_map([row])
        bounds = [900_000, 900_300]
        event_bounds = {"earliest_time": "0", "latest_time": "1000000"}
        for physical_copies, should_pass in ((1, False), (2, True), (3, False)):
            with self.subTest(physical_copies=physical_copies):
                self.journal.path.unlink(missing_ok=True)
                migration = self.migration(FakeApi())
                migration.prepare(900_000, 900_300)
                journal = self.journal.read()
                journal["rollback"] = {}
                recovery = journal["rollback"].setdefault(
                    "v1_recovery",
                    {"resume_activation_epoch": 899_999, "expected_slices": {}},
                )
                item = {
                    "state": "expected",
                    "index_bounds": bounds,
                    "event_bounds": event_bounds,
                    "expected": expected,
                    "expected_fingerprint": fingerprint(expected),
                }
                recovery["expected_slices"]["900000:900300"] = item
                intent = fingerprint(
                    {
                        "migration_id": journal["migration_id"],
                        "rollback_resume_epoch": 899_999,
                        "slice": bounds,
                        "expected": fingerprint(expected),
                    }
                )
                job = {
                    "kind": "saved_search",
                    "label": "ADM - Conversation rollup",
                    "state": "complete",
                    "sid": "manual-sid",
                    "intent_fingerprint": intent,
                    "search_fingerprint": "search-fingerprint",
                    "request_bounds": {
                        **event_bounds,
                        "index_earliest": "900000",
                        "index_latest": "900300",
                    },
                    "result_count": 1,
                    "job_state": {
                        "dispatchState": "DONE",
                        "isDone": True,
                        "isFinalized": False,
                        "eventIsTruncated": False,
                        "dropCount": 0,
                        "resultCount": 1,
                        "messages": [],
                    },
                }
                journal["jobs"] = [job]
                physical_rows = [dict(row) for _ in range(physical_copies)]
                migration._read_job = lambda _journal, _job: [row]
                migration._v1_expected_rows = lambda *_args: expected
                migration._query = lambda *_args, **_kwargs: physical_rows
                migration._write_journal(journal)
                if should_pass:
                    migration._reconcile_pending_v1_manual_slices(
                        journal, recovery, {"scheduler-sid": expected}
                    )
                    self.assertEqual(
                        recovery["expected_slices"]["900000:900300"]["state"],
                        "verified",
                    )
                else:
                    with self.assertRaises(Refused):
                        migration._reconcile_pending_v1_manual_slices(
                            journal, recovery, {"scheduler-sid": expected}
                        )

    def test_v1_retained_read_bounds_include_late_bucket_from_prior_cycle(self):
        migration = self.migration(FakeApi())
        late_row = {
            "_time": "913800",
            "rollup_id": "7" * 64,
            "records": "1",
            "adm_record": "conversation",
        }
        current_row = {
            "_time": "914100",
            "rollup_id": "8" * 64,
            "records": "2",
            "adm_record": "conversation",
        }
        expected = migration._v1_record_map([late_row, current_row])
        physical_rows = [dict(late_row), dict(current_row)]
        query_bounds = []

        def retained_query(_journal, _query, _start, _end, **kwargs):
            earliest = float(kwargs["earliest_time"])
            latest = float(kwargs["latest_time"])
            query_bounds.append((earliest, latest))
            return [
                row for row in physical_rows if earliest <= float(row["_time"]) < latest
            ]

        migration._query = retained_query
        # This models the second cycle's narrower raw-event window. Its
        # cumulative expectation still contains a prior-cycle bucket at 913800.
        event_bounds = {"earliest_time": "914100", "latest_time": "1001400"}
        actual = migration._v1_persisted_rows(
            {}, expected, event_bounds, "late prior-cycle retained read"
        )
        self.assertEqual(actual, expected)
        self.assertEqual(query_bounds, [(913800, 1001400)])

        # A complete material readback is required: widening the time range
        # must not make a missing prior-cycle row or an unexplained extra copy
        # pass the same cumulative physical audit.
        physical_rows[:] = [dict(current_row)]
        missing = migration._v1_persisted_rows(
            {}, expected, event_bounds, "missing prior-cycle retained row"
        )
        self.assertNotEqual(missing, expected)
        physical_rows[:] = [dict(late_row), dict(late_row), dict(current_row)]
        extra = migration._v1_persisted_rows(
            {}, expected, event_bounds, "extra prior-cycle retained copy"
        )
        self.assertNotEqual(extra, expected)
        self.assertEqual(
            migration._v1_persisted_rows({}, {}, event_bounds, "empty retained read"),
            {},
        )

    def test_enabled_v1_recovery_requires_and_journals_exact_resumed_coverage(self):
        migration = self.migration(FakeApi())
        row = {"rollup_id": "9" * 64, "records": "2", "adm_record": "conversation"}
        expected = migration._v1_record_map([row])
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "v1-resume-test",
            "interface_sha256": migration._interface()[1],
            "created_at": 900_000,
            "v1_pre_pause": {"index_bounds": [999_000, 999_300]},
            "rollback": {
                "state": "recovering",
                "v1_recovery": {"resume_activation_epoch": 999_600},
            },
            "cutover": {"started_at": 999_000},
            "jobs": [],
        }
        migration._write_journal(journal)
        migration._verify_v1_raw_retention = lambda *_args: {
            "indexes": {"netflow": 1000}
        }
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [
            {
                "sid": "scheduler__v1_resume",
                "index_bounds": [999_300, 999_600],
                "event_bounds": {"earliest_time": "913500", "latest_time": "1000800"},
                "anchor": 999_900,
            }
        ]
        migration._v1_expected_rows = lambda *_args, **_kwargs: expected
        migration._v1_persisted_rows = lambda *_args, **_kwargs: expected
        audit_requests = []

        def audit_query(*args, **kwargs):
            audit_requests.append((args, kwargs))
            return [row]

        migration._query = audit_query

        recovery = migration._v1_recovery_window(journal, 999_600)

        self.assertEqual(recovery["state"], "verified")
        self.assertEqual(recovery["expected_rollups"], 1)
        self.assertIn("999300:999600", recovery["scheduler_cycles"])
        self.assertEqual(audit_requests[-1][1]["earliest_time"], "0")
        self.assertEqual(audit_requests[-1][1]["latest_time"], "1000900")

    def test_v1_retry_empty_cycle_allows_only_durable_manual_gap_rows(self):
        row = {
            "rollup_id": "8" * 64,
            "records": "2",
            "adm_record": "conversation",
        }
        extra = {
            "rollup_id": "7" * 64,
            "records": "1",
            "adm_record": "conversation",
        }
        for include_extra in (False, True):
            with self.subTest(include_extra=include_extra):
                api = FakeApi()
                migration = self.migration(api)
                expected = migration._v1_record_map([row])
                gap_bounds = [999_000, 999_300]
                gap_event_bounds = {
                    "earliest_time": "913200",
                    "latest_time": "1000500",
                }
                cycle = {
                    "sid": "scheduler__v1_empty_after_gap",
                    "index_bounds": [999_300, 999_600],
                    "event_bounds": {
                        "earliest_time": "913500",
                        "latest_time": "1000800",
                    },
                    "anchor": 999_900,
                    "empty_summary_warning": True,
                }
                migration.clock = lambda: 1_000_200
                migration._verify_v1_raw_retention = lambda *_args: {
                    "indexes": {"netflow": 1}
                }
                migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [cycle]

                def source_expected(_journal, bounds, *_args, **_kwargs):
                    return expected if tuple(bounds) == tuple(gap_bounds) else {}

                migration._v1_expected_rows = source_expected
                migration._v1_persisted_rows = (
                    lambda _journal, found, *_args, **_kwargs: found
                )
                migration._query = lambda *_args, **_kwargs: (
                    [row, extra] if include_extra else [row]
                )
                journal = {
                    "schema": JOURNAL_SCHEMA,
                    "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
                    "migration_id": "v1-empty-retry-test",
                    "interface_sha256": migration._interface()[1],
                    "created_at": 900_000,
                    "origin": {
                        "saved_searches": {
                            "ADM - Conversation rollup": {"content": {"disabled": "0"}}
                        }
                    },
                    "v1_pre_pause": {"index_bounds": [998_700, 999_000]},
                    "rollback": {
                        "state": "recovering",
                        "v1_recovery": {
                            "state": "recovering",
                            "resume_activation_epoch": 999_600,
                            "expected_slices": {
                                "999000:999300": {
                                    "index_bounds": gap_bounds,
                                    "event_bounds": gap_event_bounds,
                                    "expected": expected,
                                    "expected_fingerprint": fingerprint(expected),
                                    "state": "expected",
                                }
                            },
                            "scheduler_cycles": {},
                        },
                    },
                    "cutover": {"started_at": 999_000},
                    "jobs": [
                        {
                            "id": "retired-rejected-attempt",
                            "kind": "saved_search",
                            "label": "ADM - Conversation rollup",
                            "state": "rejected",
                            "request_bounds": {
                                "index_earliest": "999000",
                                "index_latest": "999300",
                                "earliest_time": "913200",
                                "latest_time": "1000500",
                            },
                            "intent_fingerprint": fingerprint(
                                {
                                    "migration_id": "v1-empty-retry-test",
                                    "rollback_resume_epoch": 999_600,
                                    "slice": gap_bounds,
                                    "expected": fingerprint(expected),
                                }
                            ),
                        },
                        {
                            "id": "manual-gap-job",
                            "kind": "saved_search",
                            "label": "ADM - Conversation rollup",
                            "sid": "manual-gap-sid",
                            "state": "running",
                            "request_bounds": {
                                "index_earliest": "999000",
                                "index_latest": "999300",
                                "earliest_time": "913200",
                                "latest_time": "1000500",
                            },
                            "search_fingerprint": fingerprint(
                                api.searches["ADM - Conversation rollup"]["search"]
                            ),
                            "intent_fingerprint": fingerprint(
                                {
                                    "migration_id": "v1-empty-retry-test",
                                    "rollback_resume_epoch": 999_600,
                                    "slice": gap_bounds,
                                    "expected": fingerprint(expected),
                                }
                            ),
                            "result_count": 1,
                            "job_state": {
                                "dispatchState": "RUNNING",
                                "isDone": False,
                                "isFinalized": False,
                                "eventIsTruncated": False,
                                "dropCount": "0",
                                "resultCount": "1",
                                "messages": [],
                            },
                        },
                    ],
                }
                api.jobs["manual-gap-sid"] = {
                    "rows": [row],
                    "savedsearch_name": "ADM - Conversation rollup",
                    "search": api.searches["ADM - Conversation rollup"]["search"],
                    "request": journal["jobs"][0]["request_bounds"],
                    "saved_search": True,
                    "app": "splunk_adm",
                    "owner": "splunk-system-user",
                }
                migration._write_journal(journal)

                if include_extra:
                    with self.assertRaisesRegex(Refused, "outside validated manifests"):
                        migration._v1_recovery_window(journal, 999_600)
                else:
                    recovery = migration._v1_recovery_window(journal, 999_600)
                    proof = recovery["empty_summary_proofs"]["999300:999600"]
                    self.assertEqual(proof["observed_manifest_rows"], 1)
                    self.assertEqual(proof["retained_rows"], 0)

    def test_v1_nonempty_retained_gap_without_writer_sid_is_not_verified(self):
        migration = self.migration(FakeApi())
        row = {"rollup_id": "6" * 64, "records": "1", "adm_record": "conversation"}
        expected = migration._v1_record_map([row])
        cycle = {
            "sid": "scheduler__v1_after_gap",
            "index_bounds": [999_300, 999_600],
            "event_bounds": {"earliest_time": "913500", "latest_time": "1000800"},
            "anchor": 999_900,
        }
        migration.clock = lambda: 1_000_200
        migration._verify_v1_raw_retention = lambda *_args: {"indexes": {"netflow": 1}}
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [cycle]
        migration._v1_expected_rows = lambda _journal, bounds, *_args, **_kwargs: (
            expected if tuple(bounds) == (999_000, 999_300) else {}
        )
        migration._v1_persisted_rows = lambda _journal, found, *_args, **_kwargs: found
        migration._dispatch_writer = lambda *_args, **_kwargs: [row]
        origin = migration.snapshot(allow_activation=True)
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "v1-gap-no-sid-test",
            "interface_sha256": migration._interface()[1],
            "phase": "rollback_in_progress",
            "created_at": 900_000,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "v1_pre_pause": {"index_bounds": [998_700, 999_000]},
            "rollback": {
                "state": "recovering",
                "v1_recovery": {"resume_activation_epoch": 999_600},
            },
            "cutover": {"started_at": 999_000},
            "jobs": [],
        }
        migration._write_journal(journal)

        with self.assertRaisesRegex(Refused, "no exact journaled writer SID"):
            migration._v1_recovery_window(journal, 999_600)

    def test_v1_recovery_refuses_rows_without_stable_rollup_id(self):
        with self.assertRaises(Refused):
            Migration._v1_record_map([{"records": "1", "adm_record": "conversation"}])

    def test_enabled_v1_cutover_anchor_refuses_without_real_scheduler_job(self):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)

        with self.assertRaises(Refused):
            migration._capture_v1_pre_pause(journal)

    def test_v1_empty_warning_refuses_nonempty_source_expectation(self):
        migration = self.migration(FakeApi())
        cycle = {
            "sid": "scheduler__v1_empty",
            "index_bounds": [999_300, 999_600],
            "event_bounds": {"earliest_time": "913500", "latest_time": "1000800"},
            "anchor": 999_900,
            "empty_summary_warning": True,
        }
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [cycle]
        migration._v1_expected_rows = lambda *_args, **_kwargs: {
            "9" * 64: {"records": 1, "adm_record": "conversation"}
        }
        with self.assertRaisesRegex(Refused, "empty summary while source rows exist"):
            migration._capture_v1_pre_pause({"jobs": []})

    def test_v1_empty_warning_requires_retained_index_window_to_be_empty(self):
        cycle = {
            "sid": "scheduler__v1_empty",
            "index_bounds": [999_300, 999_600],
            "event_bounds": {"earliest_time": "913500", "latest_time": "1000800"},
            "anchor": 999_900,
            "empty_summary_warning": True,
        }
        migration = self.migration(FakeApi())
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [cycle]
        migration._v1_expected_rows = lambda *_args, **_kwargs: {}
        journal = migration.prepare(900_000, 900_300)

        proof = migration._capture_v1_pre_pause(journal)

        self.assertEqual(proof["empty_summary_proof"]["retained_rows"], 0)
        self.assertEqual(
            proof["empty_summary_proof"]["lower_indextime"], cycle["anchor"]
        )

        migration = self.migration(FakeApi())
        migration._scheduled_writer_cycles = lambda *_args, **_kwargs: [cycle]
        migration._v1_expected_rows = lambda *_args, **_kwargs: {}
        journal = migration.prepare(900_000, 900_300)
        retained = {"rollup_id": "9" * 64, "records": "1", "adm_record": "conversation"}
        migration._query = lambda *_args, **_kwargs: [retained]
        with self.assertRaisesRegex(Refused, "retained rows in its audit window"):
            migration._capture_v1_pre_pause(journal)

    def test_v2_replay_manifest_counts_identical_rows_and_rejects_material_conflicts(
        self,
    ):
        migration = self.migration(FakeApi())
        row = {
            **SIDES["conversation"],
            "scope": "prod/ns-a",
            "client_ip": "10.0.0.1",
            "bytes_c2s": "0",
            "direction_basis": "initiator",
            "first_seen": "100",
            "last_seen": "110",
        }
        manifest = migration._record_map([row, dict(row)], "conversation")
        self.assertEqual(manifest[row["rollup_id"]]["copies"], 2)
        self.assertEqual(manifest[row["rollup_id"]]["content"]["bytes_c2s"], 0)
        for field, corrupt in (
            ("scope", "prod/ns-b"),
            ("bytes_c2s", "1"),
            ("direction_basis", "unknown"),
            ("first_seen", "99"),
            ("last_seen", "111"),
        ):
            with self.subTest(field=field):
                changed = dict(row, **{field: corrupt})
                with self.assertRaisesRegex(Refused, "conflicting material"):
                    migration._record_map([row, changed], "conversation")
        missing_zero = dict(row)
        missing_zero.pop("bytes_c2s")
        with self.assertRaisesRegex(Refused, "conflicting material"):
            migration._record_map([row, missing_zero], "conversation")

    def test_v1_recovery_manifest_allows_exact_replay_but_rejects_corruption(self):
        row = {
            "rollup_id": "9" * 64,
            "records": "2",
            "adm_record": "conversation",
            "scope": "prod/ns-a",
            "client_ip": "10.0.0.1",
            "bytes_c2s": "0",
            "direction_basis": "initiator",
            "first_seen": "100",
            "last_seen": "110",
        }
        manifest = Migration._v1_record_map([row, dict(row)])
        self.assertEqual(manifest[row["rollup_id"]]["copies"], 2)
        changed = dict(row, scope="prod/ns-b")
        with self.assertRaisesRegex(Refused, "conflicts for a stable rollup ID"):
            Migration._v1_record_map([row, changed])

    def test_preexisting_baseline_is_immutable_and_identical_surplus_is_audited(self):
        row = {
            **SIDES["conversation"],
            "source": "adm:conversation",
            "_indextime": 900_100,
            "scope": "prod/ns-a",
        }
        api = FakeApi()
        api.persisted_rows = [dict(row)]
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        baseline = list(journal["preexisting_v2_baseline"])
        api.persisted_rows.append(dict(row))

        migration._verify_preexisting_index(journal, final_pass=True)

        self.assertEqual(journal["preexisting_v2_baseline"], baseline)
        journal["slices"] = []
        migration._write_journal(journal)
        with self.assertRaisesRegex(Refused, "missing or unexpected summary rollups"):
            migration._validate_migration_ingestion_window(journal)

    def test_global_audit_adds_overlapping_manifests_and_checks_physical_multiplicity(
        self,
    ):
        baseline = {
            **SIDES["conversation"],
            "source": "adm:conversation",
            "_indextime": 900_100,
            "scope": "prod/ns-a",
        }
        api = FakeApi()
        api.persisted_rows = [dict(baseline)]
        migration = self.migration(api)
        journal = migration.prepare(900_000, 900_300)
        original_baseline = list(journal["preexisting_v2_baseline"])

        expected = migration._record_map([baseline], "conversation")
        for timestamp in (900_200, 900_250, 900_275):
            api.persisted_rows.append({**baseline, "_indextime": timestamp})
        empty_streams = {
            "conversation": {"state": "verified", "expected": {}},
            "traffic": {"state": "verified", "expected": {}},
        }
        journal["slices"] = [
            {
                "index_bounds": [900_150, 900_210],
                "streams": {
                    **empty_streams,
                    "conversation": {
                        "state": "verified",
                        "expected": expected,
                    },
                },
            },
            {
                "index_bounds": [900_210, 900_300],
                "streams": {
                    **empty_streams,
                    "conversation": {
                        "state": "verified",
                        "expected": expected,
                    },
                },
            },
            {"streams": empty_streams},
        ]
        journal["cutover"] = {
            "scheduled_streams": {
                "conversation": {
                    "cycles": [
                        {
                            "sid": "scheduler__overlap",
                            "index_bounds": [900_300, 900_360],
                            "state": "verified",
                            "expected": expected,
                        }
                    ],
                },
                "traffic": {"cycles": [{"expected": {}}]},
            }
        }
        self.journal.write(journal)

        evidence = migration._validate_migration_ingestion_window(journal)

        self.assertEqual(evidence["rows"], 1)
        self.assertEqual(journal["preexisting_v2_baseline"], original_baseline)
        # Re-auditing the same immutable intents is a resume, not another copy.
        resumed = migration._validate_migration_ingestion_window(journal)
        self.assertEqual(resumed["rows"], 1)
        del api.persisted_rows[-1:]
        with self.assertRaisesRegex(Refused, "missing or unexpected summary rollups"):
            migration._validate_migration_ingestion_window(journal)
        api.persisted_rows.append({**baseline, "_indextime": 900_275})
        api.persisted_rows.append({**baseline, "_indextime": 900_280})
        api.persisted_rows.append({**baseline, "_indextime": 900_285})
        with self.assertRaisesRegex(Refused, "missing or unexpected summary rollups"):
            migration._validate_migration_ingestion_window(journal)

    def test_cutover_and_rollback_fail_closed_without_public_surface_evidence(self):
        migration = self.migration()
        with self.assertRaises(Refused):
            migration.cutover()
        with self.assertRaises(Refused):
            migration.rollback()

    def test_partial_cutover_rolls_back_journaled_targets(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, interface_hash = migration._interface()
        origin = migration.snapshot()
        mutations = migration._build_cutover_mutations({"origin": origin}, interface)
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "partial-cutover-test",
            "interface_sha256": interface_hash,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "phase": "cutover_in_progress",
            "cutover": {
                "state": "in_progress",
                "mutations": mutations,
                "scenario": {},
            },
            "jobs": [],
        }
        migration._write_journal(journal)
        migration._apply_mutation(journal, mutations[0])
        migration._public_selector_smoke = lambda *_args, **_kwargs: []

        result = migration.rollback()

        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(
            str(api.searches["ADM - Conversation rollup"]["disabled"]), "1"
        )
        self.assertEqual(api.macros["adm_data_contract_version"], "1")

    def test_rollback_resumes_v1_but_keeps_public_v2_state_until_recovery(self):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        interface, interface_hash = migration._interface()
        origin = migration.snapshot()
        mutations = migration._build_cutover_mutations({"origin": origin}, interface)
        for selector in interface["activation"]["cutover_selectors"]:
            api.macros[selector["name"]] = selector["after"]
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "rollback-needs-v1-recovery",
            "interface_sha256": interface_hash,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "phase": "cutover_in_progress",
            "cutover": {
                "state": "in_progress",
                "started_at": 999_000,
                "mutations": mutations,
                "scenario": {},
            },
            "created_at": 900_000,
            "v1_pre_pause": {
                "index_bounds": [998_700, 999_000],
                "event_bounds": {"earliest_time": "912600", "latest_time": "999900"},
                "expected": {},
                "expected_fingerprint": fingerprint({}),
            },
            "jobs": [],
        }
        migration._write_journal(journal)
        migration._apply_mutation(journal, mutations[0])
        writes_before = sum(method == "POST" for method, _, _ in api.calls)

        result = migration.rollback()

        self.assertEqual(result["status"], "awaiting_v1_recovery")
        self.assertEqual(
            self.journal.read()["rollback"]["state"], "awaiting_v1_recovery"
        )
        self.assertEqual(
            sum(method == "POST" for method, _, _ in api.calls), writes_before + 1
        )
        self.assertEqual(
            str(api.searches["ADM - Conversation rollup"]["disabled"]), "0"
        )
        self.assertEqual(api.macros["adm_data_contract_version"], "2")

    def test_enabled_origin_rollback_uses_fresh_immutable_resume_epoch(self):
        api = FakeApi()
        api.searches["ADM - Conversation rollup"]["disabled"] = "0"
        migration = self.migration(api)
        interface, interface_hash = migration._interface()
        origin = migration.snapshot()
        forward = migration._build_cutover_mutations({"origin": origin}, interface)
        for mutation in forward:
            mutation.update(state="applied", verified_at=999_100)
            if mutation["kind"] == "macro_definition":
                api.macros[mutation["name"]] = mutation["after"]
                if "args" in mutation:
                    api.macro_args[mutation["name"]] = mutation["args"]
            else:
                api.searches[mutation["name"]][mutation["field"]] = mutation["after"]
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "rollback-fresh-resume-epoch",
            "interface_sha256": interface_hash,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "phase": "cutover",
            "cutover": {
                "state": "complete",
                "started_at": 999_000,
                "mutations": forward,
                "scenario": {},
            },
            "v1_pre_pause": {"index_bounds": [998_700, 999_000]},
            "jobs": [],
        }
        migration._write_journal(journal)
        now = [1_000_000]
        migration.clock = lambda: now[0]
        migration._public_selector_smoke = lambda *_args, **_kwargs: []
        recovery_calls = []

        def wait_then_recover(current_journal, resume_epoch):
            recovery_calls.append(resume_epoch)
            return None if len(recovery_calls) == 1 else {"state": "verified"}

        migration._v1_recovery_window = wait_then_recover

        first = migration.rollback()
        checkpoint = self.journal.read()
        v1_restore = next(
            item
            for item in checkpoint["rollback"]["mutations"]
            if item.get("name") == "ADM - Conversation rollup"
            and item.get("field") == "disabled"
        )
        self.assertEqual(first["status"], "awaiting_v1_recovery")
        self.assertEqual(v1_restore["verified_at"], 1_000_000)
        self.assertEqual(
            checkpoint["rollback"]["v1_recovery"]["resume_activation_epoch"],
            1_000_000,
        )
        self.assertNotEqual(v1_restore["verified_at"], 999_100)

        now[0] += 900
        second = migration.rollback()
        checkpoint = self.journal.read()
        v1_restore = next(
            item
            for item in checkpoint["rollback"]["mutations"]
            if item.get("name") == "ADM - Conversation rollup"
            and item.get("field") == "disabled"
        )
        self.assertEqual(second["status"], "rolled_back")
        self.assertEqual(recovery_calls, [1_000_000, 1_000_000])
        self.assertEqual(v1_restore["verified_at"], 1_000_000)

    def test_rollback_refuses_drift_in_an_unapplied_selector(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, interface_hash = migration._interface()
        origin = migration.snapshot()
        mutations = migration._build_cutover_mutations({"origin": origin}, interface)
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": "rollback-drift-test",
            "interface_sha256": interface_hash,
            "origin": origin,
            "origin_fingerprint": fingerprint(origin),
            "phase": "cutover_in_progress",
            "cutover": {"state": "in_progress", "mutations": mutations},
            "jobs": [],
        }
        migration._write_journal(journal)
        migration._apply_mutation(journal, mutations[0])
        api.macros["adm_graph(4)"] = "operator-change"

        with self.assertRaises(Refused):
            migration.rollback()

    def test_parameterized_macro_update_preserves_args_on_apply_and_rollback(self):
        expected_args = "service, environment, cluster, namespace"
        for origin_args, return_list in (
            (expected_args, True),
            (expected_args.split(", "), False),
        ):
            with self.subTest(origin_args=origin_args, return_list=return_list):
                api = FakeApi()
                api.macro_args["adm_graph(4)"] = origin_args
                api.return_macro_args_as_list = isinstance(origin_args, list)
                migration = self.migration(api)
                interface, _ = migration._interface()
                origin = migration.snapshot()
                mutation = next(
                    item
                    for item in migration._build_cutover_mutations(
                        {"origin": origin}, interface
                    )
                    if item["name"] == "adm_graph(4)"
                )
                self.assertEqual(mutation["args"], origin_args)
                api.return_macro_args_as_list = return_list
                journal = {
                    "origin": origin,
                    "origin_fingerprint": fingerprint(origin),
                    "cutover": {"mutations": [mutation]},
                    "phase": "cutover_in_progress",
                    "jobs": [],
                }
                migration._apply_mutation(journal, mutation)
                apply_posts = [
                    data
                    for method, path, data in api.calls
                    if method == "POST" and path == mutation["rest_target"]
                ]
                self.assertEqual(
                    apply_posts[-1],
                    {"definition": mutation["after"], "args": expected_args},
                )
                migration._assert_cutover_origin_compatible(journal)

                rollback_mutation = {
                    **mutation,
                    "before": mutation["after"],
                    "after": mutation["before"],
                    "state": "pending",
                }
                migration._apply_mutation(journal, rollback_mutation)
                rollback_posts = [
                    data
                    for method, path, data in api.calls
                    if method == "POST" and path == mutation["rest_target"]
                ]
                self.assertEqual(
                    rollback_posts[-1],
                    {"definition": mutation["before"], "args": expected_args},
                )

    def test_parameterized_macro_missing_args_is_rejected_by_rest_mock(self):
        api = FakeApi()
        interface, _ = self.migration(api)._interface()
        mutation = next(
            item
            for item in interface["activation"]["cutover_selectors"]
            if item["name"] == "adm_graph(4)"
        )
        with self.assertRaisesRegex(Refused, "requires args"):
            api.request(
                "POST",
                mutation["rest_target"],
                {"definition": mutation["after"]},
            )
        self.assertEqual(api.macros["adm_graph(4)"], mutation["before"])

    def test_parameterized_macro_args_reject_malformed_types_and_arity(self):
        for malformed in (None, 4, ["service", 4], "service, environment"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(Refused):
                    Migration._macro_args_parts("adm_graph(4)", malformed)

    def test_parameterized_macro_argument_drift_refuses_without_post(self):
        api = FakeApi()
        migration = self.migration(api)
        interface, _ = migration._interface()
        origin = migration.snapshot()
        mutation = next(
            item
            for item in migration._build_cutover_mutations(
                {"origin": origin}, interface
            )
            if item["name"] == "adm_graph(4)"
        )
        api.macro_args["adm_graph(4)"] = "changed, arguments, from, operator"

        with self.assertRaisesRegex(Refused, "arguments drifted"):
            migration._apply_mutation({"phase": "cutover_in_progress"}, mutation)

        self.assertFalse(
            any(
                method == "POST" and path == mutation["rest_target"]
                for method, path, _ in api.calls
            )
        )

    def test_drift_in_legacy_reader_macro_refuses_resume(self):
        api = FakeApi()
        migration = self.migration(api)
        migration.prepare(900_000, 900_300)
        api.macros["adm_summary_index_name"] = "adm_summary_v2"
        with self.assertRaises(Refused):
            migration.backfill()


if __name__ == "__main__":
    unittest.main()
