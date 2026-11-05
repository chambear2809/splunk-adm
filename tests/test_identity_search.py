from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin"
sys.path.insert(0, str(ROOT))
from adm_identity_lib.search import (  # noqa: E402
    SearchError,
    NativeSearch,
    bounded_query,
    complete_rows,
)
import admqualified  # noqa: E402


PROFILE = {
    "enabled": True,
    "cluster": "c",
    "environment": "e",
    "scope": "s",
    "producer_id": "p",
    "namespaces": ["shop"],
    "interval_index": "intervals",
    "span_index": "spans",
    "interval_source": "producer",
    "span_source": "otel",
    "interval_sourcetype": "adm:pod_ip_interval:v2",
    "span_sourcetype": "otel:traces",
}


class IdentitySearchTests(unittest.TestCase):
    def test_completion_rejects_mixed_markers(self):
        with self.assertRaises(SearchError):
            complete_rows(
                [
                    {"_atlas_total": "2", "_raw": "{}"},
                    {"_atlas_total": "3", "_raw": "{}"},
                ]
            )

    def test_query_is_bounded_and_filters_after_all_namespace_sources(self):
        query = bounded_query(PROFILE, "graph", namespace="shop", start=100, as_of=200)
        self.assertIn("eventstats count AS _atlas_total", query)
        self.assertIn("head 50001", query)
        self.assertNotIn('namespace="shop"', query)
        self.assertNotIn("inputlookup", query)

    def test_rejects_oversized_graph_window_and_query_injection(self):
        with self.assertRaises(SearchError):
            bounded_query(PROFILE, "graph", start=0, as_of=301)
        with self.assertRaises(SearchError):
            bounded_query(
                PROFILE, "catalog", service='x" | delete', start=100, as_of=200
            )

    def test_completion_requires_exact_total_and_raw_evidence(self):
        rows = [{"_atlas_total": "1", "_raw": "{}"}]
        self.assertEqual(complete_rows(rows), rows)
        with self.assertRaises(SearchError):
            complete_rows([{"_atlas_total": "50001", "_raw": "{}"}])
        with self.assertRaises(SearchError):
            complete_rows([{"_atlas_total": "2", "_raw": "{}"}])
        with self.assertRaises(SearchError):
            complete_rows([{"_atlas_total": "1"}])


def done(**changes):
    result = {
        "dispatchState": "DONE",
        "isDone": True,
        "isFailed": False,
        "isFinalized": False,
        "eventIsTruncated": False,
        "dropCount": 0,
        "resultCount": 1,
        "messages": [],
    }
    result.update(changes)
    return {"entry": [{"content": result}]}


class NativeSearchTests(unittest.TestCase):
    def request(self, metadata=None, page=None):
        calls = []
        row = {"_atlas_total": "1", "_raw": "{}"}

        def request(method, path, data=None):
            calls.append((method, path, data))
            if method == "POST":
                return {"sid": "owned.123"}
            if method == "DELETE":
                return {}
            if "/results?" in path:
                return (
                    page if page is not None else {"preview": False, "results": [row]}
                )
            return metadata if metadata is not None else done()

        return request, calls

    def test_success_uses_bounded_job_and_deletes_only_owned_sid(self):
        request, calls = self.request()
        result = NativeSearch(request).run("search index=example")
        self.assertEqual(result, [{"_atlas_total": "1", "_raw": "{}"}])
        self.assertEqual(calls[0][2]["max_time"], "30")
        self.assertEqual(
            calls[-1][:2], ("DELETE", "/services/search/v2/jobs/owned.123")
        )
        self.assertTrue(any("count=4000&offset=0" in path for _, path, _ in calls))

    def test_finalized_truncated_missing_and_failed_metadata_rejected(self):
        bad = [
            done(isFinalized=True),
            done(eventIsTruncated=True),
            done(resultIsTruncated=True),
            done(dropCount=1),
            done(isFailed=True),
            done(dispatchState="FAILED"),
            done(isDone=False),
            {"entry": []},
        ]
        missing = done()
        del missing["entry"][0]["content"]["isFinalized"]
        bad.append(missing)
        for metadata in bad:
            with self.subTest(metadata=metadata):
                request, calls = self.request(
                    metadata=metadata, page={"preview": False, "results": []}
                )
                with self.assertRaises(SearchError):
                    NativeSearch(request).run("search index=example")
                self.assertEqual(calls[-1][0], "DELETE")

    def test_warnings_error_preview_and_short_page_rejected(self):
        row = {"_atlas_total": "1", "_raw": "{}"}
        bad_pages = [
            {"preview": True, "results": [row]},
            {"preview": False, "results": []},
            {"preview": False, "results": [row], "messages": [{"type": "WARN"}]},
            {"preview": False, "results": [row], "messages": [{"type": "ERROR"}]},
        ]
        for page in bad_pages:
            with self.subTest(page=page):
                request, _ = self.request(page=page)
                with self.assertRaises(SearchError):
                    NativeSearch(request).run("search index=example")

    def test_result_cap_and_deadline_fail_closed(self):
        request, _ = self.request(metadata=done(resultCount=50001))
        with self.assertRaises(SearchError):
            NativeSearch(request).run("search index=example")
        request, calls = self.request(
            metadata=done(dispatchState="RUNNING", isDone=False)
        )
        clock = Mock(side_effect=[0, 0, 0, 0, 46])
        with self.assertRaises(SearchError):
            NativeSearch(request, clock=clock, sleep=Mock()).run("search index=example")
        self.assertEqual(calls[-1][0], "DELETE")

    def test_reads_all_pages_and_rejects_status_warning(self):
        paths = []
        rows = [{"_atlas_total": "4001", "_raw": "{}"} for _ in range(4001)]

        def request(method, path, data=None):
            paths.append(path)
            if method == "POST":
                return {"sid": "owned"}
            if method == "DELETE":
                return {}
            if "offset=4000" in path:
                return {"preview": False, "results": rows[4000:]}
            if "/results?" in path:
                return {"preview": False, "results": rows[:4000]}
            return done(resultCount=4001)

        self.assertEqual(len(NativeSearch(request).run("search index=x")), 4001)
        self.assertTrue(any("offset=4000" in path for path in paths))
        request, _ = self.request(metadata=done(messages=[{"type": "WARN"}]))
        with self.assertRaises(SearchError):
            NativeSearch(request).run("search index=x")

    def test_empty_native_source_requires_completed_unwarned_job(self):
        request, _ = self.request(
            metadata=done(resultCount=0), page={"preview": False, "results": []}
        )
        self.assertEqual(
            NativeSearch(request).run("search index=x", allow_empty=True), []
        )
        request, _ = self.request(
            metadata=done(resultCount=0), page={"preview": False, "results": []}
        )
        with self.assertRaises(SearchError):
            NativeSearch(request).run("search index=x")
        for metadata in [
            done(resultCount=0, isFinalized=True),
            done(resultCount=0, messages=[{"type": "WARN"}]),
        ]:
            request, _ = self.request(
                metadata=metadata, page={"preview": False, "results": []}
            )
            with self.assertRaises(SearchError):
                NativeSearch(request).run("search index=x", allow_empty=True)

    def test_completion_after_deadline_is_rejected(self):
        request, calls = self.request()
        clock = Mock(side_effect=[0, 0, 0, 0, 46])
        with self.assertRaises(SearchError):
            NativeSearch(request, clock=clock, sleep=Mock()).run("search index=x")
        self.assertEqual(calls[-1][0], "DELETE")

    def test_no_cleanup_for_invalid_or_unowned_sid(self):
        request = Mock(return_value={"sid": "../other"})
        with self.assertRaises(SearchError):
            NativeSearch(request).run("search index=example")
        self.assertEqual(request.call_count, 1)

    def test_dispatch_permission_error_never_attempts_cleanup(self):
        request = Mock(side_effect=SearchError("permission denied"))
        with self.assertRaises(SearchError):
            NativeSearch(request).run("search index=example")
        self.assertEqual(request.call_count, 1)


class CommandTests(unittest.TestCase):
    def command(self):
        command = admqualified.AdmQualified()
        command.mode = "catalog"
        command.start, command.as_of = "100", "200"
        command._metadata = SimpleNamespace(
            searchinfo=SimpleNamespace(session_key="caller-key")
        )
        return command

    def test_disabled_profile_never_starts_search(self):
        command = self.command()
        config = Mock()
        config.has_section.return_value = False
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch") as native,
        ):
            with self.assertRaises(SearchError):
                list(command.generate())
            native.assert_not_called()

    def test_invalid_command_bounds_are_search_errors_before_dispatch(self):
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        for field in ("start", "as_of"):
            for value in ("abc", "nan", "inf", "-inf", "1e999"):
                command = self.command()
                setattr(command, field, value)
                with (
                    self.subTest(field=field, value=value),
                    patch.object(
                        admqualified.configparser, "ConfigParser", return_value=config
                    ),
                    patch.object(admqualified, "NativeSearch") as native,
                    self.assertRaises(SearchError),
                ):
                    list(command.generate())
                native.assert_not_called()

    def test_enabled_profile_is_boolean_and_forwards_caller_token(self):
        command = self.command()
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        raw_profile = {**PROFILE, "enabled": "true", "namespaces": "shop"}
        config.__getitem__ = Mock(return_value=raw_profile)
        native = Mock()
        native.run.return_value = ["rows"]
        request = Mock(return_value={"ok": True})
        command._request = request
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch", return_value=native) as factory,
            patch.object(
                admqualified, "reduce_rows", return_value=[{"service": "app"}]
            ) as reducer,
        ):
            self.assertEqual(list(command.generate()), [{"service": "app"}])
            self.assertIs(reducer.call_args.args[1]["enabled"], True)
            callback = factory.call_args.args[0]
            callback("GET", "/services/example")
            request.assert_called_once_with(
                "caller-key", "GET", "/services/example", None
            )

    def test_network_dispatch_and_invalid_config_preflight(self):
        import configparser
        import json

        command = self.command()
        command.mode = "graph"
        command.service, command.environment = "app", "e"
        command.cluster, command.namespace = "c", "shop"
        config = configparser.ConfigParser(interpolation=None)
        config["profile"] = {**PROFILE, "enabled": "true", "namespaces": "shop"}
        config.read = Mock()
        config["network"] = {
            "enabled": "true",
            "profiles_json": json.dumps(
                [
                    {
                        "id": "h",
                        "kind": "hubble",
                        "index": "hubble",
                        "source": "/hubble/",
                        "sourcetype": "cilium:hubble:flow",
                        "scope": "s",
                        "owner_scope": "s",
                        "cluster": "c",
                        "observers": ["node-a"],
                    }
                ]
            ),
            "frontends_json": "[]",
        }
        native = Mock()
        native.run.side_effect = [["identity"], []]
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch", return_value=native),
            patch.object(
                admqualified, "reduce_network_rows", return_value=[{"row_type": "meta"}]
            ) as reducer,
        ):
            self.assertEqual(list(command.generate()), [{"row_type": "meta"}])
            self.assertEqual(native.run.call_count, 2)
            self.assertEqual(native.run.call_args.kwargs, {"allow_empty": True})
            self.assertEqual(reducer.call_args.args[:2], (["identity"], []))
        config["network"]["profiles_json"] = "not-json"
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch") as factory,
        ):
            with self.assertRaises(SearchError):
                list(command.generate())
            factory.assert_not_called()

    def test_sdk_writer_preserves_heterogeneous_graph_columns(self):
        import csv
        from io import BytesIO, StringIO
        from splunklib.searchcommands.internals import RecordWriterV1

        command = self.command()
        command.mode = "graph"
        command.service, command.environment = "app", "prod"
        command.cluster, command.namespace = "c", "shop"
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        output = [
            {"row_type": "node", "id": "a", "label": "a"},
            {
                "row_type": "edge",
                "id": "call",
                "source": "a",
                "target": "b",
                "count": 1,
            },
            {
                "row_type": "meta",
                "nodes": 2,
                "edges": 1,
                "window_start": 100,
                "window_end": 200,
            },
        ]
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch") as native,
            patch.object(admqualified, "reduce_rows", return_value=output),
        ):
            native.return_value.run.return_value = []
            stream = BytesIO()
            writer = RecordWriterV1(stream)
            writer.write_records(command.generate())
            writer.flush(finished=True)
        parsed = list(
            csv.DictReader(StringIO(stream.getvalue().decode().lstrip("\r\n")))
        )
        self.assertEqual(parsed[1]["source"], "a")
        self.assertEqual(parsed[1]["target"], "b")
        self.assertEqual(parsed[1]["count"], "1")
        self.assertEqual(parsed[2]["nodes"], "2")
        self.assertEqual(parsed[2]["edges"], "1")
        self.assertEqual(parsed[2]["window_end"], "200")

    def test_native_transport_merges_pagination_and_forwards_token_kind(self):
        command = self.command()
        rest = SimpleNamespace(
            simpleRequest=Mock(
                return_value=(SimpleNamespace(status=200), b'{"results": []}')
            )
        )
        splunk = ModuleType("splunk")
        splunk.rest = rest
        with patch.dict(sys.modules, {"splunk": splunk, "splunk.rest": rest}):
            for key, bearer in [
                ("caller-key", False),
                ("eyJheader.payload.signature", True),
            ]:
                self.assertEqual(
                    command._request(
                        key,
                        "GET",
                        "/services/search/v2/jobs/owned/results?count=1000&offset=1000",
                    ),
                    {"results": []},
                )
                args, kwargs = rest.simpleRequest.call_args
                self.assertEqual(args, ("/services/search/v2/jobs/owned/results",))
                self.assertEqual(
                    kwargs["getargs"],
                    {"count": "1000", "offset": "1000", "output_mode": "json"},
                )
                self.assertEqual(kwargs["sessionKey"], key)
                self.assertIs(kwargs["token"], bearer)
            with self.assertRaises(SearchError):
                command._request(
                    "caller-key", "GET", "https://external.example/services/search/jobs"
                )

    def test_catalog_bounds_are_integer_and_replayable(self):
        command = self.command()
        command.start, command.as_of = None, None
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified.time, "time", return_value=1000.75),
            patch.object(admqualified, "NativeSearch") as native,
            patch.object(admqualified, "reduce_rows", return_value=[]) as reducer,
        ):
            native.return_value.run.return_value = []
            list(command.generate())
            # Five minutes spans several snapshots, so producer audit gaps
            # cannot leave the catalog without a complete manifest.
            self.assertEqual(reducer.call_args.args[3:5], (685, 985))
            self.assertIn(
                "earliest=685 latest=985", native.return_value.run.call_args.args[0]
            )

    def test_missing_caller_token_never_dispatches_nested_search(self):
        command = self.command()
        command._metadata.searchinfo.session_key = ""
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch") as native,
        ):
            with self.assertRaises(SearchError):
                list(command.generate())
            native.assert_not_called()

    def test_graph_selection_is_propagated_after_full_evidence_search(self):
        command = self.command()
        command.mode = "graph"
        command.service, command.environment = "app", "prod"
        command.cluster, command.namespace = "c", "shop"
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        native = Mock()
        native.run.return_value = ["all-source-rows"]
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch", return_value=native),
            patch.object(admqualified, "reduce_rows", return_value=[]) as reducer,
        ):
            self.assertEqual(list(command.generate()), [])
        self.assertEqual(
            reducer.call_args.args[-1],
            {
                "service": "app",
                "environment": "prod",
                "cluster": "c",
                "namespace": "shop",
            },
        )

    def test_long_graph_window_is_read_as_qualified_slices(self):
        command = self.command()
        command.mode = "graph"
        command.service, command.environment = "app", "prod"
        command.cluster, command.namespace = "c", "shop"
        command.start, command.as_of = "1000", "1900"
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        native = Mock()
        native.run.return_value = ["rows"]
        node = {"row_type": "node", "id": "service:c/shop/app/prod", "kind": "service"}
        windows = []

        def reduce(rows, profile, mode, start, as_of, selection):
            windows.append((start, as_of))
            if start == 1300:
                raise SearchError("identity evidence is empty")
            return [node, {"row_type": "meta", "spans": 2, "warnings": ["w"]}]

        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch", return_value=native),
            patch.object(admqualified, "reduce_rows", side_effect=reduce),
        ):
            out = list(command.generate())
        self.assertEqual(sorted(windows), [(1000, 1300), (1300, 1600), (1600, 1900)])
        meta = [r for r in out if r["row_type"] == "meta"][0]
        self.assertEqual(
            (meta["window_start"], meta["window_end"], meta["spans"]), (1000, 1900, 4)
        )
        # An empty slice was read: it contributes nothing and is no gap.
        self.assertEqual((meta["window_slices"], meta["window_slices_read"]), (3, 3))
        self.assertFalse(any(w.startswith("Read ") for w in meta["warnings"]))
        for query in [c.args[0] for c in native.run.call_args_list]:
            self.assertRegex(
                query, r"earliest=(1000|1300|1600) latest=(1300|1600|1900) "
            )

    def test_long_graph_window_reports_unqualified_slice_as_unread(self):
        command = self.command()
        command.mode = "graph"
        command.service, command.environment = "app", "prod"
        command.cluster, command.namespace = "c", "shop"
        command.start, command.as_of = "1000", "1900"
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        native = Mock()
        native.run.return_value = ["rows"]
        node = {"row_type": "node", "id": "service:c/shop/app/prod", "kind": "service"}

        def reduce(rows, profile, mode, start, as_of, selection):
            if start == 1300:
                raise SearchError("No complete interval snapshot covers the window.")
            return [node, {"row_type": "meta", "spans": 2, "warnings": ["w"]}]

        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch", return_value=native),
            patch.object(admqualified, "reduce_rows", side_effect=reduce),
        ):
            out = list(command.generate())
        meta = [r for r in out if r["row_type"] == "meta"][0]
        self.assertEqual((meta["window_slices"], meta["window_slices_read"]), (3, 2))
        self.assertEqual(meta["read_coverage"], 66)
        self.assertIn("Read 2 of 3 five-minute slices", meta["warnings"][0])

    def test_long_graph_window_fails_closed_on_truncated_slice(self):
        command = self.command()
        command.mode = "graph"
        command.service, command.environment = "app", "prod"
        command.cluster, command.namespace = "c", "shop"
        command.start, command.as_of = "1000", "1900"
        config = Mock()
        config.has_section.side_effect = lambda section: section == "profile"
        config.__getitem__ = Mock(
            return_value={**PROFILE, "enabled": "true", "namespaces": "shop"}
        )
        with (
            patch.object(
                admqualified.configparser, "ConfigParser", return_value=config
            ),
            patch.object(admqualified, "NativeSearch") as native,
            patch.object(
                admqualified,
                "reduce_rows",
                side_effect=SearchError("identity evidence is truncated"),
            ),
        ):
            native.return_value.run.return_value = ["rows"]
            with self.assertRaises(SearchError):
                list(command.generate())


if __name__ == "__main__":
    unittest.main()
