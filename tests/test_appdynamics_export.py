from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request
from xml.etree import ElementTree as ET

from tools.export_appdynamics import (
    CollectionError,
    ControllerClient,
    Limits,
    _NETWORK_REQUEST_SLOT,
    _outside_repository as exporter_outside_repository,
    _parse_properties,
    _xml_root,
    collect_snapshot,
    main as export_main,
)
from tools.import_appdynamics import (
    ImportErrorDetail,
    MAX_HEC_LINE_BYTES,
    _asset_history_output,
    _number,
    _outside_repository as importer_outside_repository,
    _read_json,
    convert_snapshot,
    main as import_main,
    render_appdynamics_ndjson,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "appdynamics"


class CounterClock:
    def __init__(self) -> None:
        self.value = 1_800_000_000.0

    def __call__(self) -> float:
        self.value += 0.25
        return self.value


class Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body)
        value = self.body[self.offset : self.offset + size]
        self.offset += len(value)
        return value


class FakeOpener:
    def __init__(self, *, overrides: dict[str, bytes] | None = None) -> None:
        self.calls: list[tuple[Request, int]] = []
        self.overrides = overrides or {}
        self.redirect_path: str | None = None

    def open(self, request: Request, timeout: int) -> Response:
        self.calls.append((request, timeout))
        path = urlsplit(request.full_url).path
        if path == "/controller/api/oauth/access_token":
            return Response(b'{"access_token":"test-token","expires_in":300}')
        if path == self.redirect_path:
            raise HTTPError(
                "https://controller.example.test" + path,
                302,
                "redirect",
                {"Location": "https://other.example.test/steal"},
                None,
            )
        if path in self.overrides:
            return Response(self.overrides[path])
        fixture = {
            "/controller/rest/applications": "applications.xml",
            "/controller/rest/applications/101/tiers": "application-101-tiers.xml",
            "/controller/rest/applications/101/tiers/7/nodes": "application-101-tier-7-nodes.xml",
            "/controller/rest/applications/101/backends": "application-101-backends.xml",
            "/controller/rest/applications/202/tiers": "application-202-tiers.xml",
            "/controller/rest/applications/202/tiers/8/nodes": "application-202-tier-8-nodes.xml",
            "/controller/rest/applications/202/backends": "application-202-backends.xml",
        }.get(path)
        if fixture is None:
            raise AssertionError(f"Unexpected Controller API path {path}")
        return Response((FIXTURES / fixture).read_bytes())


def collect(opener: FakeOpener | None = None, *, authority: str = "appd-prod"):
    return collect_snapshot(
        controller_origin="https://controller.example.test",
        controller_authority=authority,
        scope="prod-east",
        api_client="atlas-readonly",
        account_name="customer-one",
        client_secret="do-not-log-this-secret",
        now=CounterClock(),
        monotonic=lambda: 100.0,
        sleep=lambda _seconds: None,
        opener=opener or FakeOpener(),
    )


class AppDynamicsCollectorTests(unittest.TestCase):
    def test_collects_documented_read_only_model_and_current_node_ip_manifest(
        self,
    ) -> None:
        opener = FakeOpener()
        bundle, asset_manifest = collect(opener)

        self.assertEqual(bundle["schema"], "application_atlas.appdynamics_inventory.v1")
        self.assertTrue(bundle["snapshot_complete"])
        self.assertGreater(bundle["collection_skew_seconds"], 0)
        self.assertEqual(bundle["record_counts"]["applications"], 2)
        self.assertEqual(bundle["record_counts"]["nodes"], 2)
        self.assertEqual(bundle["record_counts"]["backends"], 3)
        self.assertEqual(bundle["record_counts"]["node_ip_addresses"], 3)
        self.assertEqual(asset_manifest["snapshot_complete"], True)
        self.assertEqual(len(asset_manifest["records"]), 3)
        self.assertTrue(
            all(
                row["validity_basis"] == "snapshot_current"
                for row in asset_manifest["records"]
            )
        )
        self.assertTrue(all("valid_to" not in row for row in asset_manifest["records"]))
        self.assertTrue(
            all("retired_at" not in row for row in asset_manifest["records"])
        )
        self.assertIn(
            "application:101:tier:7:node:3", asset_manifest["records"][0]["asset_id"]
        )
        self.assertIn(
            "application:202:tier:8:node:3", asset_manifest["records"][-1]["asset_id"]
        )

        node = next(row for row in bundle["records"] if row["record_type"] == "node")
        self.assertEqual(node["ip_addresses"][0]["ip"], "10.20.0.17")
        self.assertEqual(node["ip_addresses"][1]["ip"], "2001:db8::17")
        self.assertFalse(node["ip_addresses"][2]["matchable"])
        self.assertEqual(
            node["ip_addresses"][2]["status"], "zone_scoped_address_unmatchable"
        )

        node_requests = [
            request.full_url
            for request, _timeout in opener.calls
            if request.full_url.endswith("/nodes")
        ]
        self.assertEqual(
            node_requests,
            [
                "https://controller.example.test/controller/rest/applications/101/tiers/7/nodes",
                "https://controller.example.test/controller/rest/applications/202/tiers/8/nodes",
            ],
        )
        self.assertTrue(
            all(request.method in {"GET", "POST"} for request, _ in opener.calls)
        )
        self.assertTrue(all(timeout == 20 for _request, timeout in opener.calls))

    def test_backend_ids_are_verified_only_against_same_snapshot_and_secrets_are_redacted(
        self,
    ) -> None:
        bundle, _asset_manifest = collect()
        backends = [row for row in bundle["records"] if row["record_type"] == "backend"]
        checkout = next(
            row
            for row in backends
            if row["application_id"] == 101 and row["backend_id"] == 55
        )
        unresolved = next(row for row in backends if row["backend_id"] == 56)
        shared = next(row for row in backends if row["application_id"] == 202)

        self.assertEqual(checkout["association_status"], "verified_node")
        self.assertEqual(checkout["verified_node_id"], 3)
        self.assertEqual(unresolved["association_status"], "application_scope_only")
        self.assertEqual(shared["association_status"], "application_scope_only")
        self.assertEqual(
            unresolved["endpoint_candidates"],
            [
                {
                    "property": "HOST",
                    "kind": "hostname_unresolved",
                    "value": "payments-db.internal",
                },
                {"property": "PORT", "kind": "port", "value": 443},
            ],
        )

        url = next(prop for prop in checkout["properties"] if prop["name"] == "URL")
        password = next(
            prop for prop in checkout["properties"] if prop["name"] == "PASSWORD"
        )
        self.assertEqual(url["value"], "jdbc:mysql://db.example:3306/orders")
        self.assertTrue(password["redacted"])
        self.assertIsNone(password["value"])
        self.assertNotIn("dbpass", json.dumps(bundle))
        self.assertNotIn("query-secret", json.dumps(bundle))
        self.assertNotIn("property-secret", json.dumps(bundle))

    def test_authority_namespaces_colliding_ids_across_controllers(self) -> None:
        first, first_history = collect(authority="controller-east")
        second, second_history = collect(authority="controller-west")
        first_node = next(
            row for row in first["records"] if row["record_type"] == "node"
        )
        second_node = next(
            row for row in second["records"] if row["record_type"] == "node"
        )
        self.assertEqual(first_node["node_id"], second_node["node_id"])
        self.assertNotEqual(
            first_node["controller_authority"], second_node["controller_authority"]
        )
        self.assertNotEqual(
            first_history["records"][0]["asset_id"],
            second_history["records"][0]["asset_id"],
        )

    def test_empty_snapshot_is_explicit_and_does_not_emit_retirement_rows(self) -> None:
        opener = FakeOpener(
            overrides={"/controller/rest/applications": b"<applications/>"}
        )
        bundle, asset_manifest = collect(opener)
        self.assertEqual(len(bundle["records"]), 1)
        self.assertTrue(bundle["records"][0]["empty_inventory"])
        self.assertTrue(bundle["snapshot_complete"])
        self.assertEqual(asset_manifest["records"], [])

    def test_oauth_secret_is_form_encoded_only_for_configured_origin(self) -> None:
        opener = FakeOpener()
        collect(opener)
        token_request = opener.calls[0][0]
        self.assertEqual(token_request.method, "POST")
        self.assertEqual(
            token_request.full_url,
            "https://controller.example.test/controller/api/oauth/access_token",
        )
        payload = parse_qs(token_request.data.decode("utf-8"))
        self.assertEqual(payload["grant_type"], ["client_credentials"])
        self.assertEqual(payload["client_id"], ["atlas-readonly@customer-one"])
        self.assertEqual(payload["client_secret"], ["do-not-log-this-secret"])
        self.assertNotIn("Authorization", token_request.headers)

    def test_redirect_is_rejected_without_following_the_target(self) -> None:
        opener = FakeOpener()
        opener.redirect_path = "/controller/rest/applications"
        with self.assertRaises(CollectionError) as raised:
            collect(opener)
        self.assertEqual(raised.exception.code, "redirect_rejected")
        self.assertEqual(len(opener.calls), 2)
        self.assertTrue(
            all("other.example.test" not in req.full_url for req, _ in opener.calls)
        )

    def test_malformed_or_entity_expansion_xml_is_rejected(self) -> None:
        from tools.export_appdynamics import _xml_root

        with self.assertRaises(CollectionError):
            _xml_root(
                b"<!DOCTYPE applications [<!ENTITY x 'boom'>]><applications/>",
                "applications",
            )

    def test_controller_origin_must_be_exact_https_origin(self) -> None:
        for origin in (
            "http://controller.example.test",
            "https://user:password@controller.example.test",
            "https://controller.example.test/controller",
            "https://controller.example.test/?redirect=1",
        ):
            with self.subTest(origin=origin), self.assertRaises(CollectionError):
                collect_snapshot(
                    controller_origin=origin,
                    controller_authority="appd-prod",
                    scope="prod-east",
                    api_client="reader",
                    account_name="customer",
                    client_secret="secret",
                    opener=FakeOpener(),
                )

    def test_importer_renders_versioned_appd_and_asset_history_captures(self) -> None:
        bundle, asset_manifest = collect()
        bundle["asset_history_manifest"] = asset_manifest
        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            root = Path(directory)
            snapshot = root / "snapshot.json"
            snapshot.write_text(json.dumps(bundle), encoding="utf-8")
            outputs, report = convert_snapshot(snapshot)

        appd_envelopes = [
            json.loads(line)
            for line in outputs["appdynamics.ndjson"].decode().splitlines()
        ]
        asset_envelopes = [
            json.loads(line)
            for line in outputs["asset_history.ndjson"].decode().splitlines()
        ]
        self.assertEqual(len(appd_envelopes), bundle["record_counts"]["total_records"])
        self.assertEqual(len(asset_envelopes), 3)
        self.assertEqual(report["asset_history_conflict_count"], 1)
        self.assertEqual(
            {item["sourcetype"] for item in appd_envelopes},
            {"adm:appdynamics_inventory"},
        )
        self.assertEqual(
            {item["sourcetype"] for item in asset_envelopes}, {"adm:asset_history"}
        )
        self.assertTrue(
            all(
                item["event"]["snapshot_id"] == bundle["snapshot_id"]
                for item in appd_envelopes
            )
        )
        serialized = outputs["appdynamics.ndjson"].decode()
        self.assertNotIn("do-not-log-this-secret", serialized)
        self.assertNotIn("dbpass", serialized)
        self.assertNotIn("query-secret", serialized)
        self.assertNotIn("property-secret", serialized)

    def test_importer_refuses_partial_snapshot_and_mismatched_node_manifest(
        self,
    ) -> None:
        bundle, asset_manifest = collect()
        bundle["asset_history_manifest"] = asset_manifest
        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            snapshot = Path(directory) / "snapshot.json"
            bundle["snapshot_complete"] = False
            snapshot.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaises(ImportErrorDetail) as partial:
                convert_snapshot(snapshot)
            self.assertEqual(partial.exception.code, "incomplete_snapshot")

            bundle, asset_manifest = collect()
            asset_manifest["records"][0]["ip"] = "192.0.2.99"
            bundle["asset_history_manifest"] = asset_manifest
            snapshot.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaises(ImportErrorDetail) as mismatch:
                convert_snapshot(snapshot)
            self.assertEqual(mismatch.exception.code, "asset_history_manifest_mismatch")

    def test_empty_complete_snapshot_renders_no_asset_claims(self) -> None:
        opener = FakeOpener(
            overrides={"/controller/rest/applications": b"<applications/>"}
        )
        bundle, asset_manifest = collect(opener)
        bundle["asset_history_manifest"] = asset_manifest
        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(bundle), encoding="utf-8")
            outputs, report = convert_snapshot(snapshot)
        self.assertEqual(report["asset_history_records"], 0)
        self.assertEqual(outputs["asset_history.ndjson"], b"")
        appd = [
            json.loads(line)
            for line in outputs["appdynamics.ndjson"].decode().splitlines()
        ]
        self.assertEqual(len(appd), 1)
        self.assertEqual(appd[0]["event"]["record_type"], "snapshot")
        self.assertTrue(appd[0]["event"]["empty_inventory"])

    def test_importer_writes_private_outputs_and_refuses_overwrite(self) -> None:
        bundle, asset_manifest = collect()
        bundle["asset_history_manifest"] = asset_manifest
        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            root = Path(directory)
            snapshot = root / "snapshot.json"
            appd_output = root / "appd.ndjson"
            asset_output = root / "asset.ndjson"
            report = root / "report.json"
            snapshot.write_text(json.dumps(bundle), encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = import_main(
                    [
                        str(snapshot),
                        "--appd-output",
                        str(appd_output),
                        "--asset-history-output",
                        str(asset_output),
                        "--report",
                        str(report),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue(
                all(path.exists() for path in (appd_output, asset_output, report))
            )
            self.assertTrue(
                all(
                    path.stat().st_mode & 0o777 == 0o600
                    for path in (appd_output, asset_output, report)
                )
            )
            self.assertNotIn("do-not-log-this-secret", stdout.getvalue())

            asset_output.unlink()
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = import_main(
                    [
                        str(snapshot),
                        "--appd-output",
                        str(appd_output),
                        "--asset-history-output",
                        str(asset_output),
                        "--report",
                        str(root / "second-report.json"),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertFalse(asset_output.exists())
            self.assertFalse((root / "second-report.json").exists())
            self.assertIn('"error": "output_exists"', stderr.getvalue())

    def test_xml_rejects_late_and_utf16_doctypes(self) -> None:
        late_doctype = (
            b'<?xml version="1.0"?>'
            + b" " * 5000
            + b"<!DOCTYPE applications [<!ENTITY x 'expanded'>]>"
            + b"<applications>&x;</applications>"
        )
        utf16_doctype = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            + " " * 5000
            + "<!DOCTYPE applications [<!ENTITY x 'expanded'>]>"
            + "<applications>&x;</applications>"
        ).encode("utf-16")
        for payload in (late_doctype, utf16_doctype):
            with self.subTest(encoding=payload[:2]), self.assertRaises(CollectionError):
                _xml_root(payload, "applications")

    def test_importer_rejects_nonfinite_numbers_and_json_constants(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ImportErrorDetail):
                _number(value)

        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            snapshot = Path(directory) / "nonfinite.json"
            for encoded in ('{"value":NaN}', '{"value":1e400}'):
                snapshot.write_text(encoded, encoding="ascii")
                with (
                    self.subTest(encoded=encoded),
                    self.assertRaises(ImportErrorDetail) as raised,
                ):
                    _read_json(snapshot)
                self.assertEqual(raised.exception.code, "invalid_json")

    def test_importer_bounds_file_read_and_hec_record_lines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            snapshot = Path(directory) / "oversized.json"
            snapshot.write_bytes(b" " * 17)
            with patch("tools.import_appdynamics.MAX_INPUT_BYTES", 16):
                with self.assertRaises(ImportErrorDetail) as too_large:
                    _read_json(snapshot)
        self.assertEqual(too_large.exception.code, "input_size_limit")

        with self.assertRaises(ImportErrorDetail) as appd_line:
            render_appdynamics_ndjson(
                [{"snapshot_at": 1, "large_value": "x" * MAX_HEC_LINE_BYTES}]
            )
        self.assertEqual(appd_line.exception.code, "record_size_limit")

        with (
            patch(
                "tools.import_appdynamics.prepare",
                return_value=([], {"authority": "appd-prod"}, 0, 0),
            ),
            patch("tools.import_appdynamics.find_conflicts", return_value=([], 0)),
            patch(
                "tools.import_appdynamics.render_asset_history_ndjson",
                return_value="x" * (MAX_HEC_LINE_BYTES + 1),
            ),
        ):
            with self.assertRaises(ImportErrorDetail) as asset_line:
                _asset_history_output({"authority": "appd-prod", "records": []})
        self.assertEqual(asset_line.exception.code, "record_size_limit")

    def test_unknown_backend_connection_values_do_not_retain_credentials(self) -> None:
        backend = ET.fromstring(
            """<backend><properties>
            <name-value><name>CUSTOM_ENDPOINT</name>
            <value>https://url-user:url-pass@db.example/orders?token=query-secret</value>
            </name-value>
            <name-value><name>UNRECOGNIZED_CONNECTION</name>
            <value>Data Source=db.example;User Id=svc;Password=connection-secret</value>
            </name-value>
            <name-value><name>UNKNOWN_USERINFO</name>
            <value>Data Source=db.example;User Id=svc;Encrypt=true</value>
            </name-value>
            </properties></backend>"""
        )
        properties = _parse_properties(backend)
        by_name = {item["name"]: item["value"] for item in properties}
        self.assertEqual(by_name["CUSTOM_ENDPOINT"], "https://db.example/orders")
        self.assertIsNone(by_name["UNRECOGNIZED_CONNECTION"])
        self.assertIsNone(by_name["UNKNOWN_USERINFO"])
        encoded = json.dumps(properties)
        for secret in ("url-user", "url-pass", "query-secret", "connection-secret"):
            self.assertNotIn(secret, encoded)

    def test_bearer_token_rejects_header_injection_and_non_ascii(self) -> None:
        for token in ("good\r\nInjected: yes", "tökén", "bad token"):

            class TokenOpener:
                def open(self, request: Request, timeout: float) -> Response:
                    return Response(
                        json.dumps({"access_token": token, "expires_in": 300}).encode(
                            "utf-8"
                        )
                    )

            client = ControllerClient(
                "https://controller.example.test",
                "reader",
                "customer",
                "secret",
                opener=TokenOpener(),
            )
            with (
                self.subTest(token=token),
                self.assertRaises(CollectionError) as raised,
            ):
                client.authenticate()
            self.assertEqual(raised.exception.code, "invalid_token_response")

    def test_request_wall_clock_timeout_covers_headers_and_body(self) -> None:
        class SlowHeaders:
            def __init__(self) -> None:
                self.release = threading.Event()

            def open(self, request: Request, timeout: float) -> Response:
                self.release.wait(2)
                return Response(b"<applications/>")

        class SlowBodyResponse(Response):
            def __init__(self, body: bytes, release: threading.Event) -> None:
                super().__init__(body)
                self.release = release

            def read(self, size: int = -1) -> bytes:
                self.release.wait(2)
                return super().read(size)

        class SlowBody:
            def __init__(self) -> None:
                self.release = threading.Event()

            def open(self, request: Request, timeout: float) -> Response:
                return SlowBodyResponse(b"<applications/>", self.release)

        for opener in (SlowHeaders(), SlowBody()):
            client = ControllerClient(
                "https://controller.example.test",
                "reader",
                "customer",
                "secret",
                opener=opener,
            )
            with patch("tools.export_appdynamics.REQUEST_TIMEOUT_SECONDS", 0.05):
                started = time.monotonic()
                with self.assertRaises(CollectionError) as raised:
                    client._request("GET", "/controller/rest/applications")
                elapsed = time.monotonic() - started
            self.assertEqual(raised.exception.code, "transport_timeout")
            self.assertLess(elapsed, 0.3)
            opener.release.set()
            deadline = time.monotonic() + 1
            while _NETWORK_REQUEST_SLOT.locked() and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertFalse(_NETWORK_REQUEST_SLOT.locked())

    def test_request_timeout_is_capped_by_collection_deadline(self) -> None:
        class SlowOpener:
            timeout: float | None = None

            def __init__(self) -> None:
                self.release = threading.Event()

            def open(self, request: Request, timeout: float) -> Response:
                self.timeout = timeout
                self.release.wait(2)
                return Response(b"<applications/>")

        opener = SlowOpener()
        client = ControllerClient(
            "https://controller.example.test",
            "reader",
            "customer",
            "secret",
            opener=opener,
        )
        client.limits = Limits(deadline=time.monotonic() + 0.05)
        with patch("tools.export_appdynamics.REQUEST_TIMEOUT_SECONDS", 20):
            with self.assertRaises(CollectionError) as raised:
                client._request("GET", "/controller/rest/applications")
        self.assertEqual(raised.exception.code, "collection_timeout")
        self.assertIsNotNone(opener.timeout)
        self.assertLessEqual(opener.timeout or 1, 0.05)
        opener.release.set()
        deadline = time.monotonic() + 1
        while _NETWORK_REQUEST_SLOT.locked() and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertFalse(_NETWORK_REQUEST_SLOT.locked())

    def test_output_paths_inside_any_git_worktree_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="atlas-appd-git-") as directory:
            checkout = Path(directory) / "sibling-worktree"
            nested = checkout / "output"
            nested.mkdir(parents=True)
            (checkout / ".git").write_text("gitdir: /tmp/example", encoding="utf-8")
            for check in (exporter_outside_repository, importer_outside_repository):
                with (
                    self.subTest(check=check.__module__),
                    self.assertRaises((CollectionError, ImportErrorDetail)),
                ):
                    check(nested / "evidence.json")

    def test_export_cli_sanitizes_unexpected_collection_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="atlas-appd-test-") as directory:
            output = Path(directory) / "snapshot.json"
            stderr = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {
                        "APPD_API_CLIENT_NAME": "reader",
                        "APPD_ACCOUNT_NAME": "customer",
                        "APPD_CLIENT_SECRET": "cli-secret-must-not-print",
                    },
                ),
                patch(
                    "tools.export_appdynamics.collect_snapshot",
                    side_effect=ValueError("cli-secret-must-not-print malformed API"),
                ),
                redirect_stderr(stderr),
            ):
                code = export_main(
                    [
                        "--controller-origin",
                        "https://controller.example.test",
                        "--authority",
                        "appd-prod",
                        "--scope",
                        "prod-east",
                        "--output",
                        str(output),
                    ]
                )
        self.assertEqual(code, 2)
        self.assertIn('"error": "collection_failed"', stderr.getvalue())
        self.assertNotIn("cli-secret-must-not-print", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
