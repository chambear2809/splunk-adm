from __future__ import annotations

import unittest

from tools.change_activation_transport import (
    BoundedSearchClient,
    CallerProfile,
    LabTransportError,
    _decode_json,
)


class FakeTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def _rest_request(self, method, path, data, *, form_encoded, **kwargs):
        self.calls.append((method, path, data, form_encoded))
        return next(self.responses)

    def _search_owner(self, _profile):
        return "restricted"


class BoundedActivationTransportTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            _decode_json('{"sid":"a","sid":"b"}')

    def test_search_enforces_dispatch_status_and_result_count(self):
        transport = FakeTransport(
            [
                {"status": 201, "body": {"sid": "job-1", "messages": []}},
                {
                    "status": 200,
                    "body": {
                        "entry": [
                            {"content": {"isDone": True, "dispatchState": "DONE"}}
                        ],
                        "messages": [],
                    },
                },
                {"status": 200, "body": {"results": [{"_raw": "ok"}], "messages": []}},
            ]
        )
        rows = BoundedSearchClient(transport, 1).search("index=atlas_changes", "1", "2")
        self.assertEqual(rows, [{"_raw": "ok"}])
        self.assertEqual(transport.calls[0][0], "POST")
        self.assertTrue(transport.calls[0][3])
        self.assertTrue(
            transport.calls[-1][1].endswith("/results?count=2&output_mode=json")
        )

    def test_invalid_sid_fails_closed(self):
        transport = FakeTransport(
            [{"status": 201, "body": {"sid": "bad sid", "messages": []}}]
        )
        with self.assertRaises(LabTransportError):
            BoundedSearchClient(transport, 1).search("index=atlas_changes", "1", "2")

    def test_result_over_cap_fails_closed(self):
        transport = FakeTransport(
            [
                {"status": 201, "body": {"sid": "job-1", "messages": []}},
                {
                    "status": 200,
                    "body": {"entry": [{"content": {"isDone": True}}], "messages": []},
                },
                {"status": 200, "body": {"results": [{}, {}], "messages": []}},
            ]
        )
        with self.assertRaises(LabTransportError):
            BoundedSearchClient(transport, 1).search("index=atlas_changes", "1", "2")

    def test_malformed_message_entries_fail_closed_at_every_stage(self):
        malformed = ["not an object", None]
        for bad in malformed:
            for stage in ("dispatch", "status", "results"):
                with self.subTest(bad=bad, stage=stage):
                    valid_dispatch = {
                        "status": 201,
                        "body": {"sid": "job-1", "messages": []},
                    }
                    valid_status = {
                        "status": 200,
                        "body": {
                            "entry": [{"content": {"isDone": True}}],
                            "messages": [] if stage != "status" else [bad],
                        },
                    }
                    valid_results = {
                        "status": 200,
                        "body": {
                            "results": [],
                            "messages": [] if stage != "results" else [bad],
                        },
                    }
                    if stage == "dispatch":
                        valid_dispatch["body"]["messages"] = [bad]
                    transport = FakeTransport(
                        [valid_dispatch, valid_status, valid_results]
                    )
                    with self.assertRaises(LabTransportError):
                        BoundedSearchClient(transport, 1).search(
                            "index=atlas_changes", "1", "2"
                        )

    def test_permission_message_is_only_special_for_selected_history_query(self):
        transport = FakeTransport(
            [
                {
                    "status": 201,
                    "body": {
                        "sid": "job-1",
                        "messages": [
                            {"type": "WARN", "text": "not authorized to search index"}
                        ],
                    },
                }
            ]
        )
        with self.assertRaises(LabTransportError):
            BoundedSearchClient(
                transport,
                1,
                caller_profile=CallerProfile.HISTORY_DENIED,
                query="search index=other sourcetype=foo",
            ).search("search index=other sourcetype=foo", "1", "2")

    def test_restricted_job_identity_cannot_change(self):
        transport = FakeTransport(
            [{"status": 201, "body": {"sid": "job-1", "messages": []}}]
        )
        client = BoundedSearchClient(
            transport,
            1,
            caller_profile=CallerProfile.HISTORY_DENIED,
            query="search index=other sourcetype=foo",
        )
        client._json(
            "POST",
            "/servicesNS/admin/splunk_adm/search/v2/jobs",
            {
                "search": "search index=other sourcetype=foo",
                "exec_mode": "blocking",
                "earliest_time": "1",
                "latest_time": "2",
            },
        )
        with self.assertRaises(LabTransportError):
            client._json("GET", "/services/search/v2/jobs/job-2")
