"""Owned-lab-only lifecycle for disposable deployment-settings fixture data."""

import json

COLLECTION = (
    "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_deployment_settings"
)
ENDPOINT = "/servicesNS/nobody/splunk_adm/adm/deployment-settings"
CONFIG = "/servicesNS/nobody/splunk_adm/configs/conf-adm_settings/persistence"


class SettingsFixture:
    def __init__(self, case, enable_writes=True):
        import lab
        from test_permissions import _response

        self.case, self.lab, self.response = case, lab, _response
        self.password = lab.read_secrets()["SPLUNK_PASSWORD"]
        self.original = self.rows()
        case.assertLess(
            len(self.original), 1024, "Settings fixture refuses a capped collection"
        )
        self.config = lab._json("GET", CONFIG)["entry"][0]["content"]
        case.addCleanup(self.restore)
        if enable_writes:
            lab._json(
                "POST",
                CONFIG,
                {"write_mode": "single_namespace", "platform": "enterprise"},
            )

    def request(
        self, method, path=ENDPOINT, payload=None, username="admin", password=None
    ):
        # Splunk permission/absent-row errors default to XML even when KV data
        # and successful custom endpoint responses are JSON.
        path += ("&" if "?" in path else "?") + "output_mode=json"
        status, body = self.response(
            method,
            path,
            username,
            password or self.password,
            None if payload is None else json.dumps(payload).encode(),
            "application/json",
        )
        return status, json.loads(body) if body else None

    def rows(self):
        status, rows = self.request(
            "GET", COLLECTION + "?limit=1025&skip=0&sort=_key:1"
        )
        self.case.assertEqual(status, 200)
        self.case.assertIsInstance(rows, list)
        self.case.assertLess(
            len(rows), 1025, "Settings fixture refuses an over-limit backup"
        )
        status, shifted = self.request(
            "GET", COLLECTION + "?limit=1025&skip=1&sort=_key:1"
        )
        self.case.assertEqual(status, 200)
        self.case.assertEqual(
            shifted, rows[1:], "Settings fixture refuses a capped or changing backup"
        )
        return [
            {key: value for key, value in row.items() if key != "_user"} for row in rows
        ]

    def clear(self):
        status, _ = self.request("DELETE", COLLECTION)
        self.case.assertIn(status, (200, 204))

    def restore(self):
        self.clear()
        for row in self.original:
            status, _ = self.request("POST", COLLECTION, row)
            self.case.assertIn(status, (200, 201))
        self.case.assertEqual(
            sorted(self.rows(), key=lambda row: row["_key"]),
            sorted(self.original, key=lambda row: row["_key"]),
        )
        self.lab._json(
            "POST",
            CONFIG,
            {
                key: self.config.get(key, default)
                for key, default in (
                    ("write_mode", "disabled"),
                    ("platform", "unqualified"),
                )
            },
        )
