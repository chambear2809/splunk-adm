"""Bounded insert-only KV collection adapter. Collection POST uniqueness arbitrates."""

import json
from urllib.parse import urlencode

from .ledger import Forbidden, Unavailable, canonical

APP = "/servicesNS/nobody/splunk_adm"


class SplunkCollectionStore:
    def __init__(self, session_key, collection):
        if not isinstance(collection, str) or not collection.startswith("adm_"):
            raise Unavailable("Unsupported collection.")
        self.session_key = session_key
        self.collection = collection
        self.path = APP + "/storage/collections/data/" + collection

    def request(self, method, path, body=None, query=None):
        import splunk.rest

        if query:
            path += "?" + urlencode(query)
        response, data = splunk.rest.simpleRequest(
            path,
            sessionKey=self.session_key,
            method=method,
            jsonargs=canonical(body) if body is not None else None,
            rawResult=True,
            raiseAllErrors=False,
        )
        status = int(response.status)
        if status in (401, 403):
            raise Forbidden("Collection access is denied.")
        if status >= 300:
            raise Unavailable("Splunk collection request failed.")
        if not data:
            return None
        return json.loads(data)

    def allows_write(self, capability):
        context = self.request(
            "GET",
            "/services/authentication/current-context",
            query={"output_mode": "json"},
        )
        entries = context.get("entry") if isinstance(context, dict) else None
        content = (
            entries[0].get("content")
            if isinstance(entries, list)
            and len(entries) == 1
            and isinstance(entries[0], dict)
            else {}
        )
        caps = content.get("capabilities") if isinstance(content, dict) else None
        permissions = self.request(
            "GET",
            APP + "/storage/collections/config/" + self.collection,
            query={"output_mode": "json"},
        )
        entry = (
            permissions.get("entry", [{}])[0] if isinstance(permissions, dict) else {}
        )
        acl = (entry.get("acl") if isinstance(entry, dict) else None) or (
            entry.get("content", {}).get("eai:acl", {})
            if isinstance(entry, dict)
            else {}
        )
        return (
            isinstance(caps, list)
            and capability in caps
            and acl.get("can_write")
            in (
                True,
                1,
                "1",
            )
        )

    def scan(self, limit):
        for _attempt in range(2):
            rows = self.request(
                "GET", self.path, query={"limit": limit, "skip": 0, "sort": "_key:1"}
            )
            if not isinstance(rows, list) or len(rows) > limit:
                raise Unavailable("Collection scan is malformed.")
            keys = [row.get("_key") if isinstance(row, dict) else None for row in rows]
            if not all(isinstance(key, str) and key for key in keys) or keys != sorted(
                set(keys)
            ):
                raise Unavailable("Collection scan is not uniquely ordered.")
            if len(rows) == limit:
                return rows
            shifted = self.request(
                "GET", self.path, query={"limit": limit, "skip": 1, "sort": "_key:1"}
            )
            if shifted == rows[1:]:
                return rows
        raise Unavailable(
            "Collection scan is capped or changed during its completion proof."
        )

    def insert(self, document):
        return self.request("POST", self.path, body=document)
