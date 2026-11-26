"""Bounded insert-only KV collection adapter. Collection POST uniqueness arbitrates."""

import json
from urllib.parse import urlencode

from .ledger import Unavailable, canonical

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
            raiseAllErrors=True,
        )
        if int(response.status) >= 300:
            raise Unavailable("Splunk collection request failed.")
        if not data:
            return None
        return json.loads(data)

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
