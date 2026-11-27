"""Bounded insert-only KV collection adapter. Collection POST uniqueness arbitrates."""

import json
import re
from urllib.parse import urlencode

from .ledger import Forbidden, Unavailable, canonical

APP = "/servicesNS/nobody/splunk_adm"
KEY = re.compile(r"[a-z][a-z0-9_]{0,31}_(?:root|after_[0-9a-f]{64}|epoch_[0-9]{1,7})\Z")
DOC_KEY = re.compile(
    r"(?:[0-9a-f]{64}|[a-z][a-z0-9_]{0,31}_(?:root|after_[0-9a-f]{64}|epoch_[0-9]{1,7}))\Z"
)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_SCAN_LIMIT = 4097
MAX_IN_BATCH = 50
METADATA_FIELDS = (
    "_key,format,epoch,epoch_root,seal,kind,previous_revision,"
    "request_id,operation_fingerprint,revision"
)


class SplunkCollectionStore:
    def __init__(self, session_key, collection):
        if not isinstance(collection, str) or not collection.startswith("adm_"):
            raise Unavailable("Unsupported collection.")
        self.session_key = session_key
        self.collection = collection
        self.path = APP + "/storage/collections/data/" + collection

    @staticmethod
    def _validate_limit(limit):
        if type(limit) is not int or not 1 <= limit <= MAX_SCAN_LIMIT:
            raise Unavailable("Unsupported collection read limit.")

    def request(self, method, path, body=None, query=None, absent_ok=False):
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
        if absent_ok and status == 404:
            return None
        if status >= 300:
            raise Unavailable("Splunk collection request failed.")
        if not data:
            return None
        raw_len = len(data.encode("utf-8")) if isinstance(data, str) else len(data)
        if raw_len > MAX_RESPONSE_BYTES:
            raise Unavailable("Splunk collection response exceeds size limit.")
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
        perm_entries = (
            permissions.get("entry") if isinstance(permissions, dict) else None
        )
        entry = (
            perm_entries[0]
            if isinstance(perm_entries, list)
            and len(perm_entries) == 1
            and isinstance(perm_entries[0], dict)
            else {}
        )
        raw_acl = entry.get("acl")
        perm_content = entry.get("content")
        acl = (
            raw_acl
            if isinstance(raw_acl, dict)
            else (
                perm_content.get("eai:acl")
                if isinstance(perm_content, dict)
                and isinstance(perm_content.get("eai:acl"), dict)
                else {}
            )
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

    def scan(self, limit, *, fields=None):
        self._validate_limit(limit)
        base_query = {"limit": limit, "sort": "_key:1"}
        if fields is not None:
            if not isinstance(fields, str) or not fields:
                raise Unavailable("Unsupported field projection.")
            base_query["fields"] = fields
        for _attempt in range(2):
            rows = self.request("GET", self.path, query={**base_query, "skip": 0})
            if not isinstance(rows, list) or len(rows) > limit:
                raise Unavailable("Collection scan is malformed.")
            keys = [row.get("_key") if isinstance(row, dict) else None for row in rows]
            if not all(isinstance(key, str) and key for key in keys) or keys != sorted(
                set(keys)
            ):
                raise Unavailable("Collection scan is not uniquely ordered.")
            if len(rows) == limit:
                return rows
            shifted = self.request("GET", self.path, query={**base_query, "skip": 1})
            if shifted == rows[1:]:
                return rows
        raise Unavailable(
            "Collection scan is capped or changed during its completion proof."
        )

    def scan_metadata(self, limit):
        """Bounded scan projecting only hash-chain metadata (omitting payload_json)."""
        return self.scan(limit, fields=METADATA_FIELDS)

    def get(self, key):
        """Point lookup of one document by primary _key."""
        if not isinstance(key, str) or not DOC_KEY.fullmatch(key):
            raise Unavailable("Unsupported collection key.")
        row = self.request("GET", self.path + "/" + key, absent_ok=True)
        if row is not None and not isinstance(row, dict):
            raise Unavailable("Collection document is malformed.")
        return row

    def query(self, filter_doc, *, limit, sort=None, fields=None):
        """Bounded indexed KV query with skip=0/skip=1 completion proof."""
        self._validate_limit(limit)
        if not isinstance(filter_doc, dict):
            raise Unavailable("Unsupported collection query.")
        effective_sort = "_key:1" if sort is None else sort
        if not isinstance(effective_sort, str) or not effective_sort:
            raise Unavailable("Unsupported collection sort.")
        base_query = {
            "query": canonical(filter_doc),
            "limit": limit,
            "sort": effective_sort,
        }
        if fields is not None:
            if not isinstance(fields, str) or not fields:
                raise Unavailable("Unsupported field projection.")
            base_query["fields"] = fields
        for _attempt in range(2):
            rows = self.request("GET", self.path, query={**base_query, "skip": 0})
            if not isinstance(rows, list) or len(rows) > limit:
                raise Unavailable("Collection query is malformed.")
            keys = [row.get("_key") if isinstance(row, dict) else None for row in rows]
            if not all(isinstance(key, str) and key for key in keys) or len(
                keys
            ) != len(set(keys)):
                raise Unavailable("Collection query is not uniquely ordered.")
            if effective_sort == "_key:1" and keys != sorted(set(keys)):
                raise Unavailable("Collection query is not uniquely ordered.")
            if len(rows) == limit:
                return rows
            shifted = self.request("GET", self.path, query={**base_query, "skip": 1})
            if shifted == rows[1:]:
                return rows
        raise Unavailable(
            "Collection query is capped or changed during its completion proof."
        )

    def insert(self, document):
        return self.request("POST", self.path, body=document)

    def delete(self, key):
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise Unavailable("Unsupported collection key.")
        self.request("DELETE", self.path + "/" + key, absent_ok=True)

    def delete_many(self, keys):
        """Query-based batched $in DELETEs (up to MAX_IN_BATCH keys per request)."""
        validated = []
        for key in keys:
            if not isinstance(key, str) or not KEY.fullmatch(key):
                raise Unavailable("Unsupported collection key.")
            validated.append(key)
        for offset in range(0, len(validated), MAX_IN_BATCH):
            chunk = validated[offset : offset + MAX_IN_BATCH]
            self.request(
                "DELETE",
                self.path,
                query={"query": canonical({"_key": {"$in": chunk}})},
                absent_ok=True,
            )
