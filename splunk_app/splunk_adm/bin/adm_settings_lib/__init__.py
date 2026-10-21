"""Immutable deployment-settings persistence using KV Store insert uniqueness.

The sole arbitration primitive is POST to a collection with an explicit unique
_key. This module never updates or deletes a document, including the legacy row.
"""

import hashlib
import json
import re

MAX_RECORDS = 1024
ROOT_KEY = "atomic_root"
TOKEN = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")


class SettingsError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code = status, code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def invalid(message="Deployment settings history is invalid or incomplete."):
    return SettingsError(503, "unavailable", message)


def validate_settings(value, source_ids=None):
    """source_ids=None checks stored history structurally; retired IDs stay verifiable."""
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "revision", "sources"}
        or value["schemaVersion"] != 1
        or isinstance(value["schemaVersion"], bool)
        or not isinstance(value["revision"], str)
        or not TOKEN.fullmatch(value["revision"])
        or not isinstance(value["sources"], dict)
    ):
        raise SettingsError(400, "invalid", "Unsupported deployment settings schema.")
    for name, item in value["sources"].items():
        if (
            (source_ids is not None and name not in source_ids)
            or not isinstance(item, dict)
            or set(item) != {"state", "cadenceSeconds", "staleAfterSeconds"}
            or item["state"] not in ("active", "staged", "not_selected")
            or type(item["cadenceSeconds"]) is not int
            or type(item["staleAfterSeconds"]) is not int
            or not 60 <= item["cadenceSeconds"] <= item["staleAfterSeconds"] <= 604800
        ):
            raise SettingsError(400, "invalid", "Invalid source expectations.")
    return json.loads(canonical(value))


def successor_key(revision):
    return "after_" + digest(revision)


class SettingsService:
    """A store supplies bounded scan and insert-only operations; no locks needed."""

    def __init__(self, store, source_ids):
        self.store, self.source_ids = store, frozenset(source_ids)

    def inspect(self):
        rows = self.store.scan(MAX_RECORDS + 1)
        if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
            raise invalid(
                "Deployment settings history limit reached; writes are disabled."
            )
        records = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("_key"), str):
                raise invalid()
            if row["_key"] in records:
                raise invalid()
            records[row["_key"]] = row
        legacy = records.pop("deployment", None)
        legacy_settings = None
        try:
            if legacy is not None:
                legacy_settings = validate_settings(json.loads(legacy["settings_json"]))
                if legacy.get("revision") != legacy_settings["revision"]:
                    raise invalid()
        except (KeyError, TypeError, ValueError, SettingsError) as exc:
            raise invalid("Legacy deployment settings are invalid.") from exc
        anchor = digest(legacy_settings)
        root = records.get(ROOT_KEY)
        if root is None:
            if records:
                raise invalid()
            return legacy_settings, [], anchor, len(rows)
        if root.get("legacy_fingerprint") != anchor:
            raise invalid(
                "Legacy deployment settings changed after migration. Stop older writers "
                "and reconcile settings before saving."
            )
        previous = legacy_settings["revision"] if legacy_settings else None
        key, chain, ids = ROOT_KEY, [], set()
        while key in records:
            row = records[key]
            try:
                settings = validate_settings(json.loads(row["settings_json"]))
                if (
                    row.get("format") != 2
                    or row.get("previous_revision") != previous
                    or row.get("revision") != settings["revision"]
                    or not isinstance(row.get("request_id"), str)
                    or not TOKEN.fullmatch(row["request_id"])
                    or row["request_id"] in ids
                    or row.get("operation_fingerprint")
                    != self.fingerprint(settings, previous, row["request_id"])
                    or row["revision"]
                    != digest(["revision", row["operation_fingerprint"]])
                ):
                    raise invalid()
            except (KeyError, TypeError, ValueError, SettingsError) as exc:
                raise invalid() from exc
            chain.append(row)
            ids.add(row["request_id"])
            previous = row["revision"]
            key = successor_key(previous)
            if len(chain) > MAX_RECORDS:
                raise invalid(
                    "Deployment settings history limit reached; writes are disabled."
                )
        if len(chain) != len(records):
            raise invalid()
        return settings, chain, anchor, len(rows)

    @staticmethod
    def fingerprint(settings, previous, request_id):
        return digest(
            [previous, request_id, settings["schemaVersion"], settings["sources"]]
        )

    def visible(self, settings):
        # Revisions and fingerprints cover the stored sources; only the view drops
        # sources the installed registry no longer offers.
        if settings is None:
            return None
        sources = {
            name: item
            for name, item in settings["sources"].items()
            if name in self.source_ids
        }
        return {**settings, "sources": sources}

    def read(self):
        settings, chain, _, _ = self.inspect()
        revisions = [row["revision"] for row in chain]
        if chain and chain[0]["previous_revision"] is not None:
            revisions.insert(0, chain[0]["previous_revision"])
        if not chain and settings:
            revisions.append(settings["revision"])
        return {
            "state": "configured" if settings else "absent",
            "settings": self.visible(settings),
            "observedRevisions": revisions,
        }

    def write(self, payload):
        if (
            not isinstance(payload, dict)
            or set(payload) != {"settings", "expectedRevision", "requestId"}
            or not isinstance(payload["requestId"], str)
            or not TOKEN.fullmatch(payload["requestId"])
            or (
                payload["expectedRevision"] is not None
                and (
                    not isinstance(payload["expectedRevision"], str)
                    or not TOKEN.fullmatch(payload["expectedRevision"])
                )
            )
        ):
            raise SettingsError(400, "invalid", "Invalid settings operation.")
        settings = validate_settings(payload["settings"], self.source_ids)
        expected, request_id = payload["expectedRevision"], payload["requestId"]
        fingerprint = self.fingerprint(settings, expected, request_id)
        current, chain, anchor, count = self.inspect()
        # Recover a committed operation before checking whether the head advanced.
        for row in chain:
            if row["request_id"] == request_id:
                if row["operation_fingerprint"] != fingerprint:
                    raise SettingsError(
                        409, "conflict", "Request ID was used with different settings."
                    )
                return self.verified(row, current)
        if (current["revision"] if current else None) != expected:
            raise SettingsError(
                409,
                "conflict",
                "Deployment expectations changed. Your draft is preserved; reload before saving.",
            )
        if count >= MAX_RECORDS:
            raise invalid(
                "Deployment settings history limit reached; writes are disabled."
            )
        settings["revision"] = digest(["revision", fingerprint])
        document = {
            "_key": successor_key(expected) if chain else ROOT_KEY,
            "format": 2,
            "previous_revision": expected,
            "request_id": request_id,
            "operation_fingerprint": fingerprint,
            "revision": settings["revision"],
            "settings_json": canonical(settings),
        }
        if not chain:
            document["legacy_fingerprint"] = anchor
        try:
            self.store.insert(document)
        except Exception:
            # A duplicate, timeout, or lost response is resolved by immutable
            # operation identity, never by retrying an overwrite.
            pass
        try:
            current, chain, _, _ = self.inspect()
        except Exception as exc:
            raise SettingsError(
                503,
                "uncertain",
                "Save outcome is uncertain. Your draft is preserved; retry the same save to verify it.",
            ) from exc
        for row in chain:
            if row["_key"] == document["_key"]:
                if row["operation_fingerprint"] == fingerprint:
                    return self.verified(row, current)
                raise SettingsError(
                    409,
                    "conflict",
                    "Deployment expectations changed. Your draft is preserved; reload before saving.",
                )
        raise SettingsError(
            503,
            "uncertain",
            "Save outcome is uncertain. Your draft is preserved; retry the same save to verify it.",
        )

    def verified(self, row, current):
        return {
            "state": "configured",
            "settings": self.visible(current),
            "committedRevision": row["revision"],
            "requestId": row["request_id"],
            "superseded": current["revision"] != row["revision"],
        }
