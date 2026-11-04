"""Pure, quarantined current attachment context from an attested v2 poll.

Bindings are supplied by trusted server configuration, never search arguments.
This module performs no I/O and makes no ownership or traversal claim.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re

from adm_identity_lib.search import SearchError, complete_rows
from .reader import (
    MAX_RAW_BYTES,
    MAX_ROWS,
    MAX_TOTAL_BYTES,
    SOURCE,
    bounds,
    profile_config,
    unique_object,
)
from .validation import PollQualificationError, validate_events

MAX_BINDINGS = 32
MAX_CANDIDATES = 512
MAX_PATHS = 64
MAX_DN_BYTES = 2048
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_CANDIDATE_BYTES = 64 * 1024
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_bindings(profile, bindings):
    profile_config(profile)
    if profile.get("poll_version") != "2":
        raise SearchError("ACI context requires the v2 poll profile.")
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= MAX_BINDINGS:
        raise SearchError("ACI context requires bounded trusted bindings.")
    for binding in bindings:
        if not isinstance(binding, dict) or binding.get("enabled") is not True:
            raise SearchError("Invalid ACI context binding.")
        for field in (
            "authority",
            "fabric",
            "scope",
            "apic_host",
            "apic_pin",
            "index",
            "host",
        ):
            if binding.get(field) != profile[field]:
                raise SearchError("ACI context source binding mismatch.")
        for field in ("revision", "address_realm"):
            if not isinstance(binding.get(field), str) or not IDENT.fullmatch(
                binding[field]
            ):
                raise SearchError("Invalid ACI context binding identifier.")
        tenant, vrf = binding.get("tenant_dn"), binding.get("vrf_dn")
        if (
            not isinstance(tenant, str)
            or not re.fullmatch(r"uni/tn-[^/\x00-\x1f]{1,200}", tenant)
            or not isinstance(vrf, str)
            or not vrf.startswith(tenant + "/ctx-")
            or not re.fullmatch(r"[^/\x00-\x1f]{1,200}", vrf[len(tenant) + 1 :])
        ):
            raise SearchError("Invalid ACI tenant or VRF binding.")
        if (
            not finite(binding.get("valid_from"))
            or not finite(binding.get("valid_to"))
            or binding["valid_from"] >= binding["valid_to"]
        ):
            raise SearchError("Invalid ACI binding validity.")
    for i, left in enumerate(bindings):
        for right in bindings[i + 1 :]:
            if (
                (
                    left["tenant_dn"] == right["tenant_dn"]
                    and left["vrf_dn"] == right["vrf_dn"]
                )
                or left["address_realm"] == right["address_realm"]
            ) and max(left["valid_from"], right["valid_from"]) < min(
                left["valid_to"], right["valid_to"]
            ):
                raise SearchError("Overlapping ACI context bindings.")
    return bindings


def resolve_context(rows, profile, bindings, *, start, as_of, now):
    """Return finite poll candidates only; all records and bindings fail closed."""
    validate_bindings(profile, bindings)
    start, as_of = bounds(start, as_of, now)
    complete_rows(rows)
    if len(rows) > MAX_ROWS:
        raise SearchError("ACI context row cap exceeded.")
    events, receipts, total = [], {}, 0
    for row in rows:
        if any(
            row.get(k) != v
            for k, v in (
                ("index", profile["index"]),
                ("host", profile["host"]),
                ("source", SOURCE),
                ("sourcetype", "adm:aci_poll:v2"),
            )
        ):
            raise SearchError("ACI context source mismatch.")
        try:
            raw = row["_raw"]
            if not isinstance(raw, str):
                raise ValueError()
            size = len(raw.encode("utf-8"))
            total += size
            if size > MAX_RAW_BYTES or total > MAX_TOTAL_BYTES:
                raise ValueError()
            event = json.loads(raw, object_pairs_hook=unique_object)
            completed = event["capture_completed_at"]
            indexed, event_time = float(row["receipt_time"]), float(row["event_time"])
            if (
                not finite(completed)
                or not finite(indexed)
                or not finite(event_time)
                or not start <= completed < as_of
                or not start <= event_time < as_of
                or abs(event_time - completed) > 0.000001
                or not completed - 1 <= indexed < as_of
                or indexed - completed > 300
                or now - completed > 300
            ):
                raise ValueError()
        except (ValueError, TypeError, KeyError, OverflowError):
            raise SearchError("Invalid ACI context event or receipt.") from None
        events.append(event)
        receipts[(event.get("record_type"), event.get("class"), event.get("dn"))] = (
            indexed
        )
    try:
        report = validate_events(
            events,
            expected_authority=profile["authority"],
            expected_fabric=profile["fabric"],
            expected_scope=profile["scope"],
            expected_apic_pin=profile["apic_pin"],
            expected_apic_host=profile["apic_host"],
            now=as_of,
            expected_version=2,
        )
    except PollQualificationError as exc:
        raise SearchError("ACI context poll validation failed: " + str(exc)) from None
    manifest = next(e for e in events if e["record_type"] == "manifest")
    objects = {(e["class"], e["dn"]): e for e in events if e["record_type"] == "object"}

    def bounded_dn(value):
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > MAX_DN_BYTES
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise SearchError("Invalid or oversized ACI DN.")
        return value

    def provenance(e):
        bounded_dn(e["dn"])
        return {
            "class": e["class"],
            "dn": e["dn"],
            "fingerprint": e["record_fingerprint"],
            "observation_started_at": e["observation_started_at"],
            "observation_completed_at": e["observation_completed_at"],
            "received_at": receipts[("object", e["class"], e["dn"])],
        }

    def get(cls, dn):
        obj = objects.get((cls, dn))
        if not obj:
            raise SearchError("Missing ACI context relation or target.")
        return obj

    def target(relation):
        attrs = relation["attributes"]
        if (
            attrs.get("state") != "formed"
            or not isinstance(attrs.get("tDn"), str)
            or not attrs["tDn"]
        ):
            raise SearchError("Unresolved ACI context relation.")
        return bounded_dn(attrs["tDn"])

    paths_by_endpoint = {}
    for (kind, rel_dn), obj in objects.items():
        if kind == "fvRsCEpToPathEp":
            bounded_dn(rel_dn)
            parent, sep, _ = rel_dn.partition("/rscEpToPathEp-[")
            if not sep:
                raise SearchError("Invalid ACI path relation hierarchy.")
            paths_by_endpoint.setdefault(parent, []).append(obj)
    candidates = []
    serialized_candidates = 0
    active = 0
    for binding in bindings:
        if not (
            binding["valid_from"] <= manifest["capture_started_at"]
            and manifest["capture_completed_at"] < binding["valid_to"]
        ):
            continue
        active += 1
        tenant, vrf = binding["tenant_dn"], binding["vrf_dn"]
        for (cls, dn), ip_obj in objects.items():
            if cls != "fvIp" or not dn.startswith(tenant + "/"):
                continue
            attrs = ip_obj["attributes"]
            if attrs.get("vrfDn") != vrf:
                if not isinstance(attrs.get("vrfDn"), str) or not attrs["vrfDn"]:
                    raise SearchError("ACI IP has no explicit VRF.")
                continue
            bounded_dn(dn)
            parent, sep, _ = dn.partition("/ip-[")
            if not sep:
                raise SearchError("Invalid ACI IP hierarchy.")
            cep = get("fvCEp", parent)
            cep_attrs = cep["attributes"]
            if cep_attrs.get("vrfDn") != vrf:
                raise SearchError("ACI endpoint VRF mismatch.")
            try:
                parsed_address = ipaddress.ip_address(attrs["addr"])
                if (
                    parsed_address.is_unspecified
                    or parsed_address.is_multicast
                    or parsed_address.is_loopback
                    or parsed_address.is_link_local
                ):
                    raise ValueError()
                address = str(parsed_address)
            except (KeyError, ValueError, TypeError):
                raise SearchError("Invalid ACI endpoint address.") from None
            if dn != parent + "/ip-[" + attrs["addr"] + "]":
                raise SearchError("ACI IP address DN mismatch.")
            vrf_obj = get("fvCtx", vrf)
            chain = [ip_obj, cep, vrf_obj]
            epg_dn = parent.rsplit("/cep-", 1)[0] if "/cep-" in parent else ""
            if epg_dn == vrf:
                branch = "vrf_scoped"
                epg_value, bd_value = None, None
                if attrs.get("bdDn") not in (None, "", "unspecified") or cep_attrs.get(
                    "bdDn"
                ) not in (None, "", "unspecified"):
                    raise SearchError("Conflicting VRF-scoped bridge domain.")
            else:
                branch = "epg"
                if not epg_dn.startswith(tenant + "/ap-") or "/epg-" not in epg_dn:
                    raise SearchError("Invalid ACI endpoint EPG hierarchy.")
                epg = get("fvAEPg", epg_dn)
                bd_rel = get("fvRsBd", epg_dn + "/rsbd")
                bd_value = target(bd_rel)
                if (
                    not bd_value.startswith(tenant + "/BD-")
                    or attrs.get("bdDn") != bd_value
                    or cep_attrs.get("bdDn") != bd_value
                ):
                    raise SearchError("ACI bridge domain mismatch.")
                bd = get("fvBD", bd_value)
                ctx_rel = get("fvRsCtx", bd_value + "/rsctx")
                if target(ctx_rel) != vrf:
                    raise SearchError("ACI bridge domain VRF mismatch.")
                chain.extend([epg, bd_rel, bd, ctx_rel])
                epg_value = epg_dn
            path_relations = paths_by_endpoint.get(parent, [])
            if not path_relations or len(path_relations) > MAX_PATHS:
                raise SearchError("Missing or capped ACI path alternatives.")
            alternatives = []
            for e in path_relations:
                path_dn = target(e)
                if e["dn"] != parent + "/rscEpToPathEp-[" + path_dn + "]":
                    raise SearchError("ACI path relation target mismatch.")
                alternatives.append(
                    {
                        "target_dn": path_dn,
                        "target_resolution": "unresolved",
                        "provenance": provenance(e),
                    }
                )
            candidate = {
                "address": address,
                "address_realm": binding["address_realm"],
                "binding_revision": binding["revision"],
                "binding_valid_from": binding["valid_from"],
                "binding_valid_to": binding["valid_to"],
                "tenant_dn": tenant,
                "vrf_dn": vrf,
                "endpoint_dn": parent,
                "branch": branch,
                "epg_dn": epg_value,
                "bd_dn": bd_value,
                "evidence": [provenance(e) for e in chain],
                "path_alternatives": alternatives,
            }
            candidate_bytes = len(
                json.dumps(candidate, separators=(",", ":")).encode("utf-8")
            )
            if candidate_bytes > MAX_CANDIDATE_BYTES:
                raise SearchError("ACI context candidate byte cap exceeded.")
            serialized_candidates += candidate_bytes + 1
            if serialized_candidates > MAX_OUTPUT_BYTES:
                raise SearchError("ACI context output byte cap exceeded.")
            candidates.append(candidate)
            if len(candidates) > MAX_CANDIDATES:
                raise SearchError("ACI context candidate cap exceeded.")
    if not active:
        raise SearchError("No ACI context binding covers this capture.")
    result = {
        "schema": "application_atlas.aci_bound_attachment_context.v1",
        "qualification": "quarantined",
        "traversal": "not_observed",
        "capture_id": report["capture_id"],
        "capture_digest": manifest["capture_digest"],
        "manifest_received_at": receipts[("manifest", None, None)],
        "poll_schema": report["schema"],
        "poll_version": 2,
        "authority": profile["authority"],
        "fabric": profile["fabric"],
        "scope": profile["scope"],
        "source_index": profile["index"],
        "source_host": profile["host"],
        "source": SOURCE,
        "apic_host": profile["apic_host"],
        "apic_pin": profile["apic_pin"],
        "capture_started_at": manifest["capture_started_at"],
        "capture_completed_at": manifest["capture_completed_at"],
        "candidates": candidates,
    }

    if (
        len(json.dumps(result, separators=(",", ":")).encode("utf-8"))
        > MAX_OUTPUT_BYTES
    ):
        raise SearchError("ACI context output byte cap exceeded.")
    return result
