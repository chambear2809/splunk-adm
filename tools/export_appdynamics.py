#!/usr/bin/env python3
"""Collect read-only AppDynamics Controller model metadata into a v1 snapshot.

The collector calls only the documented Controller Application Model GET APIs.
It writes a local snapshot bundle; it does not deliver events to Splunk.
Credentials are read from the environment and are never written to the bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

SCHEMA_VERSION = 1
SCHEMA = "application_atlas.appdynamics_inventory.v1"
SOURCE = "appdynamics_inventory"
SOURCETYPE = "adm:appdynamics_inventory"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 50 * 1024 * 1024
MAX_OUTPUT_BYTES = 50 * 1024 * 1024
MAX_COLLECTION_SECONDS = 600
REQUEST_TIMEOUT_SECONDS = 20
MAX_REQUEST_ATTEMPTS = 20_000
MAX_RETRIES = 2
MAX_APPLICATIONS = 500
MAX_TIERS = 5_000
MAX_NODES = 10_000
MAX_BACKENDS = 10_000
MAX_RECORDS = 10_000
MAX_NODE_IP_ROWS = 10_000
MAX_TEXT = 2_048
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/@-]{0,254}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$")
SECRET_PROPERTY_RE = re.compile(
    r"(?:pass(?:word)?|secret|token|credential|authorization|api.?key|access.?key|user(?:name)?)",
    re.IGNORECASE,
)
HOST_PROPERTY_NAMES = {"HOST", "HOSTNAME", "IP", "ADDRESS", "SERVER", "ENDPOINT"}
URL_PROPERTY_NAMES = {"URL", "URI", "CONNECTION_URL", "CONNECTION_STRING"}
PORT_PROPERTY_NAMES = {"PORT", "SERVER_PORT"}
TEMP_INPUT_PREFIX = ".appdynamics-"


class CollectionError(Exception):
    """A sanitized collection failure with a stable public code."""

    def __init__(self, code: str, *, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Limits:
    deadline: float
    max_total_bytes: int = MAX_TOTAL_RESPONSE_BYTES


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _safe_text(value: str | None, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise CollectionError("invalid_response")
        return None
    value = value.strip()
    if not value:
        if required:
            raise CollectionError("invalid_response")
        return None
    if len(value) > MAX_TEXT or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise CollectionError("invalid_response")
    return value


def _xml_text(parent: ET.Element, tag: str, *, required: bool = False) -> str | None:
    matches = [child for child in parent if _tag_name(child.tag) == tag]
    if len(matches) > 1:
        raise CollectionError("invalid_response")
    if not matches:
        if required:
            raise CollectionError("invalid_response")
        return None
    return _safe_text(matches[0].text, required=required)


def _tag_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _xml_root(payload: bytes, expected: str) -> ET.Element:
    upper = payload[: min(len(payload), 4096)].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise CollectionError("invalid_response")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise CollectionError("invalid_response") from exc
    if _tag_name(root.tag) != expected:
        raise CollectionError("invalid_response")
    return root


def _items(payload: bytes, root_name: str, item_name: str) -> list[ET.Element]:
    root = _xml_root(payload, root_name)
    if any(_tag_name(child.tag) != item_name for child in root):
        raise CollectionError("invalid_response")
    return list(root)


def _positive_id(value: str | None, *, required: bool = True) -> int | None:
    if value is None:
        if required:
            raise CollectionError("invalid_response")
        return None
    if not value.isascii() or not value.isdigit():
        raise CollectionError("invalid_response")
    result = int(value)
    if result <= 0 or result > 2**53 - 1:
        raise CollectionError("invalid_response")
    return result


def _reported_id(value: str | None) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise CollectionError("invalid_response")
    result = int(value)
    if result < 0 or result > 2**53 - 1:
        raise CollectionError("invalid_response")
    return result


def _canonical_ip(value: str) -> str | None:
    if "%" in value:
        # Zone-scoped IPv6 addresses cannot be compared safely across routing scopes.
        return None
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CollectionError("invalid_response") from exc
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return parsed.compressed.lower()


def _safe_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        # Accessing port validates malformed/out-of-range ports.
        port = parsed.port
    except ValueError as exc:
        raise CollectionError("invalid_configuration") from exc
    host = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if (
            not re.fullmatch(r"[A-Za-z0-9.-]+", host)
            or host.startswith(".")
            or host.endswith(".")
        ):
            raise CollectionError("invalid_configuration")
    else:
        host = (
            f"[{address.compressed.lower()}]" if address.version == 6 else str(address)
        )
    if port is None or port == 443:
        return f"https://{host}"
    return f"https://{host}:{port}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class ControllerClient:
    """HTTPS-only client that pins every request to one configured origin."""

    def __init__(
        self,
        origin: str,
        api_client: str,
        account_name: str,
        client_secret: str,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        opener: Any | None = None,
    ) -> None:
        self.origin = _safe_origin(origin)
        self.api_client = _safe_text(api_client, required=True)
        self.account_name = _safe_text(account_name, required=True)
        self.client_secret = client_secret
        if not client_secret or len(client_secret) > 4096:
            raise CollectionError("invalid_configuration")
        self.clock = clock
        self.monotonic = monotonic
        self.sleep = sleep
        self.opener = opener or build_opener(
            HTTPSHandler(context=ssl.create_default_context()), NoRedirect()
        )
        self.token: str | None = None
        self.limits: Limits | None = None
        self.total_bytes = 0
        self.request_attempts = 0

    def _url(self, path: str) -> str:
        if not path.startswith("/controller/") or "?" in path or "#" in path:
            raise CollectionError("invalid_configuration")
        return self.origin + path

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        bearer: str | None = None,
    ) -> bytes:
        self.request_attempts += 1
        if self.request_attempts > MAX_REQUEST_ATTEMPTS:
            raise CollectionError("request_limit")
        if self.limits is not None and self.monotonic() > self.limits.deadline:
            raise CollectionError("collection_timeout")
        headers = {"Accept": "application/json" if body else "application/xml"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        request = Request(self._url(path), data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise CollectionError("http_status")
                chunks: list[bytes] = []
                response_bytes = 0
                while True:
                    if (
                        self.limits is not None
                        and self.monotonic() > self.limits.deadline
                    ):
                        raise CollectionError("collection_timeout")
                    chunk = response.read(
                        min(64 * 1024, MAX_RESPONSE_BYTES + 1 - response_bytes)
                    )
                    if not chunk:
                        break
                    chunks.append(chunk)
                    response_bytes += len(chunk)
                    if response_bytes > MAX_RESPONSE_BYTES:
                        raise CollectionError("response_size_limit")
                payload = b"".join(chunks)
        except HTTPError as exc:
            raise CollectionError(
                "redirect_rejected" if 300 <= exc.code < 400 else "http_status",
                status=exc.code,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise CollectionError("transport_error") from exc
        if len(payload) > MAX_RESPONSE_BYTES:
            raise CollectionError("response_size_limit")
        self.total_bytes += len(payload)
        if self.limits is not None and self.total_bytes > self.limits.max_total_bytes:
            raise CollectionError("total_response_limit")
        return payload

    def _get(self, path: str) -> bytes:
        assert self.token is not None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return self._request("GET", path, bearer=self.token)
            except CollectionError as exc:
                retryable = exc.status in {429, 502, 503, 504}
                # The public error object does not retain source response details.
                if attempt >= MAX_RETRIES or not retryable:
                    raise
                self.sleep(min(float(2**attempt), 2.0))
        raise CollectionError("transport_error")

    def authenticate(self) -> None:
        data = urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": f"{self.api_client}@{self.account_name}",
                "client_secret": self.client_secret,
            }
        ).encode("utf-8")
        payload = self._request("POST", "/controller/api/oauth/access_token", body=data)
        try:
            token_data = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CollectionError("invalid_token_response") from exc
        token = token_data.get("access_token") if isinstance(token_data, dict) else None
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise CollectionError("invalid_token_response")
        expires_in = token_data.get("expires_in")
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, (int, float))
            or not 0 < expires_in <= 86_400
        ):
            raise CollectionError("invalid_token_response")
        self.token = token

    def get_xml(self, path: str) -> tuple[bytes, float]:
        payload = self._get(path)
        return payload, self.clock()


def _property_values(backend: ET.Element) -> list[dict[str, Any]]:
    properties_nodes = [
        child for child in backend if _tag_name(child.tag) == "properties"
    ]
    if len(properties_nodes) > 1:
        raise CollectionError("invalid_response")
    if not properties_nodes:
        return []
    result: list[dict[str, Any]] = []
    for item in properties_nodes[0]:
        if _tag_name(item.tag) != "name-value":
            raise CollectionError("invalid_response")
        name = _safe_text(_xml_text(item, "name", required=True), required=True)
        value = _safe_text(_xml_text(item, "value"))
        assert name is not None
        redacted = bool(SECRET_PROPERTY_RE.search(name))
        safe_value = None if redacted else _sanitize_property(name, value)
        result.append({"name": name, "value": safe_value, "redacted": redacted})
    if len(result) > 200:
        raise CollectionError("record_limit")
    return result


def _sanitize_property(name: str, value: str | None) -> str | None:
    if value is None:
        return value
    upper_name = name.upper()
    if upper_name in HOST_PROPERTY_NAMES:
        candidate = value.strip()
        if (
            len(candidate) > 255
            or any(char.isspace() for char in candidate)
            or any(char in candidate for char in "@/?#")
        ):
            return None
        return candidate
    if upper_name not in URL_PROPERTY_NAMES:
        return value
    candidate = value.strip()
    prefix = "jdbc:" if candidate.lower().startswith("jdbc:") else ""
    parsed_value = candidate[len(prefix) :] if prefix else candidate
    try:
        parsed = urlsplit(parsed_value)
        if not parsed.scheme or not parsed.hostname:
            return None
        host = parsed.hostname
        try:
            ip = ipaddress.ip_address(host)
            host = f"[{ip.compressed.lower()}]" if ip.version == 6 else str(ip)
        except ValueError:
            host = host.lower()
        port = parsed.port
        authority = host if port is None else f"{host}:{port}"
        scheme = f"{prefix}{parsed.scheme.lower()}"
        return f"{scheme}://{authority}{parsed.path}"
    except ValueError:
        return None


def _backend_endpoint_candidates(
    properties: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for prop in properties:
        if prop["redacted"] or not isinstance(prop["value"], str):
            continue
        name = prop["name"].upper()
        value = prop["value"].strip()
        if name in HOST_PROPERTY_NAMES:
            try:
                ip = _canonical_ip(value)
            except CollectionError:
                ip = None
            if ip is not None:
                candidates.append({"property": prop["name"], "kind": "ip", "value": ip})
            elif value and len(value) <= 255 and not any(c.isspace() for c in value):
                candidates.append(
                    {
                        "property": prop["name"],
                        "kind": "hostname_unresolved",
                        "value": value,
                    }
                )
        elif name in URL_PROPERTY_NAMES:
            safe_url = _sanitize_property(name, value)
            if safe_url:
                without_jdbc = (
                    safe_url[5:] if safe_url.lower().startswith("jdbc:") else safe_url
                )
                try:
                    parsed = urlsplit(without_jdbc)
                    host = parsed.hostname
                    if not host:
                        continue
                    try:
                        normalized = _canonical_ip(host)
                    except CollectionError:
                        normalized = None
                    candidates.append(
                        {
                            "property": prop["name"],
                            "kind": "ip"
                            if normalized is not None
                            else "hostname_unresolved",
                            "value": normalized or host.lower(),
                            **(
                                {"port": parsed.port} if parsed.port is not None else {}
                            ),
                        }
                    )
                except ValueError:
                    continue
        elif name in PORT_PROPERTY_NAMES and value.isascii() and value.isdigit():
            port = int(value)
            if 1 <= port <= 65_535:
                candidates.append(
                    {"property": prop["name"], "kind": "port", "value": port}
                )
    return candidates


def _record(
    record_type: str,
    record_id: str,
    observed_at: float,
    common: dict[str, Any],
    **fields: Any,
) -> dict[str, Any]:
    event = {
        "schema_version": SCHEMA_VERSION,
        "schema": SCHEMA,
        "source": SOURCE,
        "controller_authority": common["controller_authority"],
        "scope": common["scope"],
        "snapshot_id": common["snapshot_id"],
        "snapshot_at": common["snapshot_at"],
        "collection_started_at": common["collection_started_at"],
        "collection_completed_at": common["collection_completed_at"],
        "collection_skew_seconds": common["collection_skew_seconds"],
        "snapshot_complete": True,
        "record_type": record_type,
        "record_id": record_id,
        "observed_at": observed_at,
        "identity_basis": "controller_application_model_ids",
        **fields,
    }
    event["record_fingerprint"] = hashlib.sha256(_canonical(event)).hexdigest()
    return event


def _parse_address_items(node: ET.Element) -> tuple[list[dict[str, Any]], list[str]]:
    containers = [child for child in node if _tag_name(child.tag) == "ipAddresses"]
    if len(containers) > 1:
        raise CollectionError("invalid_response")
    if not containers:
        return [], []
    addresses: list[dict[str, Any]] = []
    matchable: list[str] = []
    for child in containers[0]:
        if _tag_name(child.tag) != "ipAddress":
            raise CollectionError("invalid_response")
        raw = _safe_text(child.text, required=True)
        assert raw is not None
        canonical = _canonical_ip(raw)
        entry: dict[str, Any] = {"reported": raw, "matchable": canonical is not None}
        if canonical is not None:
            entry["ip"] = canonical
            matchable.append(canonical)
        else:
            entry["status"] = "zone_scoped_address_unmatchable"
        addresses.append(entry)
    if len(addresses) > 64:
        raise CollectionError("record_limit")
    return addresses, sorted(set(matchable))


def _parse_properties(backend: ET.Element) -> list[dict[str, Any]]:
    properties = _property_values(backend)
    properties.sort(key=lambda item: (item["name"].casefold(), str(item["value"])))
    return properties


def collect_snapshot(
    *,
    controller_origin: str,
    controller_authority: str,
    scope: str,
    api_client: str,
    account_name: str,
    client_secret: str,
    now: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    opener: Any | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    authority = controller_authority.strip().lower()
    if not IDENTIFIER_RE.fullmatch(authority):
        raise CollectionError("invalid_configuration")
    if not SCOPE_RE.fullmatch(scope) or re.match(
        r"^(unmapped|unknown|reserved)(:|$)", scope, re.IGNORECASE
    ):
        raise CollectionError("invalid_configuration")
    started_at = now()
    client = ControllerClient(
        controller_origin,
        api_client,
        account_name,
        client_secret,
        clock=now,
        monotonic=monotonic,
        sleep=sleep,
        opener=opener,
    )
    client.limits = Limits(deadline=monotonic() + MAX_COLLECTION_SECONDS)
    client.authenticate()
    records_raw: list[tuple[str, str, float, dict[str, Any]]] = []

    applications_payload, apps_observed_at = client.get_xml(
        "/controller/rest/applications"
    )
    applications = _items(applications_payload, "applications", "application")
    if len(applications) > MAX_APPLICATIONS:
        raise CollectionError("application_limit")

    parsed_applications: list[dict[str, Any]] = []
    for app in applications:
        app_id = _positive_id(_xml_text(app, "id", required=True))
        app_name = _xml_text(app, "name", required=True)
        assert app_id is not None and app_name is not None
        record = {
            "application_id": app_id,
            "application_name": app_name,
        }
        parsed_applications.append(record)
        records_raw.append(
            ("application", f"application:{app_id}", apps_observed_at, record)
        )

    tier_count = node_count = backend_count = node_ip_count = 0
    node_keys: set[tuple[int, int, int]] = set()
    node_records: list[dict[str, Any]] = []
    backend_records: list[dict[str, Any]] = []

    for app in parsed_applications:
        app_id = app["application_id"]
        app_name = app["application_name"]
        tiers_payload, tiers_observed_at = client.get_xml(
            f"/controller/rest/applications/{app_id}/tiers"
        )
        tiers = _items(tiers_payload, "tiers", "tier")
        tier_count += len(tiers)
        if tier_count > MAX_TIERS:
            raise CollectionError("tier_limit")
        parsed_tiers: list[dict[str, Any]] = []
        for tier in tiers:
            tier_id = _positive_id(_xml_text(tier, "id", required=True))
            tier_name = _xml_text(tier, "name", required=True)
            assert tier_id is not None and tier_name is not None
            record = {
                "application_id": app_id,
                "application_name": app_name,
                "tier_id": tier_id,
                "tier_name": tier_name,
                "tier_type": _xml_text(tier, "type"),
                "agent_type": _xml_text(tier, "agentType"),
                "reported_node_count": _reported_id(_xml_text(tier, "numberOfNodes")),
            }
            parsed_tiers.append(record)
            records_raw.append(
                (
                    "tier",
                    f"application:{app_id}:tier:{tier_id}",
                    tiers_observed_at,
                    record,
                )
            )

        for tier in parsed_tiers:
            tier_id = tier["tier_id"]
            nodes_payload, nodes_observed_at = client.get_xml(
                f"/controller/rest/applications/{app_id}/tiers/{tier_id}/nodes"
            )
            nodes = _items(nodes_payload, "nodes", "node")
            node_count += len(nodes)
            if node_count > MAX_NODES:
                raise CollectionError("node_limit")
            for node in nodes:
                node_id = _positive_id(_xml_text(node, "id", required=True))
                node_name = _xml_text(node, "name", required=True)
                reported_tier_id = _positive_id(
                    _xml_text(node, "tierId", required=True)
                )
                if node_id is None or reported_tier_id != tier_id or node_name is None:
                    raise CollectionError("invalid_response")
                key = (app_id, tier_id, node_id)
                if key in node_keys:
                    raise CollectionError("duplicate_identity")
                node_keys.add(key)
                addresses, matchable = _parse_address_items(node)
                node_ip_count += len(matchable)
                if node_ip_count > MAX_NODE_IP_ROWS:
                    raise CollectionError("node_ip_limit")
                record = {
                    "application_id": app_id,
                    "application_name": app_name,
                    "tier_id": tier_id,
                    "tier_name": tier["tier_name"],
                    "node_id": node_id,
                    "node_name": node_name,
                    "machine_id": _reported_id(_xml_text(node, "machineId")),
                    "machine_name": _xml_text(node, "machineName"),
                    "machine_os_type": _xml_text(node, "machineOSType"),
                    "machine_agent_present": _xml_text(node, "machineAgentPresent"),
                    "machine_agent_version": _xml_text(node, "machineAgentVersion"),
                    "application_agent_present": _xml_text(node, "appAgentPresent"),
                    "application_agent_version": _xml_text(node, "appAgentVersion"),
                    "agent_type": _xml_text(node, "agentType"),
                    "ip_addresses": addresses,
                    "ip_address_observation": (
                        "reported" if any(addresses) else "no_address_values_returned"
                    ),
                    "relationship_basis": "application_model_tier_nodes_endpoint",
                }
                node_records.append(record)
                records_raw.append(
                    (
                        "node",
                        f"application:{app_id}:tier:{tier_id}:node:{node_id}",
                        nodes_observed_at,
                        record,
                    )
                )

        backends_payload, backends_observed_at = client.get_xml(
            f"/controller/rest/applications/{app_id}/backends"
        )
        backends = _items(backends_payload, "backends", "backend")
        backend_count += len(backends)
        if backend_count > MAX_BACKENDS:
            raise CollectionError("backend_limit")
        backend_ids: set[int] = set()
        for backend in backends:
            backend_id = _positive_id(_xml_text(backend, "id", required=True))
            backend_name = _xml_text(backend, "name", required=True)
            if backend_id is None or backend_name is None or backend_id in backend_ids:
                raise CollectionError("duplicate_identity")
            backend_ids.add(backend_id)
            reported_node_id = _reported_id(
                _xml_text(backend, "applicationComponentNodeId")
            )
            reported_tier_id = _reported_id(_xml_text(backend, "tierId"))
            matching = [
                key
                for key in node_keys
                if key[0] == app_id
                and key[2] == reported_node_id
                and key[1] == reported_tier_id
            ]
            if (
                reported_node_id is not None
                and reported_node_id > 0
                and reported_tier_id is not None
                and reported_tier_id > 0
                and len(matching) == 1
            ):
                association_status = "verified_node"
                association_basis = "same_snapshot_application_tier_node_id_match"
                verified_node_id = reported_node_id
                verified_tier_id = reported_tier_id
            elif (reported_node_id or 0) > 0 or (reported_tier_id or 0) > 0:
                association_status = "unverified_reported_ids"
                association_basis = "application_model_backend_record_only"
                verified_node_id = None
                verified_tier_id = None
            else:
                association_status = "application_scope_only"
                association_basis = "application_model_backend_record_only"
                verified_node_id = None
                verified_tier_id = None
            properties = _parse_properties(backend)
            record = {
                "application_id": app_id,
                "application_name": app_name,
                "backend_id": backend_id,
                "backend_name": backend_name,
                "exit_point_type": _xml_text(backend, "exitPointType"),
                "reported_tier_id": reported_tier_id,
                "reported_application_component_node_id": reported_node_id,
                "association_status": association_status,
                "association_basis": association_basis,
                "verified_tier_id": verified_tier_id,
                "verified_node_id": verified_node_id,
                "properties": properties,
                "endpoint_candidates": _backend_endpoint_candidates(properties),
                "relationship_basis": "registered_backend_inventory",
            }
            backend_records.append(record)
            records_raw.append(
                (
                    "backend",
                    f"application:{app_id}:backend:{backend_id}",
                    backends_observed_at,
                    record,
                )
            )

    if len(records_raw) + 1 > MAX_RECORDS:
        raise CollectionError("record_limit")
    completed_at = now()
    skew = max(0.0, completed_at - started_at)
    if skew > MAX_COLLECTION_SECONDS:
        raise CollectionError("collection_timeout")
    snapshot_id = str(uuid.uuid4())
    common = {
        "controller_authority": authority,
        "scope": scope,
        "snapshot_id": snapshot_id,
        "snapshot_at": completed_at,
        "collection_started_at": started_at,
        "collection_completed_at": completed_at,
        "collection_skew_seconds": skew,
    }
    events = [
        _record(
            "snapshot",
            f"snapshot:{snapshot_id}",
            completed_at,
            common,
            identity_basis="controller_application_model_ids",
            record_counts={
                "applications": len(parsed_applications),
                "tiers": tier_count,
                "nodes": node_count,
                "backends": backend_count,
                "total_records": len(records_raw) + 1,
                "node_ip_addresses": node_ip_count,
            },
            empty_inventory=not parsed_applications,
        ),
    ]
    for record_type, record_id, observed_at, record in records_raw:
        events.append(_record(record_type, record_id, observed_at, common, **record))
    if len(events) > MAX_RECORDS:
        raise CollectionError("record_limit")
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "schema": SCHEMA,
        "controller_authority": authority,
        "scope": scope,
        "snapshot_id": snapshot_id,
        "snapshot_at": completed_at,
        "collection_started_at": started_at,
        "collection_completed_at": completed_at,
        "collection_skew_seconds": skew,
        "snapshot_complete": True,
        "identity_basis": "controller_application_model_ids",
        "record_counts": {
            "applications": len(parsed_applications),
            "tiers": tier_count,
            "nodes": node_count,
            "backends": backend_count,
            "total_records": len(events),
            "node_ip_addresses": node_ip_count,
        },
        "records": events,
    }
    asset_history = _asset_history_manifest(
        authority,
        scope,
        snapshot_id,
        completed_at,
        node_records,
    )
    return bundle, asset_history


def _asset_history_manifest(
    authority: str,
    scope: str,
    snapshot_id: str,
    snapshot_at: float,
    nodes: list[dict[str, Any]],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for node in nodes:
        app_id = node["application_id"]
        tier_id = node["tier_id"]
        node_id = node["node_id"]
        asset_id = (
            f"appd:{authority}:application:{app_id}:tier:{tier_id}:node:{node_id}"
        )
        service_id = f"appd:{authority}:application:{app_id}:tier:{tier_id}"
        service_name = f"{node['application_name']} / {node['tier_name']}"
        for address in sorted(
            {
                item["ip"]
                for item in node["ip_addresses"]
                if item.get("matchable") is True
            }
        ):
            records.append(
                {
                    "record_id": (
                        f"{snapshot_id}:application:{app_id}:tier:{tier_id}:"
                        f"node:{node_id}:ip:{address}"
                    ),
                    "revision": 0,
                    "asset_id": asset_id,
                    "asset_name": node["node_name"],
                    "service_id": service_id,
                    "service_name": service_name,
                    "scope": scope,
                    "ip": address,
                    "validity_basis": "snapshot_current",
                }
            )
    if len(records) > MAX_NODE_IP_ROWS:
        raise CollectionError("node_ip_limit")
    return {
        "schema_version": 1,
        "authority": authority,
        "snapshot_id": snapshot_id,
        "snapshot_at": snapshot_at,
        "snapshot_complete": True,
        "records": records,
    }


def _atomic_write(path: Path, content: bytes, *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise CollectionError("output_exists")
    temp = path.with_name(f"{TEMP_INPUT_PREFIX}{uuid.uuid4().hex}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temp, path)
        else:
            os.link(temp, path)
    except FileExistsError as exc:
        raise CollectionError("output_exists") from exc
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _outside_repository(path: Path) -> Path:
    resolved = path.resolve()
    repository = Path(__file__).resolve().parents[1]
    if resolved == repository or repository in resolved.parents:
        raise CollectionError("output_must_be_outside_repository")
    return resolved


def _write_bundle(path: Path, value: dict[str, Any], *, overwrite: bool) -> None:
    encoded = _canonical(value) + b"\n"
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise CollectionError("output_size_limit")
    _atomic_write(path, encoded, overwrite=overwrite)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-origin", required=True)
    parser.add_argument(
        "--authority", required=True, help="Stable lowercase Controller authority"
    )
    parser.add_argument("--scope", required=True, help="Verified routing scope")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="AppDynamics snapshot bundle JSON output",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    try:
        client_id = os.environ.get("APPD_API_CLIENT_NAME", "")
        account_name = os.environ.get("APPD_ACCOUNT_NAME", "")
        client_secret = os.environ.get("APPD_CLIENT_SECRET", "")
        if not client_id or not account_name or not client_secret:
            raise CollectionError("credentials_unavailable")
        output = _outside_repository(args.output)
        bundle, asset_manifest = collect_snapshot(
            controller_origin=args.controller_origin,
            controller_authority=args.authority,
            scope=args.scope,
            api_client=client_id,
            account_name=account_name,
            client_secret=client_secret,
        )
        bundle["asset_history_manifest"] = asset_manifest
        _write_bundle(output, bundle, overwrite=args.overwrite)
        print(
            json.dumps(
                {
                    "status": "complete",
                    "snapshot_id": bundle["snapshot_id"],
                    "counts": bundle["record_counts"],
                },
                sort_keys=True,
            )
        )
        return 0
    except CollectionError as exc:
        print(json.dumps({"status": "failed", "error": exc.code}), file=sys.stderr)
        return 2
    except OSError:
        print(
            json.dumps({"status": "failed", "error": "output_error"}), file=sys.stderr
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
