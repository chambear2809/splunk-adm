"""Saved dependency assertions for change verification.

An assertion names an expected observed dependency. It never grants search
authorization: evaluation always runs as the reader against current sources.
"""

import ipaddress
import json
import re

from .payload import NAME, PRINCIPAL, TOKEN, PayloadError, _text

KINDS = frozenset({"reaches", "redundant", "no_new_blocked"})
TRANSPORTS = frozenset({"tcp", "udp", "sctp"})
SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}\Z")
NOTE = re.compile(r"[^\x00-\x1f\x7f]{0,280}\Z")
MAX_ASSERTIONS = 100
MAX_DOCUMENT_BYTES = 24 * 1024
MIN_OBSERVERS = 2
MAX_OBSERVERS = 8
FIELDS = frozenset(
    {
        "id",
        "name",
        "owner",
        "kind",
        "scope",
        "src",
        "dst",
        "transport",
        "port",
        "minObservers",
        "team",
        "note",
    }
)
REQUIRED = frozenset({"id", "name", "kind", "scope", "src", "dst"})


def _address(value, label):
    if not isinstance(value, str) or len(value) > 45:
        raise PayloadError("Invalid " + label + ".")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PayloadError("Invalid " + label + ".") from exc
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        raise PayloadError("Use the IPv4 form of the " + label + ".")
    canonical = str(parsed)
    if canonical != value:
        raise PayloadError("Use the canonical form of the " + label + ".")
    return canonical


def _scope(value):
    if (
        not isinstance(value, str)
        or not SCOPE.fullmatch(value)
        or value.lower().startswith("unmapped:")
    ):
        raise PayloadError("Assertions require a mapped routing scope.")
    return value


def _assertion(row, principal):
    if not isinstance(row, dict) or not REQUIRED <= set(row) or set(row) - FIELDS:
        raise PayloadError("Invalid dependency assertion.")
    assertion_id = _text(row["id"], TOKEN, "assertion id")
    raw_name = row["name"].strip() if isinstance(row["name"], str) else ""
    name = _text(raw_name, NAME, "assertion name")
    owner = _text(row.get("owner", principal), PRINCIPAL, "assertion owner")
    kind = row["kind"]
    if kind not in KINDS:
        raise PayloadError("Unsupported assertion kind.")
    src = _address(row["src"], "source address")
    dst = _address(row["dst"], "destination address")
    if src == dst:
        raise PayloadError("Source and destination must differ.")
    result = {
        "id": assertion_id,
        "name": name,
        "owner": owner,
        "kind": kind,
        "scope": _scope(row["scope"]),
        "src": src,
        "dst": dst,
    }
    transport, port = row.get("transport"), row.get("port")
    if kind == "no_new_blocked":
        if transport is not None or port is not None:
            raise PayloadError("No-new-blocked assertions cover every service.")
    else:
        if transport not in TRANSPORTS:
            raise PayloadError("Assertions require tcp, udp or sctp.")
        if type(port) is not int or not 1 <= port <= 65535:
            raise PayloadError("Assertions require a port from 1 to 65535.")
        result["transport"], result["port"] = transport, port
    minimum = row.get("minObservers")
    if kind == "redundant":
        if type(minimum) is not int or not MIN_OBSERVERS <= minimum <= MAX_OBSERVERS:
            raise PayloadError("Redundancy assertions need 2 to 8 observers.")
        result["minObservers"] = minimum
    elif minimum is not None:
        raise PayloadError("Only redundancy assertions set minObservers.")
    team = row.get("team")
    if team is not None:
        result["team"] = _text(team, TOKEN, "team")
    note = row.get("note")
    if note is not None:
        if not isinstance(note, str) or not NOTE.fullmatch(note):
            raise PayloadError("Invalid assertion note.")
        result["note"] = note
    return result


def assertions_payload(value, principal):
    if not isinstance(value, dict) or set(value) != {"assertions"}:
        raise PayloadError("Invalid dependency assertion document.")
    rows = value["assertions"]
    if not isinstance(rows, list) or len(rows) > MAX_ASSERTIONS:
        raise PayloadError("Assertions exceed the 100-assertion bound.")
    ids, names, result = set(), set(), []
    for row in rows:
        assertion = _assertion(row, principal)
        if assertion["id"] in ids:
            raise PayloadError("Duplicate assertion id.")
        if assertion["name"] in names:
            raise PayloadError("Duplicate assertion name.")
        ids.add(assertion["id"])
        names.add(assertion["name"])
        result.append(assertion)
    document = {"assertions": result}
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > MAX_DOCUMENT_BYTES:
        raise PayloadError("Assertions exceed 24 KiB.")
    return document
