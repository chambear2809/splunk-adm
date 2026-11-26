"""Bounded collaboration documents. Ownership never grants search authorization."""

import re

NAME = re.compile(r"[^\x00-\x1f\x7f]{1,80}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}\Z")
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\\@-]{0,127}\Z")
VISIBILITY = frozenset({"private", "shared"})
KINDS = frozenset({"views", "ownership"})


class PayloadError(ValueError):
    pass


def _text(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PayloadError("Invalid " + label + ".")
    return value


def views_payload(value, principal):
    if not isinstance(value, dict) or set(value) != {"views"}:
        raise PayloadError("Invalid saved views document.")
    rows = value["views"]
    if not isinstance(rows, list) or len(rows) > 50:
        raise PayloadError("Saved views exceed the 50-view bound.")
    names = set()
    result = []
    for row in rows:
        if not isinstance(row, dict) or not {
            "id",
            "name",
            "visibility",
            "state",
        } <= set(row):
            raise PayloadError("Invalid saved view.")
        extra = set(row) - {"id", "name", "visibility", "owner", "team", "state"}
        if extra:
            raise PayloadError("Invalid saved view.")
        raw_name = row["name"].strip() if isinstance(row["name"], str) else ""
        name = _text(raw_name, NAME, "view name")
        if name in names:
            raise PayloadError("Duplicate saved view name.")
        names.add(name)
        visibility = row["visibility"]
        if visibility not in VISIBILITY:
            raise PayloadError("Invalid view visibility.")
        owner = row.get("owner", principal)
        _text(owner, PRINCIPAL, "view owner")
        if visibility == "private" and owner != principal:
            raise PayloadError("Private views stay with their owner.")
        state = row["state"]
        if not isinstance(state, dict) or len(state) > 32:
            raise PayloadError("Invalid view state.")
        team = row.get("team")
        if team is not None:
            _text(team, TOKEN, "team")
        result.append(
            {
                "id": _text(row["id"], TOKEN, "view id"),
                "name": name,
                "visibility": visibility,
                "owner": owner,
                "state": state,
                **({"team": team} if team is not None else {}),
            }
        )
    return {"views": result}


def ownership_payload(value):
    if not isinstance(value, dict) or set(value) != {"records"}:
        raise PayloadError("Invalid ownership document.")
    rows = value["records"]
    if not isinstance(rows, list) or len(rows) > 200:
        raise PayloadError("Ownership records exceed the 200-row bound.")
    keys = set()
    result = []
    for row in rows:
        if not isinstance(row, dict) or not {
            "service",
            "environment",
            "owner",
            "team",
        } <= set(row):
            raise PayloadError("Invalid ownership record.")
        extra = set(row) - {"service", "environment", "owner", "team", "contact"}
        if extra:
            raise PayloadError("Invalid ownership record.")
        service = _text(row["service"], TOKEN, "service")
        environment = _text(row["environment"], TOKEN, "environment")
        key = (service, environment)
        if key in keys:
            raise PayloadError("Duplicate ownership record.")
        keys.add(key)
        contact = row.get("contact")
        if contact is not None:
            _text(contact, TOKEN, "contact")
        result.append(
            {
                "service": service,
                "environment": environment,
                "owner": _text(row["owner"], PRINCIPAL, "owner"),
                "team": _text(row["team"], TOKEN, "team"),
                **({"contact": contact} if contact is not None else {}),
            }
        )
    return {"records": result}


def validate(kind, payload, principal):
    if kind == "views":
        return views_payload(payload, principal)
    if kind == "ownership":
        return ownership_payload(payload)
    raise PayloadError("Unsupported collaboration kind.")
