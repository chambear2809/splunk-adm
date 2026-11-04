"""Administrator-owned, bounded configuration for point attachment context."""

import configparser
import json
from pathlib import Path

from adm_identity_lib.search import SearchError
from .context import MAX_BINDINGS, validate_bindings

FIELDS = frozenset(
    {
        "enabled",
        "index",
        "host",
        "authority",
        "fabric",
        "scope",
        "apic_host",
        "apic_pin",
        "tenant_dn",
        "vrf_dn",
        "address_realm",
        "revision",
        "valid_from",
        "valid_to",
    }
)


def load_bindings(app_root: Path, profile):
    """Read only app default/local files; callers cannot supply paths or bindings."""
    config = configparser.ConfigParser(interpolation=None)
    try:
        for directory in ("default", "local"):
            path = app_root / directory / "adm_aci_bindings.conf"
            if not path.exists():
                continue
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
                raise ValueError()
            config.read_string(path.read_text(encoding="utf-8"))
        if config.defaults() or len(config.sections()) > MAX_BINDINGS + 1:
            raise ValueError()
        if not config.has_section("bindings"):
            return None
        if set(config["bindings"]) != {"enabled"}:
            raise ValueError()
        enabled = config["bindings"]["enabled"]
        if enabled not in ("true", "false"):
            raise ValueError()
        if enabled == "false":
            return None
        bindings = []
        for section in config.sections():
            if section == "bindings":
                continue
            if not section.startswith("binding:") or not section[8:]:
                raise ValueError()
            binding = dict(config[section])
            if set(binding) - FIELDS or binding.get("enabled") not in ("true", "false"):
                raise ValueError()
            if binding["enabled"] == "false":
                continue
            if set(binding) != FIELDS:
                raise ValueError()
            binding["enabled"] = True
            for field in ("valid_from", "valid_to"):
                binding[field] = float(binding[field])
            bindings.append(binding)
        return validate_bindings(profile, bindings)
    except (OSError, UnicodeError, ValueError, configparser.Error):
        raise SearchError("Invalid administrator ACI context configuration.") from None


def context_rows(context):
    """Keep nested provenance lossless through Splunk's CSV search SDK."""
    base = {key: value for key, value in context.items() if key != "candidates"}
    rows = [
        {
            **base,
            "record_class": "completion",
            "candidate_count": len(context["candidates"]),
        }
    ]
    for candidate in context["candidates"]:
        rows.append(
            {
                **base,
                "record_class": "bound_attachment_context",
                "address": candidate["address"],
                "address_realm": candidate["address_realm"],
                "binding_revision": candidate["binding_revision"],
                "context_json": json.dumps(
                    candidate, sort_keys=True, separators=(",", ":"), allow_nan=False
                ),
            }
        )
    total = 0
    for row in rows:
        size = len(json.dumps(row, sort_keys=True, allow_nan=False).encode("utf-8"))
        total += size
        if size > 128 * 1024 or total > 2 * 1024 * 1024:
            raise SearchError("ACI emitted context exceeds its output budget.")
    return rows
