"""Shared contract constants, pure helpers, and local state-directory checks."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Any
from urllib.parse import urlparse
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
APP = "/servicesNS/nobody/splunk_adm"
MACROS = APP + "/configs/conf-macros/"
SEARCHES = APP + "/saved/searches/"
JOBS = "/services/search/v2/jobs"
CREATE_JOBS = APP + "/search/v2/jobs"
V1_INDEX = "adm_summary"
V2_INDEX = "adm_summary_v2"
CONTRACT_VERSION = "2"
SLICE_SECONDS = 300
MAX_BACKFILL_SECONDS = 7 * 24 * 60 * 60
MAX_SLICES = MAX_BACKFILL_SECONDS // SLICE_SECONDS
# Fixed allowance for the first resumed V1 cycle and the bounded re-inventory
# retries, on top of the per-slice gap recovery budget below.
ROLLBACK_RECOVERY_MARGIN_SECONDS = 60 * 60
# Persisted-row readbacks wait for a freshly collected summary to become
# searchable: exponential pauses from 1 s, each capped, with a bounded total.
SUMMARY_INDEX_WAIT_INITIAL_SECONDS = 1.0
SUMMARY_INDEX_WAIT_MAX_SECONDS = 15.0
SUMMARY_INDEX_WAIT_BUDGET_SECONDS = 60.0


def _summary_wait_delays(
    initial: float, cap: float, budget: float
) -> tuple[float, ...]:
    delays: list[float] = []
    delay, total = initial, 0.0
    while total < budget:
        step = min(delay, cap, budget - total)
        delays.append(step)
        total += step
        delay *= 2
    return tuple(delays)


SUMMARY_INDEX_WAIT_DELAYS = _summary_wait_delays(
    SUMMARY_INDEX_WAIT_INITIAL_SECONDS,
    SUMMARY_INDEX_WAIT_MAX_SECONDS,
    SUMMARY_INDEX_WAIT_BUDGET_SECONDS,
)
SUMMARY_INDEX_WAIT_ATTEMPTS = len(SUMMARY_INDEX_WAIT_DELAYS) + 1
# _v1_recovery_window refuses once the last resumed cycle ends more than seven
# days after the pre-pause boundary, and that end tracks the wall clock on every
# rerun, so rollback must finish inside the bound. The tool imposes no wall-clock
# limit on a search job, so the pre-flight uses this planning budget per gap
# slice (a conservative allowance, not a Splunk guarantee): the source read,
# retained-row read, writer and up to SUMMARY_INDEX_WAIT_ATTEMPTS readbacks are
# at most ROLLBACK_SEARCHES_PER_SLICE searches, each allowed
# ROLLBACK_SEARCH_BUDGET_SECONDS, plus the readback sleeps and the writer's
# JOB_METADATA_WAIT_SECONDS identity wait.
ROLLBACK_SEARCHES_PER_SLICE = 3 + SUMMARY_INDEX_WAIT_ATTEMPTS
ROLLBACK_SEARCH_BUDGET_SECONDS = 15
CATALOG_SETTLED_JOB_STATES = frozenset(
    {"complete", "failed", "rejected", "preparation_aborted"}
)
MAX_RESULTS = 10000
MAX_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_RESULT_ARTIFACT_BYTES = 16 * 1024 * 1024
# The candidate copies journal coverage plus the validation scenario.
MAX_CANDIDATE_BYTES = 2 * MAX_JOURNAL_BYTES
MAX_RESULT_EVIDENCE_BYTES = 256 * 1024 * 1024
# Rollback evidence has its own budget so forward-path evidence cannot leave a
# started rollback unable to persist the results it must read back on resume.
MAX_RECOVERY_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_COLLECTION_ROWS = 100000
# Enabled identity and interface builders rewrite these on every run. Staged
# outputs that read them are compared row by row, so only readability is bound.
LIVE_BUILDER_COLLECTIONS = ("adm_ip_identity", "adm_interfaces")
COLLECTION_PAGE_SIZE = 500
ROLLUP_ID_QUERY_BATCH = 250
SCHEDULED_WRITER_WAIT_SECONDS = 2.0
JOB_METADATA_WAIT_SECONDS = 30.0
JOB_METADATA_WAIT_ATTEMPTS = 120
ROLLBACK_SLICE_BUDGET_SECONDS = (
    ROLLBACK_SEARCHES_PER_SLICE * ROLLBACK_SEARCH_BUDGET_SECONDS
    + sum(SUMMARY_INDEX_WAIT_DELAYS)
    + JOB_METADATA_WAIT_SECONDS
)
JOURNAL_SCHEMA = 2
JOURNAL_DEFAULT = Path.home() / ".splunk-adm" / "cisco-contract-migration.json"
VOLATILE_SAVED_SEARCH_FIELDS = {
    "next_scheduled_time",
    "next_scheduled_time_epoch",
    "last_run",
    "last_run_time",
    "last_success",
    "last_success_time",
    "dispatchState",
    "isDone",
    "isFinalized",
    "run_duration",
    "run_time",
    "updated_at",
    "eai:acl",
}
REQUIRED_SURFACES = {
    "graph",
    "catalog",
    "find",
    "health",
    "evidence_drilldown",
    "topology",
}
ALLOWED_PREDICATES = {
    "contains",
    "allowed_values",
    "equals_or_missing",
    "must_exist_in_node_ids",
    "must_resolve_to_device_ids",
    "flat_json_array_if_present",
    "traffic_observation_contract",
    "equals",
    "unique_for_source_authority_native",
    "is_not_null",
    "null_when_mapping_unmapped_or_ambiguous",
    "distinct_from",
    "not_null",
    "contains_all",
    "only_explicit_physical_links",
    "exactly_one_mapped_row_for_cross_domain_join",
    "required_for_kubernetes_nodes",
    "topology_mapping_scope_consistency",
    "source_qualified_before_aggregation",
    "legacy_explicit_physical_links",
}


class MigrationError(RuntimeError):
    """A safe refusal or a known migration failure."""


class Uncertain(MigrationError):
    """A remote operation may have completed; manual reconciliation is required."""


class Refused(MigrationError):
    """The target configuration or evidence did not meet a precondition."""


STREAMS = {
    "conversation": {
        "saved_search": "ADM - Conversation rollup v2",
        "source": "adm:conversation",
        "record": "conversation",
        "records": ("conversation", "hubble_xlate", "hubble_l7"),
        "macro": "adm_conversation_rollup_v2",
    },
    "traffic": {
        "saved_search": "ADM - Traffic observation rollup v2",
        "source": "adm:traffic_observation",
        "record": "traffic_observation",
        "records": ("traffic_observation",),
        "macro": "adm_traffic_observations_v2",
    },
}
EMPTY_SUMMARY_WARNING = {"type": "WARN", "text": "No results to summary index."}
EMPTY_SUMMARY_WRITERS = {
    "ADM - Conversation rollup",
    "ADM - Conversation rollup v2",
    "ADM - Traffic observation rollup v2",
}
REQUIRED_MACROS = (
    "adm_index_summary",
    "adm_summary_index_name",
    "adm_index_summary_v2",
    "adm_summary_index_v2_name",
    "adm_data_contract_version",
    "adm_graph(4)",
    "adm_catalog_build",
    "adm_find(1)",
    "adm_health_sources",
    "adm_flow_evidence(4)",
    "adm_topology",
    "adm_health_quality",
    "adm_network_client_history_observations",
    "adm_network_client_history_build",
    "adm_catalog_build_status_v2",
    "adm_catalog_build_v2",
    "adm_catalog_writer_v2",
)
REQUIRED_SEARCHES = tuple(item["saved_search"] for item in STREAMS.values()) + (
    "ADM - Conversation rollup",
    "ADM - Network client history builder",
    "ADM - Application catalog",
    "ADM - Application catalog v2",
)
V1_ROW_FIELDS = (
    "_time",
    "rollup_id",
    "replay_protected",
    "adm_record",
    "scope",
    "client_ip",
    "server_ip",
    "server_port",
    "transport",
    "flow_source",
    "observer",
    "observations",
    "bytes_c2s",
    "bytes_s2c",
    "packets",
    "records",
    "client_ports",
    "client_port_list",
    "conns",
    "conns_capped",
    "sampled",
    "first_seen",
    "last_seen",
    "direction_basis",
    "encapsulation",
    "acl_permits",
    "acl_drops",
    "xlate_ip",
    "xff",
    "trace_ids",
    "vlan_observations",
    "vlan_observations_truncated",
)

# Versioned physical-row projections used by the migration and rollback parity
# audits. Keep these aligned with the reviewed load probe projections.
V2_ROW_FIELDS = {
    "conversation": tuple(
        "_time contract_version rollup_id replay_protected adm_record scope client_ip server_ip server_port "
        "transport flow_source observer observations bytes_c2s bytes_s2c packets records client_ports "
        "client_port_list conns conns_capped sampled first_seen last_seen direction_basis encapsulation "
        "acl_permits acl_drops xlate_ip xff trace_ids vlan_observations vlan_observations_truncated".split()
    ),
    "traffic": tuple(
        "_time contract_version adm_record rollup_id replay_protected scope cluster routing_domain "
        "source_port destination_port source_mac destination_mac raw_bytes raw_packets raw_sampling "
        "counter_semantics metrics_authoritative adm_profile_status adm_scope_source adm_scope_authority "
        "adm_scope_domain_kind adm_scope_observation_domain_present adm_scope_observation_domain_id "
        "adm_scope_vpn_id adm_scope_routing_domain adm_registered_profiles adm_quality_status "
        "adm_quality_errors adm_quality_warnings quality_status quality_errors quality_warnings "
        "source_ip destination_ip server_port transport first_seen last_seen received_time direction "
        "records traffic_observations".split()
    ),
}
# Version 2 drops the columns below from parity material: they are resolved
# against adm_ip_identity / adm_interfaces, which enabled builders rewrite, so a
# later recomputation cannot tell builder activity from a changed source.
SUMMARY_CANONICALIZER_VERSION = 3
V2_LOOKUP_DERIVED_FIELDS = {"conversation": ("encapsulation",), "traffic": ()}


def _observations_without_netflow_interfaces(value: Any, observer: Any) -> Any:
    """Keep every observation; V1 resolves only NetFlow interface names.

    A NetFlow entry is "<observer>[:<in>><out>]" where the row's observer is
    "netflow:<exporter>". Only the interface part is looked up, so the observer
    prefix stays in the material. Matching on the known observer avoids parsing
    exporter addresses or interface names, either of which may contain ":".
    """
    if not isinstance(value, str):
        return value
    prefix = f"{observer}:" if isinstance(observer, str) else None
    netflow = prefix is not None and observer.startswith("netflow:")
    kept = set()
    for item in value.split("|"):
        if netflow and item.startswith(prefix):
            item = prefix
        kept.add(item)
    return "|".join(sorted(kept))


def _vlan_observations_without_interface_names(value: Any, truncated: Any) -> Any:
    """Drop V1's looked-up "interface" key; keep every other VLAN context field."""
    if not isinstance(value, str):
        return value
    try:
        items = json.loads(value)
    except ValueError:
        return value
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        return value
    if _truth(truncated):
        # The retained 32 contexts are chosen by sorted JSON text, which the
        # interface name changes, so nothing but truncation itself is stable.
        return {"truncated": True}
    # Contexts that differed only by interface (named in one run, unnamed in
    # another) are one context; merge their time bounds like adm_vlan_merge.
    contexts: dict[str, dict[str, Any]] = {}
    for item in items:
        context = {
            key: item[key]
            for key in item
            if key not in {"interface", "first_seen", "last_seen"}
        }
        text = json.dumps(context, sort_keys=True, separators=(",", ":"))
        merged = contexts.setdefault(text, {"first_seen": [], "last_seen": []})
        for bound in ("first_seen", "last_seen"):
            if bound in item:
                number = _number(item[bound])
                if number is None:
                    raise Refused("VLAN observation time bound is not numeric")
                merged[bound].append(int(number) if number.is_integer() else number)
    return sorted(
        json.dumps(
            {
                **json.loads(text),
                **(
                    {"first_seen": min(bounds["first_seen"])}
                    if bounds["first_seen"]
                    else {}
                ),
                **(
                    {"last_seen": max(bounds["last_seen"])}
                    if bounds["last_seen"]
                    else {}
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for text, bounds in contexts.items()
    )


def _summary_content(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Canonical full summary material while preserving missing versus zero."""
    numeric = {
        "_time",
        "server_port",
        "source_port",
        "destination_port",
        "raw_bytes",
        "raw_packets",
        "bytes_c2s",
        "bytes_s2c",
        "packets",
        "records",
        "client_ports",
        "conns_capped",
        "sampled",
        "first_seen",
        "last_seen",
        "acl_permits",
        "acl_drops",
        "vlan_observations_truncated",
        "traffic_observations",
    }
    optional_empty = {
        "routing_domain",
        "adm_scope_authority",
        "adm_scope_observation_domain_id",
        "adm_scope_vpn_id",
        "adm_scope_routing_domain",
    }
    multivalue = {
        "adm_quality_errors",
        "adm_quality_warnings",
        "quality_errors",
        "quality_warnings",
        "trace_ids",
    }
    stable = {}
    for field in fields:
        value = row.get(field)
        if field in optional_empty and value in (None, ""):
            value = None
        if field in multivalue:
            if value is None or value == "":
                value = []
            elif isinstance(value, str):
                value = value.splitlines()
        if field in numeric and value is not None:
            parsed = _number(value)
            if parsed is not None:
                value = int(parsed) if parsed.is_integer() else parsed
        stable[field] = value
    return stable


def _add_record_maps(left: dict, right: dict, *, label: str) -> dict:
    """Add physical multiplicities, refusing conflicting material per ID."""
    combined = {key: dict(value) for key, value in left.items()}
    for key, value in right.items():
        if key in combined:
            prior = combined[key]
            if prior.get("content_digest") != value.get("content_digest"):
                raise Refused(f"{label} contains conflicting material for a rollup ID")
            prior["copies"] = int(prior.get("copies", 1)) + int(value.get("copies", 1))
        else:
            combined[key] = dict(value)
    return combined


ADMIN_ROLES = {"admin", "sc_admin"}
SAVEDSEARCH_DISPATCH_OWNER = "splunk-system-user"
ROLLUP_ID_RE = re.compile(r"^[0-9a-f]{64}$")
INTERFACE_PATH = ROOT / "research" / "cisco-pipeline-interface.json"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _truth(value: Any) -> bool:
    return str(value).lower() in {"1", "true"}


def _job_active(content: dict[str, Any]) -> bool:
    # FINALIZING may still flush collect/outputlookup writes even if isDone
    # arrived early; it is never a safe drain boundary.
    return content.get("dispatchState") == "FINALIZING" or not _truth(
        content.get("isDone")
    )


def _job_pre_execution(content: dict[str, Any]) -> bool:
    return content.get("dispatchState") in {
        "PARSING",
        "QUEUED",
        "PENDING",
    } and not _truth(content.get("isDone"))


def _job_messages_complete(messages: Any, empty_warning: bool = False) -> bool:
    if not isinstance(messages, list):
        return False
    if not messages:
        return True
    if empty_warning:
        return True
    return all(
        isinstance(message, dict)
        and message.get("type") == "INFO"
        and isinstance(message.get("text"), str)
        and bool(message.get("text"))
        for message in messages
    )


def _config_equal(field: str, actual: Any, expected: Any) -> bool:
    """Compare effective REST config while handling Splunk's bool/string shapes."""
    if field in {"disabled", "enableSched", "is_scheduled"}:

        def parsed(value: Any) -> bool | None:
            if value is True or value == 1 or str(value).lower() in {"1", "true"}:
                return True
            if value is False or value == 0 or str(value).lower() in {"0", "false"}:
                return False
            return None

        left, right = parsed(actual), parsed(expected)
        return left is not None and left == right
    return actual == expected


def _canonical_spl_whitespace(value: Any) -> str | None:
    """Collapse SPL whitespace outside quoted literals for contract checks."""
    if not isinstance(value, str):
        return None
    result: list[str] = []
    pending_space = False
    quote: str | None = None
    escaped = False
    for char in value:
        if quote is not None:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            if pending_space and result:
                result.append(" ")
            pending_space = False
            result.append(char)
            quote = char
        elif char.isspace():
            pending_space = True
        else:
            if pending_space and result:
                result.append(" ")
            pending_space = False
            result.append(char)
    if quote is not None or escaped:
        return None
    return "".join(result).strip()


# ECMAScript \s, so the marker parses as frontend normalizeDefinition does.
_JS_SPACE = "[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]"


def _contract_marker(value: Any) -> str | None:
    """Normalize the contract-version macro like the Setup UI."""
    if not isinstance(value, str):
        return None
    value = re.sub(r"\\\r?\n" + _JS_SPACE + "*", " ", value)
    return re.sub(_JS_SPACE + "+", " ", value).strip(" ")


def _macro_definition_equal(actual: Any, expected: Any) -> bool:
    """Compare selector SPL while preserving quoted literal bytes."""
    left = _canonical_spl_whitespace(actual)
    right = _canonical_spl_whitespace(expected)
    return left is not None and left == right


def _strict_bool(value: Any) -> bool | None:
    if value is True or (not isinstance(value, bool) and value == 1):
        return True
    if value is False or (not isinstance(value, bool) and value == 0):
        return False
    if isinstance(value, str) and value.lower() in {"1", "true"}:
        return True
    if isinstance(value, str) and value.lower() in {"0", "false"}:
        return False
    return None


def _integer(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if str(value).strip() == str(number) and number >= 0 else None


def _job_sid(entry: dict[str, Any]) -> str:
    """Return the REST job identity, never the search-text entry name."""
    content = entry.get("content")
    if not isinstance(content, dict):
        raise Refused("search job entry has no content identity")
    sid = content.get("sid")
    if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", sid):
        raise Refused("search job entry has a missing or malformed content.sid")
    entry_id = entry.get("id")
    if entry_id is not None:
        if not isinstance(entry_id, str):
            raise Refused("search job entry has a malformed id")
        parsed = urlparse(entry_id)
        if parsed.query or parsed.fragment:
            raise Refused("search job entry has a malformed id")
        match = re.fullmatch(r"/services/search/(?:v2/)?jobs/([^/]+)", parsed.path)
        if match is None or unquote(match.group(1)) != sid:
            raise Refused("search job entry has conflicting id and content.sid")
    return sid


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def rollback_recovery_horizon_seconds(gap_seconds: int) -> float:
    """Projected pre-pause-to-finish span of an enabled-origin rollback."""
    slices = -(-max(0, gap_seconds) // SLICE_SECONDS)
    return (
        gap_seconds
        + slices * ROLLBACK_SLICE_BUDGET_SECONDS
        + ROLLBACK_RECOVERY_MARGIN_SECONDS
    )


def plan_slices(start: int, end: int, now: int | None = None) -> list[dict[str, int]]:
    """Return aligned, fully closed 5-minute index-time slices within fixed bounds."""
    if isinstance(start, bool) or isinstance(end, bool) or start >= end:
        raise Refused("backfill range must have start before end")
    if start % SLICE_SECONDS or end % SLICE_SECONDS:
        raise Refused("backfill boundaries must align to closed 5-minute slices")
    if end - start > MAX_BACKFILL_SECONDS:
        raise Refused("backfill range exceeds the seven-day limit")
    current = int(time.time() if now is None else now)
    closed_cutoff = current // SLICE_SECONDS * SLICE_SECONDS - 2 * SLICE_SECONDS
    if end > closed_cutoff:
        raise Refused("backfill end must leave two closed slices for indexing lag")
    result = [
        {"start": point, "end": point + SLICE_SECONDS}
        for point in range(start, end, SLICE_SECONDS)
    ]
    if not result or len(result) > MAX_SLICES:
        raise Refused("backfill slice count is outside the qualified limit")
    return result


def _check_state_directory(directory: Path) -> None:
    try:
        link = directory.lstat()
        if stat.S_ISLNK(link.st_mode) and link.st_uid != 0:
            raise Refused(
                f"journal directory {directory} is a symlink; use its real path"
            )
        info = directory.stat()
    except OSError as error:
        raise Refused(
            f"journal directory {directory} is not usable: {error.strerror or error}"
        ) from None
    if not stat.S_ISDIR(info.st_mode):
        raise Refused(f"journal directory {directory} is not a directory")
    if info.st_uid not in (0, os.geteuid()):
        raise Refused(
            f"journal directory {directory} is owned by another user; "
            "choose a directory you own"
        )
    if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise Refused(
            f"journal directory {directory} is group/world-writable without the "
            "sticky bit; choose a private directory (for example chmod 700 it yourself)"
        )


def _verify_created_directory(directory: Path) -> None:
    try:
        info = directory.lstat()
    except OSError as error:
        raise Refused(
            f"journal directory {directory} is not usable: {error.strerror or error}"
        ) from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise Refused(
            f"journal directory {directory} was not created as an owner-only "
            "directory; choose a directory you own"
        )


def ensure_state_directory(directory: Path) -> None:
    """Create (0700) or validate the directory holding journal state; never chmod it.

    Every directory this function creates is verified after creation, and one that
    appears concurrently is validated like an existing leaf. Pre-existing ancestors
    above the first directory created are trusted as given by the operator.
    """
    directory = Path(directory)
    missing = []
    try:
        probe = directory
        while not os.path.lexists(probe):
            missing.append(probe)
            if probe.parent == probe:
                break
            probe = probe.parent
        for candidate in reversed(missing):
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                _check_state_directory(candidate)
            else:
                _verify_created_directory(candidate)
    except OSError as error:
        raise Refused(
            f"journal directory {directory} is not usable: {error.strerror or error}"
        ) from None
    _check_state_directory(directory)
