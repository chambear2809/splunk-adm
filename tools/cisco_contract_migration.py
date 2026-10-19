#!/usr/bin/env python3
"""Stage and verify the Application Atlas summary contract v2 on standalone Splunk.

The tool is deliberately conservative. It uses a local, durable journal and
Splunk's TLS-verified local management REST API. It never accepts a token as an
argument, never retries an ambiguous search dispatch, and never changes the
legacy summary index macro.
"""

from __future__ import annotations

import argparse
import contextlib
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import stat
import tempfile
import time
from typing import Any
from urllib.parse import quote, unquote, urlparse
import uuid

ROOT = Path(__file__).resolve().parents[1]
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


class Journal:
    """Atomic local journal with a companion advisory lock and owner-only mode."""

    def __init__(self, path: Path):
        self.path = Path(path).expanduser()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    @contextmanager
    def locked(self, *, blocking: bool = True):
        ensure_state_directory(self.path.parent)
        try:
            fd = os.open(
                self.lock_path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as error:
            raise Refused(
                f"journal lock {self.lock_path} is unavailable: "
                f"{error.strerror or error}"
            ) from None
        try:
            try:
                if os.fstat(fd).st_uid != os.geteuid():
                    raise Refused("journal lock file is owned by another user")
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                    raise Refused("journal lock must be an owner-only regular file")
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except OSError as error:
                raise Refused(
                    f"journal lock {self.lock_path} is unavailable: "
                    f"{error.strerror or error}"
                ) from None
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def read(self) -> dict[str, Any] | None:
        try:
            fd = os.open(
                self.path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise Refused(
                "journal must be a regular owner-only file owned by the current user"
            ) from None
        try:
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise Refused(
                        "journal must be a regular owner-only file owned by the "
                        "current user"
                    )
                if info.st_size > MAX_JOURNAL_BYTES:
                    raise Refused("journal exceeds the 16 MiB limit")
                raw = stream.read(MAX_JOURNAL_BYTES + 1)
            if len(raw) > MAX_JOURNAL_BYTES:
                raise Refused("journal exceeds the 16 MiB limit")
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise Refused("journal is unreadable or corrupt") from None
        if not isinstance(value, dict) or value.get("schema") != JOURNAL_SCHEMA:
            raise Refused("journal schema is unsupported")
        return value

    def write(self, value: dict[str, Any]) -> None:
        payload = canonical(value)
        if len(payload) > MAX_JOURNAL_BYTES:
            raise Refused("journal exceeds the 16 MiB limit")
        self._atomic_write(self.path, payload, "journal")

    @staticmethod
    def _atomic_write(
        path: Path, payload: bytes, label: str, prefix: str = ".cisco-contract-"
    ) -> None:
        name = None
        try:
            fd, name = tempfile.mkstemp(prefix=prefix, dir=path.parent)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as error:
            raise Refused(
                f"{label} {path} could not be written: {error.strerror or error}"
            ) from None
        finally:
            if name is not None:
                with contextlib.suppress(OSError):
                    if os.path.exists(name):
                        os.unlink(name)

    @staticmethod
    def write_artifact(path: Path, value: dict[str, Any]) -> str:
        path = Path(path)
        ensure_state_directory(path.parent)
        payload = canonical(value)
        Journal._atomic_write(path, payload, "artifact", ".cisco-candidate-")
        return hashlib.sha256(payload).hexdigest()


class Migration:
    """Injectable orchestration for staged v2 summary backfill and cutover."""

    def __init__(
        self,
        api,
        journal: Journal,
        *,
        clock=time.time,
        sleep=time.sleep,
        qualifier=None,
    ):
        self.api = api
        self.journal = journal
        self.clock = clock
        self.sleep = sleep
        self.qualifier = qualifier

    @contextmanager
    def operation_locked(self, *, lock_directory: Path | None = None):
        """Serialize one OS user's local controller by verified target GUID.

        This is an extra local guard, not a remote/distributed run fence. The
        operator still owns an exclusive lifecycle across other users/hosts.
        Acquire target before journal in every mutating CLI/harness path.
        """
        self.qualify()
        server = self._single_entry("/services/server/info").get("content") or {}
        guid = server.get("guid")
        if not isinstance(guid, str) or not guid.strip():
            raise Refused("target GUID is unavailable for local operation fencing")
        directory = lock_directory or Path.home() / ".splunk-adm/cisco-target-locks"
        ensure_state_directory(directory)
        _verify_created_directory(directory)
        identity = hashlib.sha256(canonical([guid, "splunk_adm"])).hexdigest()
        target = Journal(directory / (identity + ".operation"))
        with target.locked(blocking=False), self.journal.locked(blocking=False):
            yield

    def _request(self, method: str, path: str, data=None):
        try:
            return self.api.request(method, path, data=data, json_body=False)
        except Exception as exc:
            status = getattr(exc, "status", None)
            if isinstance(status, int) and 400 <= status < 500:
                raise Refused(
                    f"Splunk REST rejected the request (HTTP {status})"
                ) from None
            # Never propagate client exception text; it may contain server or auth details.
            raise MigrationError(
                f"Splunk REST request failed ({type(exc).__name__})"
            ) from None

    @staticmethod
    def _interface() -> tuple[dict[str, Any], str]:
        try:
            raw = INTERFACE_PATH.read_bytes()
            interface = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise Refused(
                "authoritative pipeline interface manifest is unavailable"
            ) from None
        if not isinstance(interface, dict) or interface.get("contract_version") != 1:
            raise Refused("pipeline interface manifest version is unsupported")
        activation = interface.get("activation", {})
        flow = interface.get("flow_v2", {})
        expected = {
            "default": "adm_data_contract_version=1",
            "summary_v1_index_macro": "adm_index_summary -> index=adm_summary",
            "summary_v1_writer_index_macro": "adm_summary_index_name -> adm_summary",
            "summary_v2_index_macro": "adm_index_summary_v2 -> index=adm_summary_v2",
            "summary_v2_writer_index_macro": "adm_summary_index_v2_name -> adm_summary_v2",
            "v1_reader": "adm_graph(4)",
            "v2_reader": "adm_graph_v2(4)",
        }
        if any(activation.get(key) != value for key, value in expected.items()):
            raise Refused(
                "pipeline interface manifest conflicts with the supported v1/v2 contract"
            )
        if flow.get("searches") != [item["saved_search"] for item in STREAMS.values()]:
            raise Refused(
                "pipeline interface manifest has unexpected staged writer names"
            )
        if (
            flow.get("conversation_rollup") != "adm_conversation_rollup_v2"
            or flow.get("traffic_observation_rollup") != "adm_traffic_observations_v2"
        ):
            raise Refused(
                "pipeline interface manifest has unexpected v2 writer definitions"
            )
        if (
            flow.get("records")
            != "Version-2 conversations retain the base v1 fields plus contract_version=2 and use rollup IDs with a v2 prefix. Stream flow records are kept in separate source=adm:traffic_observation records and excluded from conversation totals."
        ):
            raise Refused("pipeline interface manifest v2 record contract changed")
        activation_writers = activation.get("writer_contracts")
        if not isinstance(activation_writers, list):
            raise Refused("pipeline interface has no exact writer contract allowlist")
        writer_names = {
            item.get("name") for item in activation_writers if isinstance(item, dict)
        }
        if writer_names != set(REQUIRED_SEARCHES):
            raise Refused(
                "pipeline interface writer allowlist is incomplete or unexpected"
            )
        staged = interface.get("staged_collections")
        history = (staged or {}).get("network_client_history")
        catalog = (staged or {}).get("application_catalog_v2")
        if (
            not isinstance(history, dict)
            or history.get("collection") != "adm_network_client_history"
            or history.get("builder_search") != "ADM - Network client history builder"
            or history.get("builder_source_query")
            != "| `adm_network_client_history_build`"
            or not isinstance(history.get("expected_row_query"), str)
            or not isinstance(history.get("expected_row_fields"), list)
            or history.get("expected_row_fields") != history.get("fields")
            or set(history.get("validation", {}).get("allowed_mapping_statuses", []))
            != {"mapped", "unmapped", "ambiguous"}
            or not isinstance(catalog, dict)
            or catalog.get("collection") != "adm_app_catalog_v2"
            or catalog.get("writer_search") != "ADM - Application catalog v2"
            or catalog.get("writer_source_query") != "| `adm_catalog_writer_v2`"
            or catalog.get("status_query") != "| `adm_catalog_build_status_v2`"
            or catalog.get("read_query")
            != "| inputlookup strict=true adm_app_catalog_v2"
            or not isinstance(catalog.get("dispatch_bounds"), dict)
            or catalog["dispatch_bounds"].get("earliest_time") != "-1h@h"
            or catalog["dispatch_bounds"].get("latest_time") != "@h"
        ):
            raise Refused("staged history/catalog collection contract is incomplete")
        for item in activation_writers:
            if not isinstance(item, dict) or item.get("kind") != "saved_search":
                raise Refused(
                    "pipeline interface contains an unsupported writer target"
                )
            name = item["name"]
            expected_target = SEARCHES + quote(name, safe="")
            if item.get("rest_target") != expected_target:
                raise Refused(
                    "pipeline interface writer REST target is not allowlisted"
                )
            fields = item.get("fields")
            transition = item.get("state_transition")
            if (
                not isinstance(fields, dict)
                or not isinstance(fields.get("search"), str)
                or not isinstance(item.get("source_query"), str)
                or item.get("bounded_source_query_only") is not True
                or not isinstance(transition, dict)
            ):
                raise Refused("pipeline interface writer contract is incomplete")
            if name in {spec["saved_search"] for spec in STREAMS.values()}:
                stream = next(
                    key for key, spec in STREAMS.items() if spec["saved_search"] == name
                )
                suffix = f' | collect index=`adm_summary_index_v2_name` source="{STREAMS[stream]["source"]}"'
                if fields["search"] != item["source_query"].strip() + suffix:
                    raise Refused("pipeline interface staged writer SPL is not exact")
                if str(fields.get("disabled")) not in {"1", "true", "True"}:
                    raise Refused("pipeline interface staged writer must ship disabled")
            elif name == "ADM - Conversation rollup":
                suffix = ' | collect index=`adm_summary_index_name` source="adm:conversation"'
                if fields["search"] != item["source_query"].strip() + suffix:
                    raise Refused(
                        "pipeline interface legacy writer does not preserve the v1 index"
                    )
        selectors = activation.get("cutover_selectors")
        expected_selector_names = {
            "adm_data_contract_version",
            "adm_graph(4)",
            "adm_catalog_build",
            "adm_find(1)",
            "adm_health_sources",
            "adm_flow_evidence(4)",
            "adm_topology",
            "adm_health_quality",
        }
        if (
            not isinstance(selectors, list)
            or {item.get("name") for item in selectors if isinstance(item, dict)}
            != expected_selector_names
        ):
            raise Refused(
                "pipeline interface selector allowlist is incomplete or unexpected"
            )
        for selector in selectors:
            if (
                not isinstance(selector, dict)
                or selector.get("kind") != "macro_definition"
                or selector.get("field") != "definition"
                or selector.get("rest_target")
                != MACROS + quote(str(selector.get("name", "")), safe="()")
                or not isinstance(selector.get("before"), str)
                or not isinstance(selector.get("after"), str)
            ):
                raise Refused("pipeline interface selector target is not allowlisted")
        return interface, hashlib.sha256(raw).hexdigest()

    def _single_entry(self, path: str) -> dict[str, Any]:
        response = self._request("GET", path)
        entries = response.get("entry")
        if (
            not isinstance(entries, list)
            or len(entries) != 1
            or not isinstance(entries[0], dict)
        ):
            raise Refused("target configuration evidence is incomplete")
        return entries[0]

    @staticmethod
    def _stable_saved_search_content(content: dict[str, Any]) -> dict[str, Any]:
        """Drop REST runtime counters while retaining effective search settings."""
        return {
            key: value
            for key, value in content.items()
            if key not in VOLATILE_SAVED_SEARCH_FIELDS and not key.startswith("eai:")
        }

    @staticmethod
    def _normalize_saved_search_schedule(
        content: dict[str, Any], expected_fields: dict[str, Any]
    ) -> dict[str, Any]:
        """Canonicalize Splunk REST schedule aliases for one writer contract.

        Splunk may expose ``is_scheduled`` even when the saved-search
        configuration contract names the source field ``enableSched``. Keep
        the contract's spelling in snapshots, but only when the REST evidence
        is present and unambiguous.
        """
        schedule_fields = [
            field
            for field in ("enableSched", "is_scheduled")
            if field in expected_fields
        ]
        if len(schedule_fields) != 1:
            raise Refused("writer schedule contract is missing an exact schedule field")
        canonical_field = schedule_fields[0]
        alias_field = (
            "is_scheduled" if canonical_field == "enableSched" else "enableSched"
        )
        has_canonical = canonical_field in content
        has_alias = alias_field in content
        if not has_canonical and not has_alias:
            raise Refused("saved search schedule evidence is missing")
        if has_canonical and _strict_bool(content[canonical_field]) is None:
            raise Refused("saved search schedule evidence is invalid")
        if has_alias and _strict_bool(content[alias_field]) is None:
            raise Refused("saved search schedule alias evidence is invalid")
        if (
            has_canonical
            and has_alias
            and not _config_equal(
                canonical_field, content[canonical_field], content[alias_field]
            )
        ):
            raise Refused("saved search schedule aliases conflict")
        normalized = dict(content)
        if not has_canonical:
            normalized[canonical_field] = content[alias_field]
        normalized.pop(alias_field, None)
        return normalized

    def _entries(
        self, path: str, *, max_count: int = MAX_RESULTS
    ) -> list[dict[str, Any]]:
        response = self._request("GET", path)
        entries = response.get("entry")
        paging = response.get("paging") or {}
        total = _integer(paging.get("total"))
        if not isinstance(entries, list) or total is None or total != len(entries):
            raise Refused("target REST listing is incomplete")
        if total > max_count or any(not isinstance(row, dict) for row in entries):
            raise Refused("target REST listing exceeds the qualified bound")
        return entries

    def _collection_rows(self, name: str) -> list[dict[str, Any]]:
        base = APP + "/storage/collections/data/" + quote(name, safe="")
        records = []
        offset = 0
        while True:
            page = self._request(
                "GET",
                base + f"?limit={COLLECTION_PAGE_SIZE}&skip={offset}&sort=_key:1",
            )
            if not isinstance(page, list) or len(page) > COLLECTION_PAGE_SIZE:
                raise Refused(f"{name} paged read is malformed")
            records.extend(page)
            if len(records) > MAX_COLLECTION_ROWS:
                raise Refused(f"{name} collection exceeds the qualified row bound")
            if len(page) < COLLECTION_PAGE_SIZE:
                # A reduced server query cap can masquerade as a short final
                # page. Sorted overlap proves there is no extra hidden row.
                probe = self._request(
                    "GET",
                    base
                    + f"?limit={COLLECTION_PAGE_SIZE}&skip={offset + 1}&sort=_key:1",
                )
                if probe != page[1:]:
                    raise Refused(
                        f"{name} collection read is capped or changed during completion proof"
                    )
                break
            offset += len(page)
        return records

    def _collection_snapshot(self, name: str) -> dict[str, Any]:
        records = self._collection_rows(name)
        if any(not isinstance(row, dict) or not row.get("_key") for row in records):
            raise Refused(f"{name} snapshot contains malformed rows")
        records = sorted(records, key=lambda row: str(row["_key"]))
        if len({row["_key"] for row in records}) != len(records):
            raise Refused(f"{name} snapshot contains duplicate keys")
        return {
            "count": len(records),
            "sha256": fingerprint(records),
            "complete_paged_read": True,
        }

    def _live_collection_presence(self, name: str) -> dict[str, Any]:
        base = APP + "/storage/collections/data/" + quote(name, safe="")
        page = self._request("GET", base + "?limit=1")
        if (
            not isinstance(page, list)
            or len(page) > 1
            or any(not isinstance(row, dict) or not row.get("_key") for row in page)
        ):
            raise Refused(f"{name} collection read is malformed")
        return {"live_builder_collection": True, "readable": True}

    def _macro(self, name: str) -> dict[str, Any]:
        return self._single_entry(MACROS + quote(name, safe=""))

    def _saved_search(self, name: str) -> dict[str, Any]:
        return self._single_entry(SEARCHES + quote(name, safe=""))

    @staticmethod
    def _acl(entry: dict[str, Any]) -> dict[str, tuple[str, ...]]:
        perms = (entry.get("acl") or {}).get("perms") or {}
        result = {}
        for action in ("read", "write"):
            roles = perms.get(action)
            if not isinstance(roles, list) or not roles or set(roles) - ADMIN_ROLES:
                raise Refused("saved-search ACL is not administrator-only")
            result[action] = tuple(sorted(set(roles)))
        return result

    def qualify(self) -> None:
        try:
            # The packaged recovery qualifier fails closed on version, role,
            # Cloud, SHC, indexer-cluster and peer evidence.
            if self.qualifier:
                self.qualifier()
            else:
                from adm_recovery_lib.core import Recovery

                Recovery(self.api).qualify_deployment()
        except MigrationError:
            raise
        except Exception as exc:
            raise Refused(
                f"standalone deployment qualification failed ({type(exc).__name__})"
            ) from None

    def snapshot(self, *, allow_activation: bool = False) -> dict[str, Any]:
        interface, _ = self._interface()
        server = self._single_entry("/services/server/info").get("content") or {}
        if not server.get("guid") or not server.get("version"):
            raise Refused("target instance identity is incomplete")
        context = (
            self._single_entry("/services/authentication/current-context").get(
                "content"
            )
            or {}
        )
        if not set(context.get("roles", [])) & ADMIN_ROLES:
            raise Refused("administrator session is required")
        required_capabilities = {
            "search",
            "schedule_search",
            "run_collect",
            "output_file",
        }
        if not required_capabilities.issubset(set(context.get("capabilities", []))):
            raise Refused(
                "administrator session lacks required search/write capabilities"
            )
        macros = {}
        for name in REQUIRED_MACROS:
            entry = self._macro(name)
            content = entry.get("content") or {}
            args = content.get("args", "")
            self._macro_args_parts(name, args)
            macros[name] = {
                "definition": content.get("definition"),
                "args": args,
                "acl": entry.get("acl", {}),
            }
        all_macros = self._entries(
            APP + "/configs/conf-macros?count=10000", max_count=MAX_RESULTS
        )
        macro_inventory = [
            {
                "name": entry.get("name"),
                "content": entry.get("content") or {},
                "acl": entry.get("acl") or {},
            }
            for entry in all_macros
            if entry.get("name")
            not in {
                selector.get("name")
                for selector in interface["activation"]["cutover_selectors"]
            }
        ]
        macro_inventory.sort(key=lambda item: str(item.get("name", "")))
        all_transforms = self._entries(
            APP + "/configs/conf-transforms?count=10000", max_count=MAX_RESULTS
        )
        transform_inventory = [
            {
                "name": entry.get("name"),
                "content": entry.get("content") or {},
                "acl": entry.get("acl") or {},
            }
            for entry in all_transforms
        ]
        transform_inventory.sort(key=lambda item: str(item.get("name", "")))
        searches = {}
        for name in REQUIRED_SEARCHES:
            entry = self._saved_search(name)
            searches[name] = {
                "content": self._stable_saved_search_content(entry.get("content", {})),
                "acl": entry.get("acl", {}),
            }
            self._acl(entry)
        writer_contracts = {
            item["name"]: item for item in interface["activation"]["writer_contracts"]
        }
        for name, item in searches.items():
            searches[name]["content"] = self._normalize_saved_search_schedule(
                item["content"], writer_contracts[name]["fields"]
            )
        for writer in interface["activation"]["writer_contracts"]:
            actual = searches[writer["name"]]["content"]
            for field, expected in writer["fields"].items():
                if field == "disabled":
                    continue
                if not _config_equal(field, actual.get(field), expected):
                    raise Refused(
                        "writer schedule or definition differs from the shipped contract"
                    )
        v1_index = macros["adm_index_summary"]["definition"]
        v1_write = macros["adm_summary_index_name"]["definition"]
        v2_index = macros["adm_index_summary_v2"]["definition"]
        v2_write = macros["adm_summary_index_v2_name"]["definition"]
        if v1_index != f"index={V1_INDEX}" or v1_write != V1_INDEX:
            raise Refused("legacy summary reader/writer contract differs from v1")
        if v2_index != f"index={V2_INDEX}" or v2_write != V2_INDEX:
            raise Refused("staged summary reader/writer contract differs from v2")
        if V1_INDEX == V2_INDEX:
            raise Refused("v1 and v2 summary indexes must be distinct")
        active_version = macros["adm_data_contract_version"]["definition"]
        if active_version != "1" and not (allow_activation and active_version == "2"):
            raise Refused(
                "active data contract is not v1; inspect current cutover state"
            )
        selectors = {
            selector["name"]: selector
            for selector in interface["activation"]["cutover_selectors"]
        }
        for name, selector in selectors.items():
            current = macros[name]["definition"]
            if not _macro_definition_equal(current, selector["before"]) and not (
                allow_activation and _macro_definition_equal(current, selector["after"])
            ):
                raise Refused(
                    "a public selector differs from both journal origin and cutover target"
                )
        for key, spec in STREAMS.items():
            item = searches[spec["saved_search"]]
            content = item["content"]
            expected = writer_contracts[spec["saved_search"]]["fields"]
            mismatches = [
                field
                for field, value in expected.items()
                if field != "disabled"
                and not _config_equal(field, content.get(field), value)
            ]
            disabled = str(content.get("disabled", "")).lower()
            if disabled not in {"1", "true"} and not (
                allow_activation and disabled in {"0", "false"}
            ):
                mismatches.append("disabled")
            if mismatches:
                raise Refused(
                    f"{key} staged writer differs from the shipped v2 contract"
                )
            if content.get("dispatchAs") != "owner":
                raise Refused(f"{key} staged writer is not owner-dispatched")
            if str(content.get("disabled", "")).lower() not in {"1", "true"} and not (
                allow_activation
                and str(content.get("disabled", "")).lower() in {"0", "false"}
            ):
                raise Refused(f"{key} staged writer schedule must remain disabled")
        data_snapshots = {
            name: self._collection_snapshot(name)
            for name in (
                "adm_observer_scope",
                "adm_network_source_scope",
                "adm_cilium_cluster_settings",
            )
        }
        data_snapshots.update(
            {
                name: self._live_collection_presence(name)
                for name in LIVE_BUILDER_COLLECTIONS
            }
        )
        return {
            "target": {
                "guid": server["guid"],
                "version": server["version"],
                "app": "splunk_adm",
            },
            "principal": {
                "username": context.get("username"),
                "roles": sorted(set(context.get("roles", []))),
                "capabilities": sorted(required_capabilities),
            },
            "macros": macros,
            "macro_inventory": fingerprint(macro_inventory),
            "transform_inventory": fingerprint(transform_inventory),
            "effective_lookup_data": data_snapshots,
            "saved_searches": searches,
        }

    def prepare(self, start: int, end: int) -> dict[str, Any]:
        self.qualify()
        interface, interface_hash = self._interface()
        slices = plan_slices(start, end, int(self.clock()))
        snapshot = self.snapshot()
        journal = self.journal.read()
        if journal:
            if journal.get("origin_fingerprint") != fingerprint(snapshot):
                raise Refused("effective configuration differs from the journal origin")
            if journal.get("interface_sha256") != interface_hash:
                raise Refused("pipeline interface manifest changed after preparation")
            self._assert_canonicalizer_current(journal)
            if journal.get("range") != {"start": start, "end": end}:
                raise Refused("journal already belongs to a different backfill range")
            if "preexisting_v2_rows" not in journal:
                self._verify_preexisting_index(journal)
            return journal
        journal = {
            "schema": JOURNAL_SCHEMA,
            "canonicalizer_version": SUMMARY_CANONICALIZER_VERSION,
            "migration_id": uuid.uuid4().hex,
            "created_at": int(self.clock()),
            "interface_sha256": interface_hash,
            "interface_contract_version": interface.get("contract_version"),
            "phase": "prepared",
            "range": {"start": start, "end": end},
            # Absolute and durable so a resumed job has identical REST bounds.
            "event_earliest": "0",
            "event_latest": str(int(self.clock()) + 15 * 60),
            "origin": snapshot,
            "origin_fingerprint": fingerprint(snapshot),
            "slices": [
                {
                    **time_slice,
                    "streams": {name: {"state": "pending"} for name in STREAMS},
                    "history": {"state": "pending"},
                }
                for time_slice in slices
            ],
            # Keep only hashes and receipt extents for rows that existed
            # before this migration. The collection may contain a valid
            # baseline from an earlier attempt; it must survive every staged
            # replay without copying client fields into the journal.
            "history_baseline": self._history_baseline_snapshot(interface),
            "catalog": {"state": "pending"},
            "jobs": [],
            "cutover": None,
            "rollback": None,
        }
        self._write_journal(journal)
        self._verify_preexisting_index(journal)
        return journal

    def _result_artifact_path(self, journal, record) -> Path:
        identity = [journal.get("migration_id"), record.get("id")]
        if any(
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
            for value in identity
        ):
            raise Refused("result artifact identity is invalid")
        return self.journal.path.with_name(
            self.journal.path.name
            + ".result-"
            + ("recovery-" if record.get("recovery_evidence") else "")
            + fingerprint(identity)
            + ".json"
        )

    @staticmethod
    def _read_result_artifact_file(
        path: Path, limit: int = MAX_RESULT_ARTIFACT_BYTES
    ) -> bytes:
        try:
            fd = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_size > limit
                ):
                    raise Refused(
                        "result artifact ownership, permissions, type or size is invalid"
                    )
                payload = stream.read(limit + 1)
                if len(payload) != info.st_size or len(payload) > limit:
                    raise Refused("result artifact changed or exceeds its bound")
                return payload
        except OSError:
            raise Refused("result artifact is unavailable or unsafe") from None

    @staticmethod
    def _result_artifact_identity(journal, record):
        return {
            "schema": 1,
            "migration_id": journal.get("migration_id"),
            "job_id": record.get("id"),
            "kind": record.get("kind"),
            "label": record.get("label"),
            "query_fingerprint": record.get("query_fingerprint"),
            "request_bounds": record.get("request_bounds"),
            "result_count": record.get("result_count"),
        }

    def _persist_result_artifact(self, journal, record):
        rows = record["result_rows"]
        if not isinstance(rows, list) or len(rows) != record.get("result_count"):
            raise Refused("cached result count does not match the job")
        path = self._result_artifact_path(journal, record)
        value = {**self._result_artifact_identity(journal, record), "rows": rows}
        payload = canonical(value)
        if len(payload) > MAX_RESULT_ARTIFACT_BYTES:
            raise Refused("result artifact exceeds the 16 MiB limit")
        prefix = self.journal.path.name + ".result-"
        recovery_prefix = prefix + "recovery-"
        recovery = bool(record.get("recovery_evidence"))
        limit = MAX_RECOVERY_EVIDENCE_BYTES if recovery else MAX_RESULT_EVIDENCE_BYTES
        total = 0
        for candidate in path.parent.iterdir():
            if candidate.name.startswith(prefix) and candidate.name.endswith(".json"):
                info = candidate.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or info.st_size > MAX_RESULT_ARTIFACT_BYTES
                ):
                    raise Refused("existing result evidence is unsafe")
                if candidate.name.startswith(recovery_prefix) == recovery:
                    total += info.st_size
        if path.exists() or path.is_symlink():
            if self._read_result_artifact_file(path) != payload:
                raise Refused("immutable result artifact differs from this job")
        else:
            if total + len(payload) > limit:
                raise Refused("result evidence exceeds the 256 MiB budget")
            try:
                self.journal.write_artifact(path, value)
            except (OSError, Refused) as error:
                raise Refused(
                    f"result evidence could not be persisted ({error}); "
                    "resume the recorded SID"
                ) from error
        if total > limit:
            raise Refused("existing result evidence exceeds the 256 MiB budget")
        record["result_artifact"] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
        del record["result_rows"]

    def _cached_result_rows(self, journal, record):
        reference = record.get("result_artifact")
        if reference is not None:
            if not isinstance(reference, dict):
                raise Refused("result artifact reference is malformed")
            payload = self._read_result_artifact_file(
                self._result_artifact_path(journal, record)
            )
            if len(payload) != reference.get("bytes") or hashlib.sha256(
                payload
            ).hexdigest() != reference.get("sha256"):
                raise Refused("result artifact digest or size differs from the journal")
            try:
                value = json.loads(payload)
            except (UnicodeError, json.JSONDecodeError):
                raise Refused("result artifact is corrupt") from None
            identity = self._result_artifact_identity(journal, record)
            if not isinstance(value, dict) or any(
                value.get(key) != expected for key, expected in identity.items()
            ):
                raise Refused("result artifact belongs to another job or query")
            rows = value.get("rows")
            if not isinstance(rows, list) or len(rows) != record.get("result_count"):
                raise Refused("result artifact row count differs from the job")
            return rows
        rows = record.get("result_rows")
        return rows if isinstance(rows, list) else None

    def _write_journal(self, journal: dict[str, Any]) -> None:
        # Prepared migration journals externalize complete query evidence before
        # the atomic journal replacement. Probe-only journals retain the original
        # inline format; they have no migration identity or durable recovery claim.
        if journal.get("migration_id"):
            for record in journal.get("jobs", []):
                if (
                    record.get("kind") in {"search", "saved_search"}
                    and record.get("state") == "complete"
                    and "result_rows" in record
                ):
                    self._persist_result_artifact(journal, record)
        journal["updated_at"] = int(self.clock())
        self.journal.write(journal)

    def _assert_origin_unchanged(self, journal: dict[str, Any]) -> None:
        for execution in reversed(journal.get("temporary_manual_executions", [])):
            if execution.get("state") != "restored":
                self._recover_temporary_manual_writer(journal, execution["name"])
        if journal.get("phase") in {"cutover_in_progress", "rollback_in_progress"}:
            self._assert_cutover_origin_compatible(journal)
            return
        if fingerprint(self.snapshot()) != journal.get("origin_fingerprint"):
            raise Refused("effective pipeline, mappings, or target changed")
        self._assert_no_competing_staged_jobs(journal)

    def _assert_no_competing_staged_jobs(self, journal: dict[str, Any]) -> None:
        entries = self._entries(JOBS + "?count=0")
        known_sids = {
            job.get("sid") for job in journal.get("jobs", []) if job.get("sid")
        }
        writer_names = {spec["saved_search"] for spec in STREAMS.values()}
        writer_names.update(
            {
                "ADM - Network client history builder",
                "ADM - Application catalog v2",
            }
        )
        writer_macros = {spec["macro"] for spec in STREAMS.values()}
        writer_macros.update(
            {"adm_network_client_history_build", "adm_catalog_writer_v2"}
        )
        for entry in entries:
            content = entry.get("content") or {}
            search = str(content.get("search", ""))
            label = content.get("label") or content.get("savedsearch_name")
            if (
                label in writer_names
                or any(f"`{macro}`" in search for macro in writer_macros)
                or re.search(
                    r"(?i)\bcollect\s+index\s*=\s*(?:`?adm_summary_index_v2_name`?|adm_summary_v2)\b",
                    search,
                )
            ) and _job_active(content):
                sid = _job_sid(entry)
                if sid not in known_sids:
                    raise Refused("a competing staged v2 writer job is active")

    @staticmethod
    def _scenario_query(surface: dict[str, Any], scenario: dict[str, Any]) -> str:
        invoke = surface.get("invoke")
        if not isinstance(invoke, str) or not invoke.strip():
            raise Refused("public-surface manifest has no executable query")
        query = invoke
        fields = set(re.findall(r"\{\{([a-z][a-z0-9_]*)\}\}", query))
        for field in fields:
            if (
                field not in scenario
                or not isinstance(scenario[field], str)
                or not scenario[field]
            ):
                raise Refused(f"validation scenario is missing {field}")
            if field == "server_port":
                if (
                    not re.fullmatch(r"[0-9]{1,5}", scenario[field])
                    or not 1 <= int(scenario[field]) <= 65535
                ):
                    raise Refused(
                        "validation scenario server_port must be a TCP/UDP port"
                    )
            elif not re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,128}", scenario[field]):
                raise Refused(
                    f"validation scenario {field} contains unsafe macro characters"
                )
            query = query.replace(
                "{{" + field + "}}", json.dumps(scenario[field])[1:-1]
            )
        if "{{" in query or "}}" in query:
            raise Refused("public-surface query contains an unresolved scenario value")
        if surface.get("read_only") is not True or not query.lstrip().startswith("|"):
            raise Refused(
                "public-surface query is not an allowlisted read-only macro call"
            )
        if "|" in query[1:] or ";" in query or "\n" in query or "\r" in query:
            raise Refused(
                "public-surface query contains commands outside its exact macro invocation"
            )
        return query

    @staticmethod
    def _validate_surface_predicates(
        rows: list[dict[str, Any]], surface: dict[str, Any], scenario: dict[str, Any]
    ) -> None:
        required = surface.get("required_fields")
        predicates = surface.get("predicates")
        if (
            not isinstance(required, list)
            or not required
            or any(not isinstance(field, str) or not field for field in required)
            or not isinstance(predicates, list)
        ):
            raise Refused("public-surface result contract is malformed")
        by_type = surface.get("required_fields_by_row_type")
        if by_type is not None and (
            not isinstance(by_type, dict)
            or not by_type
            or any(
                not isinstance(kind, str)
                or not kind
                or not isinstance(fields, list)
                or any(not isinstance(field, str) or not field for field in fields)
                for kind, fields in by_type.items()
            )
        ):
            raise Refused("public-surface row-type contract is malformed")
        for row in rows:
            if by_type is not None and row.get("row_type") not in by_type:
                raise Refused("public-surface row type is outside its contract")
            fields = required + (
                by_type[row["row_type"]] if by_type is not None else []
            )
            missing = [field for field in fields if field not in row]
            if missing:
                raise Refused(
                    "public-surface result is missing required fields: "
                    + ", ".join(missing)
                )
        for predicate in predicates:
            if not isinstance(predicate, dict):
                raise Refused("public-surface predicate is malformed")
            field = predicate.get("field")
            operator = predicate.get("operator")
            value = predicate.get("value")
            if (
                isinstance(value, str)
                and value.startswith("{{")
                and value.endswith("}}")
            ):
                scenario_key = value[2:-2]
                if scenario_key not in scenario:
                    raise Refused(f"validation scenario is missing {scenario_key}")
                value = scenario[scenario_key]
            if not isinstance(field, str) or operator not in ALLOWED_PREDICATES:
                raise Refused("public-surface predicate uses an unsupported rule")
            values = [row.get(field) for row in rows if field in row]
            if operator in {"contains", "contains_all"}:
                expected = value if isinstance(value, list) else [value]
                if not all(
                    any(str(item) in str(actual) for actual in values)
                    for item in expected
                ):
                    raise Refused("public-surface content predicate failed")
            elif operator == "allowed_values":
                allowed = {str(item) for item in value}
                if any(str(actual) not in allowed for actual in values):
                    raise Refused("public-surface value is outside its allowlist")
            elif operator == "equals":
                if not values or any(str(actual) != str(value) for actual in values):
                    raise Refused("public-surface equality predicate failed")
            elif operator == "equals_or_missing":
                if any(str(actual) != str(value) for actual in values):
                    raise Refused("public-surface version predicate failed")
            elif operator in {"not_null", "is_not_null"}:
                if not values or any(actual in (None, "", "null") for actual in values):
                    raise Refused("public-surface non-null predicate failed")
            elif operator == "distinct_from":
                if not rows or any(
                    str(row.get(field, "")) == str(row.get(value, "")) for row in rows
                ):
                    raise Refused("public-surface distinct-field predicate failed")
            elif operator == "traffic_observation_contract":
                for actual in values:
                    if actual in (None, ""):
                        continue
                    try:
                        observations = (
                            json.loads(actual) if isinstance(actual, str) else actual
                        )
                    except (TypeError, json.JSONDecodeError):
                        raise Refused("traffic evidence is not valid JSON") from None
                    if not isinstance(observations, list) or not observations:
                        raise Refused(
                            "traffic evidence must be a nonempty object array"
                        )
                    for observation in observations:
                        if not isinstance(observation, dict):
                            raise Refused(
                                "traffic evidence contains a non-object record"
                            )
                        status = observation.get("mapping_status")
                        if status not in {"mapped", "unmapped", "ambiguous"}:
                            raise Refused("traffic evidence mapping status is invalid")
                        if status == "mapped" and any(
                            observation.get(key) in (None, "")
                            for key in (
                                "source",
                                "source_authority",
                                "scope",
                                "cluster",
                                "domain_kind",
                            )
                        ):
                            raise Refused(
                                "mapped traffic evidence lacks qualified identity"
                            )
                        if status != "mapped" and any(
                            observation.get(key) not in (None, "", "null")
                            for key in ("scope", "cluster")
                        ):
                            raise Refused("unresolved traffic evidence carries a scope")
                        if "routing_domain" not in observation:
                            raise Refused(
                                "traffic evidence lost routing-domain context"
                            )
                        if (
                            observation.get("counter_semantics") != "unknown"
                            or str(observation.get("metrics_authoritative")) != "0"
                        ):
                            raise Refused(
                                "traffic counter semantics differ from the qualified unknown/0 contract"
                            )
            elif operator == "flat_json_array_if_present":
                for actual in values:
                    if actual in (None, ""):
                        continue
                    try:
                        decoded = (
                            json.loads(actual) if isinstance(actual, str) else actual
                        )
                    except (TypeError, json.JSONDecodeError):
                        raise Refused(
                            "public-surface JSON array predicate failed"
                        ) from None
                    if not isinstance(decoded, list) or any(
                        isinstance(item, (list, dict)) for item in decoded
                    ):
                        raise Refused("public-surface JSON array predicate failed")
            elif operator == "must_exist_in_node_ids":
                node_ids = {
                    str(row.get("id")) for row in rows if row.get("row_type") == "node"
                }
                targets = [
                    str(row.get("target"))
                    for row in rows
                    if row.get("context_edge_target")
                ]
                if any(target not in node_ids for target in targets):
                    raise Refused("public-surface graph reference predicate failed")
            elif operator == "unique_for_source_authority_native":
                entities = [
                    row
                    for row in rows
                    if row.get("endpoint_kind") == "network_client"
                    or row.get("row_type") == "device"
                ]
                identities = []
                ids = []
                for row in entities:
                    source = row.get("attr_source") or row.get("source")
                    authority = row.get("attr_source_authority") or row.get(
                        "source_authority"
                    )
                    native = row.get("attr_native_id") or row.get("native_id")
                    entity_id = (
                        row.get("node_id") or row.get("id") or row.get("device_id")
                    )
                    if not all(
                        isinstance(part, str) and part.strip()
                        for part in (source, authority, native, entity_id)
                    ):
                        raise Refused("public-surface identity is not source-qualified")
                    identities.append((source, authority, native))
                    ids.append(entity_id)
                if len(identities) != len(set(identities)) or len(ids) != len(set(ids)):
                    raise Refused("public-surface source identity is not unique")
            elif operator == "null_when_mapping_unmapped_or_ambiguous":
                ambiguous = {"unmapped", "ambiguous", "ambiguous_or_unmapped"}
                if any(
                    str(row.get("mapping_status", "")).lower() in ambiguous
                    and row.get(field) not in (None, "", "null")
                    for row in rows
                ):
                    raise Refused("public-surface unmapped observation carries a scope")
            elif operator == "source_qualified_before_aggregation":
                devices = [row for row in rows if row.get("row_type") == "device"]
                if not devices:
                    raise Refused("topology has no device evidence")
                identities = []
                device_ids = []
                for row in devices:
                    if not all(
                        isinstance(row.get(key), str) and row[key].strip()
                        for key in ("device_id", "device_authority")
                    ):
                        raise Refused("topology device authority or ID is missing")
                    device_ids.append(row["device_id"])
                    native = row.get("native_device_id")
                    if row.get("mapping_status") == "incomplete_identity":
                        if native not in (None, "", "null") or any(
                            row.get(key) not in (None, "", "null")
                            for key in ("scope", "cluster")
                        ):
                            raise Refused(
                                "incomplete topology device claims a native or scoped identity"
                            )
                    elif not isinstance(native, str) or not native.strip():
                        raise Refused("topology device native identity is missing")
                    else:
                        identities.append((row["device_authority"], native))
                if len(identities) != len(set(identities)) or len(device_ids) != len(
                    set(device_ids)
                ):
                    raise Refused("topology source-qualified device IDs are not unique")
            elif operator == "must_resolve_to_device_ids":
                device_ids = {
                    str(row.get("device_id"))
                    for row in rows
                    if row.get("row_type") == "device" and row.get("device_id")
                }
                links = [row for row in rows if row.get("row_type") == "link"]
                if any(
                    not row.get("a_device")
                    or not row.get("b_device")
                    or str(row.get("a_device")) not in device_ids
                    or str(row.get("b_device")) not in device_ids
                    for row in links
                ):
                    raise Refused("topology link endpoint does not resolve to a device")
            elif operator == "legacy_explicit_physical_links":
                if value != ["aci", "lldp", "cdp"]:
                    raise Refused("legacy topology link contract is unsupported")
                if any(
                    row.get("link_source") not in value
                    or not row.get("a_device")
                    or not row.get("b_device")
                    or row.get("a_device") == row.get("b_device")
                    for row in rows
                    if row.get("row_type") == "link"
                ):
                    raise Refused("legacy topology link lacks explicit source evidence")
            elif operator == "only_explicit_physical_links":
                links = [row for row in rows if row.get("row_type") == "link"]
                allowed_kinds = {"physical", "wireless_association"}
                if any(
                    row.get("link_kind") not in allowed_kinds
                    or not isinstance(row.get("link_source"), str)
                    or not row.get("link_source")
                    or not (
                        (row.get("a_device") and row.get("b_device"))
                        or (row.get("physical_adjacency") in (1, "1", True))
                    )
                    for row in links
                ):
                    raise Refused("topology contains an unsupported inferred link")
            elif operator == "topology_mapping_scope_consistency":
                expected_contract = {
                    "device_allowed_statuses": [
                        "mapped",
                        "unmapped",
                        "ambiguous",
                        "incomplete_identity",
                    ],
                    "mapped_device_requires_one_scope_and_cluster": True,
                    "unmapped_or_ambiguous_device_requires_null_scope_and_cluster": True,
                    "link_requires_mapping_status": "mapped",
                    "link_requires_existing_device_endpoints": True,
                }
                if value != expected_contract:
                    raise Refused("topology mapping predicate contract is unknown")
                for row in rows:
                    status = str(row.get("mapping_status", "")).lower()
                    if row.get("row_type") == "device":
                        if status not in {
                            "mapped",
                            "unmapped",
                            "ambiguous",
                            "incomplete_identity",
                        }:
                            raise Refused("topology device mapping state is invalid")
                        if status == "mapped" and not all(
                            isinstance(row.get(key), str) and row[key].strip()
                            for key in ("scope", "cluster")
                        ):
                            raise Refused("mapped topology device lacks scope/cluster")
                        if status != "mapped" and (
                            row.get("scope") not in (None, "", "null")
                            or row.get("cluster") not in (None, "", "null")
                        ):
                            raise Refused(
                                "unmapped topology device carries scope/cluster"
                            )
                    elif row.get("row_type") == "link" and status != "mapped":
                        raise Refused(
                            "topology link is not mapped to an explicit scope"
                        )
            elif operator == "required_for_kubernetes_nodes":
                if any(
                    str(row.get("device_kind", row.get("kind", ""))).lower()
                    in {"kubernetes_node", "k8s_node", "node"}
                    and not row.get(field)
                    for row in rows
                ):
                    raise Refused("Kubernetes topology node is missing its cluster")
            elif operator == "exactly_one_mapped_row_for_cross_domain_join":
                # Current pipeline manifest does not use this rule. Its contract
                # requires an explicit join key, so refuse ambiguous definitions.
                key = predicate.get("key_field")
                if not isinstance(key, str) or not key:
                    raise Refused("cross-domain join predicate has no key field")
                grouped: dict[str, list[dict[str, Any]]] = {}
                for row in rows:
                    if row.get(key) not in (None, ""):
                        grouped.setdefault(str(row[key]), []).append(row)
                if any(
                    sum(row.get("mapping_status") == "mapped" for row in group) != 1
                    for group in grouped.values()
                ):
                    raise Refused("cross-domain join did not resolve exactly once")
            else:
                # Structural semantics need a dedicated rule implementation; do not
                # claim a smoke test based on a rule this version cannot evaluate.
                raise Refused(f"public-surface predicate {operator} is not implemented")

    def _public_surface_evidence(
        self,
        journal: dict[str, Any],
        interface: dict[str, Any],
        scenario: dict[str, Any],
    ) -> list[dict[str, Any]]:
        surfaces = interface.get("public_surfaces")
        if not isinstance(surfaces, list):
            raise Refused("authoritative public-surface manifest is incomplete")
        by_name = {
            item.get("surface"): item for item in surfaces if isinstance(item, dict)
        }
        if set(by_name) != REQUIRED_SURFACES | {"writers"}:
            raise Refused(
                "public-surface manifest is incomplete or has unknown entries"
            )
        for name in REQUIRED_SURFACES:
            versions = by_name[name].get("v2") or {}
            if (
                not isinstance(versions, dict)
                or versions.get("status", "ready") != "ready"
                or not isinstance(versions.get("invoke"), str)
                or not versions.get("invoke")
                or not isinstance(versions.get("definition"), str)
                or not isinstance(versions.get("definition_sha256"), str)
            ):
                raise Refused(f"{name} v2 surface is blocked or incomplete")
        evidence = []
        for name in sorted(REQUIRED_SURFACES):
            item = by_name[name]
            versions = item.get("v2")
            if (
                not isinstance(versions, dict)
                or versions.get("status", "ready") != "ready"
            ):
                raise Refused(f"{name} v2 surface is blocked or incomplete")
            macro_name = versions.get("macro")
            expected_definition = versions.get("definition")
            expected_hash = versions.get("definition_sha256")
            if not isinstance(macro_name, str) or not isinstance(
                expected_definition, str
            ):
                raise Refused(f"{name} has no exact allowlisted v2 macro definition")
            if (
                hashlib.sha256(expected_definition.encode()).hexdigest()
                != expected_hash
            ):
                raise Refused(f"{name} v2 macro definition hash is invalid")
            live_definition = (self._macro(macro_name).get("content") or {}).get(
                "definition"
            )
            if not _macro_definition_equal(live_definition, expected_definition):
                raise Refused(
                    f"{name} v2 macro definition differs from the shipped interface"
                )
            query = self._scenario_query(versions, scenario)
            rows = self._query(
                journal, query, None, None, label=f"public surface smoke {name}"
            )
            self._validate_surface_predicates(rows, versions, scenario)
            evidence.append(
                {
                    "surface": name,
                    "query_sha256": fingerprint(query),
                    "row_count": len(rows),
                    "rows_sha256": fingerprint(rows),
                    "validated_at": int(self.clock()),
                }
            )
            if name == "evidence_drilldown":
                traffic = item.get("traffic_v2")
                if not isinstance(traffic, dict):
                    raise Refused("traffic evidence surface is missing")
                definition = traffic.get("definition")
                macro = traffic.get("macro")
                if (
                    not isinstance(definition, str)
                    or not isinstance(macro, str)
                    or hashlib.sha256(definition.encode()).hexdigest()
                    != traffic.get("definition_sha256")
                    or not _macro_definition_equal(
                        (self._macro(macro).get("content") or {}).get("definition"),
                        definition,
                    )
                ):
                    raise Refused("traffic evidence macro differs from its contract")
                traffic_query = self._scenario_query(traffic, scenario)
                traffic_rows = self._query(
                    journal,
                    traffic_query,
                    None,
                    None,
                    label="public surface smoke traffic evidence",
                )
                self._validate_surface_predicates(traffic_rows, traffic, scenario)
                evidence.append(
                    {
                        "surface": "traffic_evidence",
                        "query_sha256": fingerprint(traffic_query),
                        "row_count": len(traffic_rows),
                        "rows_sha256": fingerprint(traffic_rows),
                        "validated_at": int(self.clock()),
                    }
                )
            if name == "find":
                client_surface = item.get("network_client_v2")
                if not isinstance(client_surface, dict):
                    raise Refused("Find network-client history surface is missing")
                client_query = self._scenario_query(client_surface, scenario)
                client_rows = self._query(
                    journal,
                    client_query,
                    None,
                    None,
                    label="public surface smoke network client history",
                )
                self._validate_surface_predicates(client_rows, client_surface, scenario)
                evidence.append(
                    {
                        "surface": "network_client_history",
                        "query_sha256": fingerprint(client_query),
                        "row_count": len(client_rows),
                        "rows_sha256": fingerprint(client_rows),
                        "validated_at": int(self.clock()),
                    }
                )
        return evidence

    def _public_selector_smoke(
        self,
        journal: dict[str, Any],
        interface: dict[str, Any],
        scenario: dict[str, Any],
        *,
        phase: str,
    ) -> list[dict[str, Any]]:
        """Exercise the public macro entrypoints after selector mutation/restoration."""
        if phase not in {"public_after_invoke", "rollback_before_invoke"}:
            raise Refused("unsupported public selector smoke phase")
        surfaces = interface.get("public_surfaces")
        if not isinstance(surfaces, list):
            raise Refused("authoritative public-surface manifest is incomplete")
        evidence = []
        for item in surfaces:
            if not isinstance(item, dict) or item.get("surface") == "writers":
                continue
            for version_name in ("v2", "network_client_v2", "traffic_v2"):
                version = item.get(version_name)
                if not isinstance(version, dict):
                    continue
                invoke = version.get(phase)
                if not isinstance(invoke, str) or not invoke:
                    if version_name in {"network_client_v2", "traffic_v2"}:
                        invoke = version.get("invoke")
                    if not isinstance(invoke, str) or not invoke:
                        if version_name == "network_client_v2":
                            continue
                        raise Refused(
                            f"{item.get('surface')} has no {phase} public query"
                        )
                contract = version
                if phase == "rollback_before_invoke" and version_name not in {
                    "network_client_v2",
                    "traffic_v2",
                }:
                    contract = item.get("v1")
                    if not isinstance(contract, dict):
                        raise Refused(
                            f"{item.get('surface')} has no V1 rollback result contract"
                        )
                query_contract = {**contract, "invoke": invoke}
                query = self._scenario_query(query_contract, scenario)
                rows = self._query(
                    journal,
                    query,
                    None,
                    None,
                    label=f"{phase} selector smoke {item.get('surface')}:{version_name}",
                )
                self._validate_surface_predicates(rows, contract, scenario)
                evidence.append(
                    {
                        "surface": item.get("surface"),
                        "version": version_name,
                        "phase": phase,
                        "query_sha256": fingerprint(query),
                        "row_count": len(rows),
                        "rows_sha256": fingerprint(rows),
                        "validated_at": int(self.clock()),
                    }
                )
        required = {item for item in REQUIRED_SURFACES}
        observed = {item["surface"] for item in evidence}
        if observed != required:
            raise Refused("public selector smoke did not cover every required surface")
        return evidence

    def _load(self) -> dict[str, Any]:
        journal = self.journal.read()
        if not journal:
            raise Refused("migration journal does not exist; run prepare first")
        _, current_interface_hash = self._interface()
        if journal.get("interface_sha256") != current_interface_hash:
            raise Refused("pipeline interface manifest changed after preparation")
        self._assert_canonicalizer_current(journal)
        return journal

    @staticmethod
    def _assert_canonicalizer_current(journal: dict[str, Any]) -> None:
        # Digests recorded under another canonicalizer cannot be compared; fail
        # here instead of surfacing as misleading "content changed" refusals.
        recorded = journal.get("canonicalizer_version", 1)
        if recorded != SUMMARY_CANONICALIZER_VERSION:
            raise Refused(
                f"journal was written with summary canonicalizer version {recorded} "
                f"but this helper uses version {SUMMARY_CANONICALIZER_VERSION}; "
                "finish or roll it back with the helper that created it"
            )

    def _save_job(self, journal, job):
        journal.setdefault("jobs", []).append(job)
        self._write_journal(journal)

    @staticmethod
    def _evidence_class(journal) -> dict[str, Any]:
        if journal.get("phase") == "rollback_in_progress":
            return {"recovery_evidence": True}
        return {}

    def _manual_writer_entry(self, name: str) -> dict[str, Any]:
        return self._saved_search(name)

    def _manual_writer_check(self, execution: dict[str, Any]) -> dict[str, Any]:
        """Check the complete saved-search definition and ACL around a temporary run."""
        entry = self._manual_writer_entry(execution["name"])
        content = entry.get("content") or {}
        stable = self._stable_saved_search_content(content)
        for field in ("disabled", "enableSched", "is_scheduled"):
            stable.pop(field, None)
        if fingerprint(stable) != execution["search_fingerprint"]:
            raise Refused("saved-search definition drifted during temporary execution")
        acl = entry.get("acl") or (content.get("eai:acl") or {})
        if fingerprint(acl) != execution["acl_fingerprint"]:
            raise Refused("saved-search ACL drifted during temporary execution")
        return content

    @staticmethod
    def _manual_field_value(content: dict[str, Any], field: str) -> Any:
        if field == "is_scheduled":
            return content.get("is_scheduled", content.get("enableSched"))
        return content.get(field)

    def _manual_writer_field(
        self,
        journal: dict[str, Any],
        execution: dict[str, Any],
        field: str,
        value: Any,
        *,
        allowed_current: set[str],
    ) -> None:
        """Durably mutate and read back one temporary saved-search field."""
        content = self._manual_writer_check(execution)
        current = self._manual_field_value(content, field)
        pending_key = "pending_" + field
        prior_state = execution.get(pending_key)
        if prior_state in {"request_pending", "request_unknown"}:
            prior_target = execution.get("requested_" + field)
            prior_before = execution.get("before_" + field)
            if _config_equal(field, current, prior_target):
                execution[pending_key] = "applied"
                execution["observed_" + field] = current
                self._write_journal(journal)
            elif _config_equal(field, current, prior_before):
                execution[pending_key] = "request_unknown"
                self._write_journal(journal)
                raise Uncertain(
                    "temporary writer configuration outcome remains ambiguous"
                )
            else:
                raise Refused(
                    "temporary writer field drifted from both journaled states"
                )
        if _config_equal(field, current, value):
            execution["observed_" + field] = current
            self._write_journal(journal)
            return
        if not any(
            _config_equal(field, current, allowed) for allowed in allowed_current
        ):
            raise Refused("temporary writer field is outside the journaled transition")
        execution[pending_key] = "request_pending"
        execution["before_" + field] = current
        execution["requested_" + field] = value
        self._write_journal(journal)
        try:
            self._request(
                "POST",
                SEARCHES + quote(execution["name"], safe=""),
                {field: value},
            )
        except Refused:
            observed = self._manual_field_value(
                self._manual_writer_check(execution), field
            )
            if not _config_equal(field, observed, value):
                execution[pending_key] = "rejected"
                self._write_journal(journal)
                raise
        except MigrationError:
            observed = self._manual_field_value(
                self._manual_writer_check(execution), field
            )
            if not _config_equal(field, observed, value):
                execution[pending_key] = "request_unknown"
                self._write_journal(journal)
                raise Uncertain(
                    "temporary writer configuration outcome is unknown"
                ) from None
        observed = self._manual_field_value(self._manual_writer_check(execution), field)
        if not _config_equal(field, observed, value):
            execution[pending_key] = "readback_failed"
            self._write_journal(journal)
            raise Refused("temporary writer configuration readback failed")
        execution[pending_key] = "applied"
        execution["observed_" + field] = observed
        self._write_journal(journal)

    def _restore_manual_writer(
        self, journal: dict[str, Any], execution: dict[str, Any]
    ) -> None:
        # Disable first so the scheduler can never see an enabled writer.
        content = self._manual_writer_check(execution)
        schedule_value = self._manual_field_value(content, "is_scheduled")
        disabled_value = self._manual_field_value(content, "disabled")
        schedule_safe = _config_equal("is_scheduled", schedule_value, "0") or (
            _strict_bool(disabled_value) is True
            and _config_equal(
                "is_scheduled", schedule_value, execution["original_schedule"]
            )
        )
        if not schedule_safe:
            raise Refused("temporary writer must be unscheduled until disabled")
        self._manual_writer_field(
            journal,
            execution,
            "disabled",
            execution["original_disabled"],
            allowed_current={"0", execution["original_disabled"]},
        )
        content = self._manual_writer_check(execution)
        if _strict_bool(self._manual_field_value(content, "disabled")) is not True:
            raise Refused(
                "writer disablement did not read back before schedule restoration"
            )
        self._manual_writer_field(
            journal,
            execution,
            "is_scheduled",
            execution["original_schedule"],
            allowed_current={"0", execution["original_schedule"]},
        )
        execution["state"] = "restored"
        execution["restored_at"] = int(self.clock())
        self._write_journal(journal)

    def _recover_temporary_manual_writer(
        self, journal: dict[str, Any], name: str
    ) -> None:
        """Restore interrupted temporary config before snapshot guards run."""
        for execution in reversed(journal.get("temporary_manual_executions", [])):
            if execution.get("name") != name or execution.get("state") == "restored":
                continue
            self._restore_manual_writer(journal, execution)
            job = next(
                (
                    item
                    for item in journal.get("jobs", [])
                    if item.get("id") == execution.get("job_id")
                ),
                None,
            )
            if job and job.get("state") == "configuration_pending":
                job["state"] = "preparation_aborted"
                job["preparation_aborted_at"] = int(self.clock())
                self._write_journal(journal)
            elif job and job.get("state") in {"dispatch_pending", "dispatch_unknown"}:
                raise Uncertain(
                    "interrupted writer operation was restored; reconcile dispatch before retry"
                )

    def _temporary_manual_writer(
        self,
        journal: dict[str, Any],
        name: str,
        bounds: dict[str, str],
        job: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Prepare one disabled writer for a single manual dispatch, or resume safely.

        Returns None for already-authorized cutover writers. Disabled writers get
        a durable intent before either configuration field is changed.
        """
        interface, _ = self._interface()
        writer = next(
            (
                item
                for item in interface["activation"]["writer_contracts"]
                if item.get("name") == name
            ),
            None,
        )
        if writer is None:
            raise Refused("writer is absent from the authoritative allowlist")
        self._recover_temporary_manual_writer(journal, name)
        content = self._normalize_saved_search_schedule(
            (self._saved_search(name).get("content") or {}), writer["fields"]
        )
        disabled = _strict_bool(content.get("disabled"))
        if disabled is False and self._writer_enabled_by_journal(journal, name):
            return None
        if disabled is not True:
            raise Refused("writer must be disabled or enabled by journaled cutover")
        contract_schedule_field = next(
            field
            for field in ("enableSched", "is_scheduled")
            if field in writer["fields"]
        )
        schedule_field = "is_scheduled"
        entry = self._saved_search(name)
        acl = entry.get("acl") or {}
        stable = self._stable_saved_search_content(content)
        for field in ("disabled", "enableSched", "is_scheduled"):
            stable.pop(field, None)
        executions = journal.setdefault("temporary_manual_executions", [])
        linked = next(
            (item for item in reversed(executions) if item.get("job_id") == job["id"]),
            None,
        )
        if linked and linked.get("state") != "restored":
            # Pending means the POST may already have reached Splunk. Restore
            # configuration, but never send the same operation again.
            self._restore_manual_writer(journal, linked)
            if job.get("state") in {
                "configuration_pending",
                "dispatch_pending",
                "dispatch_unknown",
            }:
                raise Uncertain(
                    "writer dispatch remains ambiguous after safe configuration restore"
                )
            return linked
        if linked and job.get("state") in {
            "dispatch_pending",
            "dispatch_unknown",
            "running",
        }:
            return linked
        execution = {
            "id": uuid.uuid4().hex,
            "job_id": job["id"],
            "operation_id": uuid.uuid4().hex,
            "name": name,
            "request_bounds": dict(bounds),
            "state": "configuration_preparing",
            "original_disabled": content["disabled"],
            "original_schedule": content[contract_schedule_field],
            "schedule_field": schedule_field,
            "acl": acl,
            "acl_fingerprint": fingerprint(acl),
            "search_fingerprint": fingerprint(stable),
            "created_at": int(self.clock()),
        }
        executions.append(execution)
        self._write_journal(journal)
        # Ordered to avoid an enabled-and-scheduled intermediate state.
        self._manual_writer_field(
            journal,
            execution,
            schedule_field,
            "0",
            allowed_current={execution["original_schedule"]},
        )
        content = self._manual_writer_check(execution)
        if (
            not _config_equal(
                "is_scheduled", self._manual_field_value(content, "is_scheduled"), "0"
            )
            or _strict_bool(self._manual_field_value(content, "disabled")) is not True
        ):
            raise Refused(
                "writer must be disabled and unscheduled before manual enablement"
            )
        self._manual_writer_field(
            journal,
            execution,
            "disabled",
            "0",
            allowed_current={execution["original_disabled"]},
        )
        execution["state"] = "configuration_prepared"
        execution["prepared_at"] = int(self.clock())
        content = self._manual_writer_check(execution)
        if _strict_bool(
            self._manual_field_value(content, "disabled")
        ) is not False or not _config_equal(
            "is_scheduled", self._manual_field_value(content, "is_scheduled"), "0"
        ):
            raise Refused("temporary writer did not reach the exact manual-only state")
        self._write_journal(journal)
        return execution

    def _query(
        self,
        journal,
        query: str,
        index_earliest: int | None,
        index_latest: int | None,
        *,
        label: str,
        earliest_time: str | None = None,
        latest_time: str | None = None,
        persist_result_rows: bool = True,
    ) -> list[dict[str, Any]]:
        original_query_hash = fingerprint(query)
        # REST job creation requires an explicit command; manifest expressions
        # may use the same implicit-search form as saved searches and the UI.
        query = query.strip()
        if not query.startswith("|") and not re.match(r"search(?:\s|$)", query):
            query = "search " + query
        query_hash = fingerprint(query)
        request_bounds = {
            "earliest_time": str(earliest_time or journal["event_earliest"]),
            "latest_time": str(latest_time or journal["event_latest"]),
        }
        if index_earliest is not None:
            request_bounds["index_earliest"] = str(index_earliest)
        if index_latest is not None:
            request_bounds["index_latest"] = str(index_latest)
        if original_query_hash != query_hash:
            for prior in journal.get("jobs", []):
                if (
                    prior.get("kind") == "search"
                    and prior.get("label") == label
                    and prior.get("query_fingerprint") == original_query_hash
                    and prior.get("request_bounds") == request_bounds
                    and prior.get("state") != "rejected"
                ):
                    raise Uncertain(
                        "legacy implicit-search attempt requires reconciliation before normalized dispatch"
                    )
        for prior in journal.get("jobs", []):
            if (
                prior.get("kind") == "search"
                and prior.get("label") == label
                and prior.get("query_fingerprint") == query_hash
                and prior.get("request_bounds") == request_bounds
            ):
                if prior.get("state") in {"dispatch_pending", "dispatch_unknown"}:
                    raise Uncertain(
                        f"{label} has an ambiguous dispatch; reconcile by SID"
                    )
                if prior.get("state") == "running":
                    return self._read_job(journal, prior)
                if prior.get("state") == "complete":
                    rows = self._cached_result_rows(journal, prior)
                    if isinstance(rows, list):
                        return rows
                    if prior.get("persist_result_rows") is False:
                        continue
                    raise Refused("completed search journal is missing its result rows")
        record = {
            "id": uuid.uuid4().hex,
            "kind": "search",
            "label": label,
            "state": "dispatch_pending",
            "query_fingerprint": query_hash,
            "request_bounds": request_bounds,
            "persist_result_rows": persist_result_rows,
            **self._evidence_class(journal),
        }
        self._save_job(journal, record)
        try:
            response = self._request(
                "POST",
                CREATE_JOBS,
                {
                    "search": query,
                    "exec_mode": "normal",
                    **request_bounds,
                },
            )
        except Refused:
            # A REST 4xx is a known rejection; it is safe to record as failed
            # and report, but it must never be mistaken for an unknown dispatch.
            record["state"] = "rejected"
            self._write_journal(journal)
            raise
        except Exception:
            record["state"] = "dispatch_unknown"
            self._write_journal(journal)
            raise Uncertain(
                f"{label} search dispatch outcome is unknown; reconcile by SID"
            ) from None
        sid = response.get("sid")
        if not isinstance(sid, str) or not sid:
            record["state"] = "dispatch_unknown"
            self._write_journal(journal)
            raise Uncertain(
                f"{label} search returned no SID; reconcile before continuing"
            )
        record.update(state="running", sid=sid)
        self._write_journal(journal)
        return self._read_job(journal, record)

    @staticmethod
    def _job_search_matches(journal, record, actual):
        if not isinstance(actual, str) or not actual:
            return False
        expected = (
            record.get("search_fingerprint")
            if record.get("kind") == "saved_search"
            else record.get("query_fingerprint")
        )
        if fingerprint(actual) == expected:
            return True
        if record.get("kind") != "saved_search":
            return False
        # Splunk prefixes implicit saved-search expressions when executing.
        # Bind that one syntax normalization to the immutable origin definition;
        # do not rewrite a recorded fingerprint or normalize quoted literals.
        origin = (
            journal.get("origin", {})
            .get("saved_searches", {})
            .get(record.get("label"), {})
            .get("content")
            or {}
        ).get("search")
        if not isinstance(origin, str) or fingerprint(origin) != expected:
            return False
        submitted = origin.strip()
        if not submitted.startswith("|") and not re.match(r"search(?:\s|$)", submitted):
            submitted = "search " + submitted
        return actual == submitted

    def _read_job(
        self, journal: dict[str, Any], record: dict[str, Any]
    ) -> list[dict[str, Any]]:
        sid = record.get("sid")
        if not isinstance(sid, str) or not sid:
            raise Refused("search job has no recorded SID")
        path = JOBS + "/" + quote(sid, safe="")
        while True:
            response = self._request("GET", path)
            entries = response.get("entry")
            if not isinstance(entries, list) or len(entries) != 1:
                raise Uncertain("search job state is unavailable")
            entry = entries[0]
            content = entry.get("content") or {}
            self._validate_job_identity(
                journal, record, entry, allow_pre_execution=True
            )
            observed_name = (
                content.get("savedsearch_name") or content.get("label")
                if record.get("kind") == "saved_search"
                else None
            )
            name_missing = record.get("kind") == "saved_search" and not observed_name
            if (
                record.get("kind") == "saved_search"
                and observed_name
                and observed_name != record.get("label")
            ):
                raise Refused("SID does not belong to the journaled saved search")
            actual_search = content.get("search")
            pre_execution = _job_pre_execution(content)
            deadline = record.get("metadata_wait_deadline")
            search_missing = not isinstance(actual_search, str) or not actual_search
            if not search_missing and not self._job_search_matches(
                journal, record, actual_search
            ):
                if record.get("kind") == "saved_search":
                    raise Refused("SID does not match the journaled writer definition")
                raise Refused("SID does not match the journaled search query")
            type_missing = record.get("kind") == "saved_search" and not _truth(
                content.get("isSavedSearch")
            )
            if name_missing or search_missing or type_missing:
                if not pre_execution:
                    if name_missing:
                        raise Refused(
                            "terminal saved-search job is missing its identity"
                        )
                    raise Refused(
                        "terminal search job is missing executed search identity"
                    )
                if record.get("metadata_wait_timed_out"):
                    raise Uncertain(
                        "search identity metadata deadline expired; reconcile the recorded SID"
                    )
                attempts = int(record.get("metadata_wait_attempts", 0)) + 1
                record["metadata_wait_attempts"] = attempts
                if deadline is None:
                    deadline = float(self.clock()) + JOB_METADATA_WAIT_SECONDS
                    record["metadata_wait_deadline"] = deadline
                if (
                    attempts > JOB_METADATA_WAIT_ATTEMPTS
                    or float(self.clock()) >= deadline
                ):
                    record["metadata_wait_timed_out"] = True
                    self._write_journal(journal)
                    raise Uncertain(
                        "search identity metadata deadline expired; reconcile the recorded SID"
                    )
                record["job_state"] = {
                    "dispatchState": content.get("dispatchState"),
                    "isDone": content.get("isDone"),
                }
                self._write_journal(journal)
                self.sleep(0.25)
                continue
            if record.get("metadata_wait_timed_out"):
                record["metadata_wait_recovered_at"] = float(self.clock())
                record.pop("metadata_wait_timed_out", None)
                self._write_journal(journal)
            record["job_state"] = {
                key: content.get(key)
                for key in (
                    "dispatchState",
                    "isDone",
                    "isFinalized",
                    "eventIsTruncated",
                    "dropCount",
                    "resultCount",
                    "messages",
                )
            }
            self._write_journal(journal)
            if content.get("dispatchState") == "FAILED" or _truth(
                content.get("isFailed")
            ):
                record["state"] = "failed"
                self._write_journal(journal)
                raise Refused("search failed")
            if _truth(content.get("isDone")):
                break
            self.sleep(0.25)
        if (
            content.get("dispatchState") != "DONE"
            or not _truth(content.get("isDone"))
            or _truth(content.get("isFinalized"))
            or content.get("eventIsTruncated") not in (False, "0", 0)
            or _integer(content.get("dropCount")) != 0
        ):
            record["state"] = "failed"
            self._write_journal(journal)
            raise Refused("search did not complete without truncation or drops")
        total = _integer(content.get("resultCount"))
        if total is None or total > MAX_RESULTS:
            raise Refused("search result count is invalid or exceeds the bound")
        messages = content.get("messages")
        saved_search_name = (
            record.get("label") if record.get("kind") == "saved_search" else None
        )
        empty_summary_warning = (
            self._expected_empty_summary_warning(saved_search_name, content)
            and record.get("expected_empty") is True
        )
        info_messages_valid = isinstance(messages, list) and all(
            isinstance(message, dict)
            and message.get("type") == "INFO"
            and isinstance(message.get("text"), str)
            and bool(message.get("text"))
            for message in messages
        )
        if not isinstance(messages, list) or (
            messages and not info_messages_valid and not empty_summary_warning
        ):
            record["state"] = "failed"
            self._write_journal(journal)
            raise Refused("search reported warnings or errors")
        rows: list[dict[str, Any]] = []
        for offset in range(0, max(total, 1), 500):
            page = self._request("GET", path + f"/results?count=500&offset={offset}")
            if _truth(page.get("preview")):
                raise Refused("preview search results are not acceptable")
            batch = page.get("results")
            if not isinstance(batch, list):
                raise Refused("search results are malformed")
            rows.extend(batch)
        if len(rows) != total:
            raise Refused("search result count does not match returned rows")
        record.update(state="complete", result_count=total)
        if record.get("kind") in {"search", "saved_search"} and record.get(
            "persist_result_rows", True
        ):
            record["result_rows"] = rows
        else:
            record["result_digest"] = hashlib.sha256(canonical(rows)).hexdigest()
        self._write_journal(journal)
        return rows

    def _completed_job_rows(
        self, journal: dict[str, Any], record: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Reuse durable results of a validated complete job instead of its artifact."""
        if record.get("state") == "complete":
            rows = self._cached_result_rows(journal, record)
            if isinstance(rows, list):
                return rows
            if record.get("persist_result_rows") is False:
                raise Refused("completed writer job did not retain its result rows")
        return self._read_job(journal, record)

    def _validate_job_identity(
        self,
        journal,
        record,
        entry,
        *,
        persist_owner: bool = True,
        allow_pre_execution: bool = False,
    ) -> None:
        content = entry.get("content") or {}
        acl = entry.get("acl") or {}
        if acl.get("app") != "splunk_adm":
            raise Refused("SID belongs to a different app namespace")
        actual_request = content.get("request")
        expected_request = record.get("request_bounds")
        if not isinstance(actual_request, dict) or not isinstance(
            expected_request, dict
        ):
            raise Refused("SID is missing its exact dispatch bounds")
        if any(
            str(actual_request.get(key, "")) != str(value)
            for key, value in expected_request.items()
        ):
            raise Refused("SID dispatch bounds do not match this migration slice")
        if record.get("kind") == "search":
            request_search = actual_request.get("search")
            if not isinstance(request_search, str) or not request_search:
                raise Refused("SID request is missing its submitted search")
            if fingerprint(request_search) != record.get("query_fingerprint"):
                raise Refused("SID request search does not match the journaled query")
            expected_owner = (journal.get("origin", {}).get("principal") or {}).get(
                "username"
            )
            if (
                acl.get("owner") != expected_owner
                or not expected_owner
                or _truth(content.get("isSavedSearch"))
            ):
                raise Refused("SID owner or dispatch type does not match the request")
            return
        if record.get("kind") != "saved_search":
            raise Refused("journal contains an unsupported job kind")
        label = record.get("label")
        if not _truth(content.get("isSavedSearch")) and not (
            allow_pre_execution and _job_pre_execution(content)
        ):
            raise Refused("SID does not belong to the journaled saved search")
        observed_name = content.get("savedsearch_name") or content.get("label")
        if observed_name and observed_name != label:
            raise Refused("SID does not belong to the journaled saved search")
        if not observed_name and not _job_pre_execution(content):
            raise Refused("terminal saved-search job is missing its identity")
        owner = acl.get("owner")
        if not isinstance(owner, str) or not owner:
            raise Refused("saved-search SID has no effective dispatch owner")
        owners = journal.setdefault("saved_search_dispatch_owners", {})
        expected_owner = owners.get(label, SAVEDSEARCH_DISPATCH_OWNER)
        if owner != expected_owner:
            raise Refused("saved-search SID effective dispatch owner changed")
        if persist_owner:
            owners[label] = owner
            self._write_journal(journal)

    def _validate_reconcile_identity(self, journal, record, entry) -> None:
        """Require complete terminal identity before adopting an operator SID."""
        self._validate_job_identity(journal, record, entry, persist_owner=False)
        content = entry.get("content") or {}
        if record.get("kind") == "saved_search":
            observed_name = content.get("savedsearch_name") or content.get("label")
            if observed_name != record.get("label"):
                raise Refused("discovered SID has no exact saved-search identity")
            message = "discovered SID does not match the pending writer definition"
        else:
            message = "discovered SID does not match the pending search query"
        actual_search = content.get("search")
        if (
            not isinstance(actual_search, str)
            or not actual_search
            or not self._job_search_matches(journal, record, actual_search)
        ):
            raise Refused(message)

    def reconcile(self, sid: str) -> dict[str, Any]:
        """Adopt an operator-discovered SID for a pending unknown dispatch, never resend it."""
        self.qualify()
        journal = self._load()
        if journal.get("phase") in {
            "cutover_in_progress",
            "cutover",
            "rollback_in_progress",
        }:
            self._assert_cutover_origin_compatible(journal)
        elif fingerprint(self.snapshot()) != journal.get("origin_fingerprint"):
            raise Refused("effective configuration drifted before SID reconciliation")
        record = next(
            (
                item
                for item in reversed(journal.get("jobs", []))
                if item.get("state") in {"dispatch_pending", "dispatch_unknown"}
            ),
            None,
        )
        if not record:
            raise Refused("journal has no ambiguous dispatch to reconcile")
        if not isinstance(sid, str) or not sid.strip():
            raise Refused("a discovered SID is required")
        sid = sid.strip()
        entry = self._single_entry(JOBS + "/" + quote(sid, safe=""))
        self._validate_reconcile_identity(journal, record, entry)
        label = record.get("label", "")
        record.update(sid=sid, state="running", reconciled_at=int(self.clock()))
        self._write_journal(journal)
        self._read_job(journal, record)
        if record.get("kind") == "saved_search":
            if record.get("stream") in STREAMS:
                slice_record = next(
                    (
                        item
                        for item in journal["slices"]
                        if item["start"] == int(record["slice_start"])
                        and item["end"] == int(record["slice_end"])
                    ),
                    None,
                )
                if slice_record is None:
                    raise Refused("writer SID does not reference a journaled slice")
                stream_state = slice_record["streams"][record["stream"]]
                stream_state.update(state="backfill_done", sid=sid)
                self._write_journal(journal)
            elif record.get("writer_role") == "network_client_history":
                history_slices = [
                    *journal["slices"],
                    *(
                        (journal.get("cutover") or {}).get("history_bridge_slices")
                        or []
                    ),
                ]
                slice_record = next(
                    (
                        item
                        for item in history_slices
                        if item["start"] == int(record["slice_start"])
                        and item["end"] == int(record["slice_end"])
                    ),
                    None,
                )
                if slice_record is None:
                    raise Refused("history SID does not reference a journaled slice")
                slice_record["history"]["sid"] = sid
                self._write_journal(journal)
            elif record.get("writer_role") == "application_catalog_v2":
                journal.setdefault("catalog", {})["sid"] = sid
                self._write_journal(journal)
        return {"status": "reconciled", "sid": sid, "label": label}

    def _verify_preexisting_index(
        self, journal: dict[str, Any], *, final_pass: bool = False
    ) -> None:
        query = f"search index={V2_INDEX} | fields source " + " ".join(
            sorted(set(V2_ROW_FIELDS["conversation"] + V2_ROW_FIELDS["traffic"]))
        )
        rows = self._query(
            journal,
            query,
            0,
            int(self.clock()),
            label=(
                "final v2 index contract"
                if final_pass
                else "preexisting v2 index contract"
            ),
        )
        by_stream: dict[str, list[dict[str, Any]]] = {name: [] for name in STREAMS}
        for row in rows:
            if row.get("source") == "adm:conversation":
                stream = "conversation"
            elif row.get("source") == "adm:traffic_observation":
                stream = "traffic"
            else:
                raise Refused(
                    "v2 summary index contains a row from an unknown contract source"
                )
            records = _integer(row.get("records"))
            if (
                str(row.get("contract_version")) != CONTRACT_VERSION
                or row.get("adm_record") not in STREAMS[stream]["records"]
                or not ROLLUP_ID_RE.fullmatch(str(row.get("rollup_id", "")))
                or records is None
                or records <= 0
            ):
                raise Refused(
                    "v2 summary index contains a row outside contract version 2"
                )
            by_stream[stream].append(row)
        baseline = {}
        for stream, stream_rows in by_stream.items():
            mapped = self._record_map(stream_rows, stream)
            baseline.update(
                {
                    (STREAMS[stream]["source"], key): value
                    for key, value in mapped.items()
                }
            )
        if final_pass:
            expected = self._preexisting_v2_map(journal)
            if any(
                key not in baseline
                or baseline[key].get("content_digest") != value.get("content_digest")
                or int(baseline[key].get("copies", 1)) < int(value.get("copies", 1))
                for key, value in expected.items()
            ):
                raise Refused(
                    "pre-existing v2 summary baseline changed during migration"
                )
        else:
            prior_raw = journal.get("preexisting_v2_baseline")
            prior = self._preexisting_v2_map(journal) if prior_raw is not None else None
            if prior is not None and prior != baseline:
                raise Refused("pre-existing v2 summary baseline changed on resume")
            journal["preexisting_v2_baseline"] = [
                {"source": source, "rollup_id": rollup_id, **value}
                for (source, rollup_id), value in sorted(baseline.items())
            ]
            journal["preexisting_v2_rows"] = sum(
                int(value.get("copies", 1)) for value in baseline.values()
            )
            journal["preexisting_v2_fingerprint"] = fingerprint(
                journal["preexisting_v2_baseline"]
            )
            journal["preexisting_rollup_ids"] = [
                {"source": source, "rollup_id": rollup_id}
                for source, rollup_id in sorted(baseline)
            ]
        self._write_journal(journal)

    @staticmethod
    def _preexisting_v2_map(
        journal: dict[str, Any],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        raw = journal.get("preexisting_v2_baseline", [])
        if not isinstance(raw, list):
            raise Refused("pre-existing v2 summary baseline is malformed")
        result = {}
        for item in raw:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("source"), str)
                or not isinstance(item.get("rollup_id"), str)
            ):
                raise Refused("pre-existing v2 summary baseline is malformed")
            key = (item["source"], item["rollup_id"])
            value = {
                field: val
                for field, val in item.items()
                if field not in {"source", "rollup_id"}
            }
            if key in result:
                raise Refused(
                    "pre-existing v2 summary baseline has duplicate identities"
                )
            result[key] = value
        return result

    @staticmethod
    def _writer_enabled_by_journal(journal: dict[str, Any] | None, name: str) -> bool:
        if not isinstance(journal, dict):
            return False
        if journal.get("phase") in {"cutover_in_progress", "cutover"}:
            mutations = journal.get("cutover", {}).get("mutations") or []
        elif journal.get("phase") == "rollback_in_progress":
            mutations = journal.get("rollback", {}).get("mutations") or []
        else:
            return False
        return any(
            item.get("kind") == "saved_search"
            and item.get("name") == name
            and item.get("field") == "disabled"
            and item.get("state") == "applied"
            and _strict_bool(item.get("after")) is False
            for item in mutations
        )

    @staticmethod
    def _expected_empty_summary_warning(
        name: str | None, content: dict[str, Any]
    ) -> bool:
        return (
            name in EMPTY_SUMMARY_WRITERS
            and _integer(content.get("resultCount")) == 0
            and content.get("messages") == [EMPTY_SUMMARY_WARNING]
        )

    def _writer_query(
        self, spec: dict[str, str], journal: dict[str, Any] | None = None
    ) -> str:
        entry = self._saved_search(spec["saved_search"])
        interface, _ = self._interface()
        writer = next(
            item
            for item in interface["activation"]["writer_contracts"]
            if item["name"] == spec["saved_search"]
        )
        expected_fields = writer["fields"]
        content = self._normalize_saved_search_schedule(
            entry.get("content") or {}, expected_fields
        )
        for field, value in expected_fields.items():
            actual = content.get(field)
            if field == "disabled":
                if _strict_bool(actual) is True:
                    continue
                if _strict_bool(actual) is False and self._writer_enabled_by_journal(
                    journal, spec["saved_search"]
                ):
                    continue
                raise Refused("staged writer is enabled outside journaled cutover")
            if not _config_equal(field, actual, value):
                raise Refused("staged writer changed after preparation")
        return writer["source_query"].strip()

    @staticmethod
    def _record_map(
        rows: list[dict[str, Any]], stream: str
    ) -> dict[str, dict[str, Any]]:
        spec = STREAMS[stream]
        observed = {}
        for row in rows:
            key = str(row.get("rollup_id", ""))
            records = _integer(row.get("records"))
            if (
                not ROLLUP_ID_RE.fullmatch(key)
                or records is None
                or records <= 0
                or str(row.get("contract_version")) != CONTRACT_VERSION
                or row.get("adm_record") not in spec["records"]
            ):
                raise Refused(f"{stream} output failed row validation")
            content = _summary_content(
                row,
                tuple(
                    field
                    for field in V2_ROW_FIELDS[stream]
                    if field not in V2_LOOKUP_DERIVED_FIELDS[stream]
                ),
            )
            digest = fingerprint(
                {"canonicalizer": SUMMARY_CANONICALIZER_VERSION, "row": content}
            )
            if key in observed:
                if observed[key]["content_digest"] != digest:
                    raise Refused(
                        f"{stream} output contains conflicting material for a rollup ID"
                    )
                observed[key]["copies"] += 1
            else:
                observed[key] = {
                    "content": content,
                    "content_digest": digest,
                    "copies": 1,
                    "records": records,
                    "adm_record": row["adm_record"],
                }
        return observed

    def _wait_before_summary_retry(self, attempt: int) -> None:
        if attempt <= len(SUMMARY_INDEX_WAIT_DELAYS):
            self.sleep(SUMMARY_INDEX_WAIT_DELAYS[attempt - 1])

    def _persisted_query(
        self, journal, spec, expected, label: str, attempt: int
    ) -> dict[str, dict[str, Any]]:
        if not expected:
            return {}
        ids = sorted(expected)
        id_filter = ", ".join(f'"{item}"' for item in ids)
        # Cumulative expectations include the immutable retained baseline, which
        # may predate migration creation by an arbitrary amount.
        lower = 0
        upper = int(self.clock()) + 60
        query = (
            f'| search index={V2_INDEX} source="{spec["source"]}" '
            f"contract_version=2 rollup_id IN ({id_filter}) "
            f"| where _indextime>={lower} AND _indextime<={upper} "
            "| fields "
            + " ".join(V2_ROW_FIELDS["conversation"] + V2_ROW_FIELDS["traffic"])
        )
        rows = self._query(
            journal,
            query,
            None,
            None,
            label=f"{label} poll {attempt}",
        )
        return self._record_map(
            rows, next(name for name, item in STREAMS.items() if item is spec)
        )

    def _poll_persisted_rows(self, journal, expected, stream, label):
        spec = STREAMS[stream]
        if not expected:
            return {}
        ids = sorted(expected)
        if len(ids) > MAX_RESULTS:
            raise Refused(
                f"cumulative {stream} rollup IDs exceed the {MAX_RESULTS}-ID "
                "migration bound; prepare a shorter backfill range"
            )
        actual = {}
        for offset in range(0, len(ids), ROLLUP_ID_QUERY_BATCH):
            batch_number = offset // ROLLUP_ID_QUERY_BATCH + 1
            wanted = {
                key: expected[key]
                for key in ids[offset : offset + ROLLUP_ID_QUERY_BATCH]
            }
            for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
                observed = self._persisted_query(
                    journal, spec, wanted, f"{label} batch {batch_number}", attempt
                )
                if observed == wanted:
                    actual.update(observed)
                    break
                self._wait_before_summary_retry(attempt)
            else:
                raise Refused(
                    f"{stream} staged rollup IDs, record kinds, or event counts do not match source slice"
                )
        return actual

    def _cumulative_v2_expected(self, journal, stream, additional=()):
        """Return every physical V2 copy a migration-wide readback can see."""
        spec = STREAMS[stream]
        expected = {}
        for (source, rollup_id), value in self._preexisting_v2_map(journal).items():
            if source == spec["source"]:
                expected = _add_record_maps(
                    expected, {rollup_id: value}, label=f"{stream} immutable baseline"
                )
        for slice_record in journal.get("slices", []):
            stream_state = slice_record.get("streams", {}).get(stream) or {}
            manifest = stream_state.get("expected")
            if stream_state.get("state") != "verified":
                continue
            if isinstance(manifest, dict):
                expected = _add_record_maps(
                    expected, manifest, label=f"{stream} verified manual intents"
                )
        scheduled = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        for cycle in (scheduled.get(stream) or {}).get("cycles", []):
            if cycle.get("state") != "verified":
                continue
            manifest = cycle.get("expected")
            if isinstance(manifest, dict):
                expected = _add_record_maps(
                    expected, manifest, label=f"{stream} verified scheduled intents"
                )
        for manifest in additional:
            expected = _add_record_maps(
                expected, manifest, label=f"{stream} current scheduled intent"
            )
        return expected

    def _retire_undispatched_attempt(self, journal, record):
        """Retain a proven no-dispatch attempt before allowing a new intent."""
        if record.get("state") not in {
            "configuration_pending",
            "preparation_aborted",
            "rejected",
        } or record.get("sid"):
            raise Uncertain("writer attempt is not proven safe to retry")
        for execution in journal.get("temporary_manual_executions", []):
            if (
                execution.get("job_id") == record.get("id")
                and execution.get("state") != "restored"
            ):
                self._restore_manual_writer(journal, execution)
        if record["state"] == "configuration_pending":
            record["state"] = "preparation_aborted"
            record["preparation_aborted_at"] = int(self.clock())
            self._write_journal(journal)
        return record["id"]

    def _settle_prior_catalog_writer_jobs(
        self, journal: dict[str, Any], writer_search: str
    ) -> None:
        for job in journal.get("jobs", []):
            if (
                job.get("kind") != "saved_search"
                or job.get("label") != writer_search
                or job.get("state") in CATALOG_SETTLED_JOB_STATES
            ):
                continue
            if job.get("sid"):
                try:
                    self._read_job(journal, job)
                except Refused as exc:
                    if job.get("state") not in CATALOG_SETTLED_JOB_STATES:
                        raise Refused(
                            f"prior catalog writer job {job['sid']} could not be "
                            f"settled ({exc}); confirm its outcome in Splunk Job "
                            f"Manager/audit evidence and run `reconcile --sid "
                            f"{job['sid']}` (see 'Interrupted and failed operations' "
                            "in docs/CISCO_CONTRACT_MIGRATION.md) before resuming"
                        ) from exc
            elif job.get("state") == "configuration_pending":
                self._retire_undispatched_attempt(journal, job)
            else:
                raise Refused(
                    "catalog output changed while a prior catalog writer dispatch "
                    "has an unknown outcome and no recorded SID; find its SID in "
                    "Splunk Job Manager/audit evidence and run `reconcile --sid "
                    "<SID>` (see 'Interrupted and failed operations' in "
                    "docs/CISCO_CONTRACT_MIGRATION.md) before resuming"
                )

    def _dispatch_writer(
        self,
        journal: dict[str, Any],
        name: str,
        request_bounds: dict[str, str],
        *,
        label: str,
        intent_fingerprint: str | None = None,
        persist_result_rows: bool = False,
    ) -> list[dict[str, Any]] | None:
        """Dispatch one exact allowlisted saved-search slice with SID journaling.

        Rows are returned (and durably retained) only when the caller reads them
        back; otherwise a completed job keeps its count and result digest.
        """
        interface, _ = self._interface()
        writer = next(
            (
                item
                for item in interface["activation"]["writer_contracts"]
                if item.get("name") == name
            ),
            None,
        )
        if writer is None:
            raise Refused("writer is absent from the authoritative allowlist")
        self._recover_temporary_manual_writer(journal, name)
        entry = self._saved_search(name)
        content = self._normalize_saved_search_schedule(
            entry.get("content") or {}, writer["fields"]
        )
        for field, expected in writer["fields"].items():
            actual = content.get(field)
            if field == "disabled":
                if _strict_bool(actual) is True:
                    continue
                if _strict_bool(actual) is False and self._writer_enabled_by_journal(
                    journal, name
                ):
                    continue
                raise Refused("staged writer is enabled outside journaled cutover")
            if not _config_equal(field, actual, expected):
                raise Refused("staged writer changed after preparation")
        search = str(content.get("search", ""))
        bounds = {key: str(value) for key, value in request_bounds.items()}
        record = next(
            (
                item
                for item in reversed(journal.get("jobs", []))
                if item.get("kind") == "saved_search"
                and item.get("label") == name
                and item.get("request_bounds") == bounds
                and item.get("intent_fingerprint") == intent_fingerprint
            ),
            None,
        )
        retry_of = None
        if record is not None and record.get("state") in {
            "configuration_pending",
            "preparation_aborted",
            "rejected",
        }:
            retry_of = self._retire_undispatched_attempt(journal, record)
            record = None
        if record is not None and record.get("state") in {
            "dispatch_pending",
            "dispatch_unknown",
        }:
            execution = next(
                (
                    item
                    for item in reversed(journal.get("temporary_manual_executions", []))
                    if item.get("job_id") == record.get("id")
                    and item.get("state") != "restored"
                ),
                None,
            )
            if execution:
                self._restore_manual_writer(journal, execution)
            raise Uncertain(f"{label} preparation or dispatch requires reconciliation")
        if record is not None and record.get("state") == "complete":
            if persist_result_rows:
                return self._completed_job_rows(journal, record)
            return None
        if record is None:
            self._assert_origin_unchanged(journal)
            self._assert_no_competing_staged_jobs(journal)
            record = {
                "id": uuid.uuid4().hex,
                "kind": "saved_search",
                "retry_of": retry_of,
                "label": name,
                "state": "configuration_pending",
                "request_bounds": bounds,
                "search_fingerprint": fingerprint(search),
                "writer_contract_id": writer["id"],
                "writer_role": writer.get("role"),
                "intent_fingerprint": intent_fingerprint,
                "persist_result_rows": persist_result_rows,
                **self._evidence_class(journal),
                **(
                    {
                        "slice_start": request_bounds["index_earliest"],
                        "slice_end": request_bounds["index_latest"],
                    }
                    if "index_earliest" in request_bounds
                    and "index_latest" in request_bounds
                    else {}
                ),
            }
            self._save_job(journal, record)
            execution = self._temporary_manual_writer(journal, name, bounds, record)
            record["state"] = "dispatch_pending"
            self._write_journal(journal)
            try:
                try:
                    response = self._request(
                        "POST",
                        SEARCHES + quote(name, safe="") + "/dispatch",
                        {
                            **{
                                f"dispatch.{key}": value
                                for key, value in bounds.items()
                            },
                            "trigger_actions": "0",
                        },
                    )
                except Refused:
                    record["state"] = "rejected"
                    self._write_journal(journal)
                    raise
                except Exception:
                    record["state"] = "dispatch_unknown"
                    self._write_journal(journal)
                    raise Uncertain(
                        f"{label} outcome is unknown; reconcile by SID without retry"
                    ) from None
                sid = response.get("sid")
                if not isinstance(sid, str) or not sid:
                    record["state"] = "dispatch_unknown"
                    self._write_journal(journal)
                    raise Uncertain(f"{label} returned no SID; reconcile before retry")
                record.update(state="running", sid=sid)
                self._write_journal(journal)
                rows = self._read_job(journal, record)
                return rows if persist_result_rows else None
            finally:
                if execution is not None and execution.get("state") != "restored":
                    self._restore_manual_writer(journal, execution)
        rows = self._read_job(journal, record)
        return rows if persist_result_rows else None

    def _validate_migration_ingestion_window(
        self, journal, *, upper_bound: int | None = None
    ) -> dict[str, Any]:
        lower = 0
        upper = int(self.clock()) + 60 if upper_bound is None else upper_bound
        if upper < lower:
            raise Refused("staged ingestion watermark precedes the migration window")
        query = (
            f"search index={V2_INDEX} | where _indextime>={lower} AND _indextime<={upper} "
            "| fields source "
            + " ".join(
                sorted(set(V2_ROW_FIELDS["conversation"] + V2_ROW_FIELDS["traffic"]))
            )
        )
        rows = self._query(
            journal,
            query,
            None,
            None,
            label="complete staged ingestion window",
            earliest_time="0",
            latest_time=str(upper + 900),
            # This audit must observe the index again on every pass. Reusing
            # a completed search from the journal would hide later missing or
            # surplus physical copies.
            persist_result_rows=False,
        )
        expected: dict[tuple[str, str], dict[str, Any]] = self._preexisting_v2_map(
            journal
        )
        for slice_record in journal["slices"]:
            for stream, spec in STREAMS.items():
                for rollup_id, value in slice_record["streams"][stream][
                    "expected"
                ].items():
                    key = (spec["source"], rollup_id)
                    if key in expected:
                        prior = expected[key]
                        if prior.get("content_digest") != value.get("content_digest"):
                            raise Refused(
                                "source rollup ID conflicts across migration evidence"
                            )
                        prior = dict(prior)
                        prior["copies"] = int(prior.get("copies", 1)) + int(
                            value.get("copies", 1)
                        )
                        expected[key] = prior
                    else:
                        expected[key] = value
        # The first scheduler-owned cycle is part of the migration's write
        # window too. It is deliberately kept in its own journal section
        # because it was produced by the scheduler, not by our bounded
        # backfill dispatches.
        scheduled = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        for stream, spec in STREAMS.items():
            scheduled_state = scheduled.get(stream) or {}
            cycles = scheduled_state.get("cycles")
            if cycles is None and scheduled_state.get("expected") is not None:
                cycles = [{"expected": scheduled_state["expected"]}]
            for cycle in cycles or []:
                scheduled_expected = cycle.get("expected")
                if not isinstance(scheduled_expected, dict):
                    raise Refused(
                        "scheduled writer evidence is missing its expected manifest"
                    )
                for rollup_id, value in scheduled_expected.items():
                    key = (spec["source"], rollup_id)
                    if key in expected:
                        prior = expected[key]
                        if prior.get("content_digest") != value.get("content_digest"):
                            raise Refused(
                                "scheduled rollup ID conflicts with migration evidence"
                            )
                        prior = dict(prior)
                        prior["copies"] = int(prior.get("copies", 1)) + int(
                            value.get("copies", 1)
                        )
                        expected[key] = prior
                    else:
                        expected[key] = value
                if cycle.get("empty_summary_warning") is True and scheduled_expected:
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
        actual = {}
        for source in {str(row.get("source", "")) for row in rows}:
            stream = next(
                (name for name, spec in STREAMS.items() if spec["source"] == source),
                None,
            )
            if stream is None:
                raise Refused("staged ingestion window contains an unknown v2 source")
            source_rows = [row for row in rows if row.get("source") == source]
            for rollup_id, value in self._record_map(source_rows, stream).items():
                key = (source, rollup_id)
                actual[key] = value
        if actual != expected:
            raise Refused(
                "staged ingestion window contains missing or unexpected summary rollups"
            )
        empty_summary_proofs = []
        for stream, state in scheduled.items():
            for cycle in state.get("cycles", []):
                if cycle.get("empty_summary_warning") is not True:
                    continue
                if cycle.get("expected"):
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
                proof = cycle.get("empty_summary_proof")
                if not isinstance(proof, dict) or proof.get("retained_rows") != 0:
                    raise Refused(
                        "empty scheduled writer has no independent retained-index proof"
                    )
                if not cycle.get("expected"):
                    cycle["empty_summary_proof"] = {
                        **proof,
                        "expected_rows": 0,
                        "retained_rows": 0,
                        "audit_lower_indextime": lower,
                        "audit_upper_indextime": upper,
                        "global_actual_equals_expected": True,
                    }
                    empty_summary_proofs.append(
                        {
                            "stream": stream,
                            "sid": cycle.get("sid"),
                            **cycle["empty_summary_proof"],
                        }
                    )
        if empty_summary_proofs:
            self._write_journal(journal)
        return {
            "lower_indextime": lower,
            "upper_indextime": upper,
            "rows": len(actual),
            "empty_summary_proofs": empty_summary_proofs,
            "fingerprint": fingerprint(
                [
                    {
                        "source": source,
                        "rollup_id": rollup_id,
                        **value,
                    }
                    for (source, rollup_id), value in sorted(actual.items())
                ]
            ),
        }

    def _scheduled_output_watermark(self, journal) -> int:
        """Return the independent observation boundary used for full-window audit."""
        observed = _integer(
            (journal.get("cutover") or {}).get("schedule_observation_epoch")
        )
        if observed is None:
            raise Refused("scheduled output observation boundary is not journaled")
        return observed

    def _stage_stream(
        self,
        journal,
        slice_record,
        stream: str,
        *,
        observed_scheduled_expected: list[dict[str, Any]] | None = None,
    ) -> None:
        spec = STREAMS[stream]
        self._recover_temporary_manual_writer(journal, spec["saved_search"])
        self._assert_origin_unchanged(journal)
        stream_state = slice_record["streams"][stream]
        if stream_state.get("state") == "verified":
            return
        if stream_state.get("state") in {"dispatch_pending", "dispatch_unknown"}:
            raise Uncertain("an earlier dispatch requires SID reconciliation")
        start, end = slice_record["start"], slice_record["end"]
        if stream_state.get("state") == "backfill_done":
            expected = stream_state.get("expected")
            if not isinstance(expected, dict):
                raise Refused(
                    "reconciled writer is missing its expected output manifest"
                )
        else:
            query = (
                self._writer_query(spec, journal)
                + " | fields "
                + " ".join(V2_ROW_FIELDS[stream])
            )
            expected_rows = self._query(
                journal, query, start, end, label=f"{stream} expected output {start}"
            )
            expected = self._record_map(expected_rows, stream)
            baseline = self._preexisting_v2_map(journal)
            for rollup_id, row in expected.items():
                prior = baseline.get((spec["source"], rollup_id))
                if prior and prior.get("content_digest") != row.get("content_digest"):
                    raise Refused(
                        "source rollup ID conflicts with pre-existing summary material"
                    )
            stream_state.update(state="backfill_pending", expected=expected)
            self._write_journal(journal)
        matching_writer = next(
            (
                item
                for item in reversed(journal.get("jobs", []))
                if item.get("kind") == "saved_search"
                and item.get("stream") == stream
                and item.get("slice_start") == start
                and item.get("slice_end") == end
            ),
            None,
        )
        retry_of = None
        if matching_writer and matching_writer.get("state") in {
            "configuration_pending",
            "preparation_aborted",
            "rejected",
        }:
            retry_of = self._retire_undispatched_attempt(journal, matching_writer)
            matching_writer = None
        if matching_writer and matching_writer.get("state") in {
            "dispatch_pending",
            "dispatch_unknown",
        }:
            execution = next(
                (
                    item
                    for item in reversed(journal.get("temporary_manual_executions", []))
                    if item.get("job_id") == matching_writer.get("id")
                    and item.get("state") != "restored"
                ),
                None,
            )
            if execution:
                self._restore_manual_writer(journal, execution)
            raise Uncertain(
                "an earlier writer preparation or dispatch requires reconciliation"
            )
        if expected and stream_state.get("state") != "backfill_done":
            self._assert_origin_unchanged(journal)
            # Persist intent before the side-effecting dispatch. If the request
            # outcome is ambiguous, only a discovered SID can resume it.
            writer_job = matching_writer or {
                "id": uuid.uuid4().hex,
                "kind": "saved_search",
                "retry_of": retry_of,
                "label": spec["saved_search"],
                "state": "configuration_pending",
                "stream": stream,
                "slice_start": start,
                "slice_end": end,
                "persist_result_rows": False,
                **self._evidence_class(journal),
                "request_bounds": {
                    "earliest_time": str(journal["event_earliest"]),
                    "latest_time": str(journal["event_latest"]),
                    "index_earliest": str(start),
                    "index_latest": str(end),
                },
                "search_fingerprint": fingerprint(
                    str(self._saved_search(spec["saved_search"])["content"]["search"])
                ),
            }
            if matching_writer is None:
                self._save_job(journal, writer_job)
                execution = self._temporary_manual_writer(
                    journal,
                    spec["saved_search"],
                    writer_job["request_bounds"],
                    writer_job,
                )
                writer_job["state"] = "dispatch_pending"
                self._write_journal(journal)
                try:
                    try:
                        response = self._request(
                            "POST",
                            SEARCHES
                            + quote(spec["saved_search"], safe="")
                            + "/dispatch",
                            {
                                "dispatch.earliest_time": str(
                                    journal["event_earliest"]
                                ),
                                "dispatch.latest_time": str(journal["event_latest"]),
                                "dispatch.index_earliest": str(start),
                                "dispatch.index_latest": str(end),
                                "trigger_actions": "0",
                            },
                        )
                    except Refused:
                        writer_job["state"] = "rejected"
                        stream_state["state"] = "rejected"
                        self._write_journal(journal)
                        raise
                    except Exception:
                        writer_job["state"] = "dispatch_unknown"
                        stream_state["state"] = "dispatch_unknown"
                        self._write_journal(journal)
                        raise Uncertain(
                            "writer dispatch outcome is unknown; reconcile by SID"
                        ) from None
                    sid = response.get("sid")
                    if not isinstance(sid, str) or not sid:
                        writer_job["state"] = "dispatch_unknown"
                        stream_state["state"] = "dispatch_unknown"
                        self._write_journal(journal)
                        raise Uncertain(
                            "writer returned no SID; reconcile before continuing"
                        )
                    writer_job.update(state="running", sid=sid)
                    stream_state.update(state="running", sid=sid)
                    self._write_journal(journal)
                finally:
                    if execution is not None and execution.get("state") != "restored":
                        self._restore_manual_writer(journal, execution)
            elif matching_writer.get("state") == "running":
                writer_job = matching_writer
            # A complete record was fully validated when it was marked complete;
            # its Splunk artifact may have expired since.
            if writer_job.get("state") != "complete":
                self._read_job(journal, writer_job)
            stream_state["state"] = "backfill_done"
            self._write_journal(journal)
        self._assert_origin_unchanged(journal)
        cumulative = {}
        # The poll window intentionally spans the migration's complete
        # ingestion window. Include the immutable baseline and every verified
        # write intent whose output can be visible in that window.
        baseline = self._preexisting_v2_map(journal)
        for (source, rollup_id), value in baseline.items():
            if source == STREAMS[stream]["source"]:
                cumulative = _add_record_maps(
                    cumulative, {rollup_id: value}, label=f"{stream} staged baseline"
                )
        for prior_slice in journal["slices"]:
            if prior_slice["start"] > start:
                continue
            prior_manifest = prior_slice["streams"][stream].get("expected")
            if isinstance(prior_manifest, dict):
                cumulative = _add_record_maps(
                    cumulative, prior_manifest, label=f"{stream} staged slices"
                )
        scheduled = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        for cycle in (scheduled.get(stream) or {}).get("cycles", []):
            if cycle.get("state") == "verified" and isinstance(
                cycle.get("expected"), dict
            ):
                cumulative = _add_record_maps(
                    cumulative,
                    cycle["expected"],
                    label=f"{stream} staged scheduled intents",
                )
        for manifest in observed_scheduled_expected or []:
            cumulative = _add_record_maps(
                cumulative,
                manifest,
                label=f"{stream} staged observed scheduled intents",
            )
        actual = self._poll_persisted_rows(
            journal,
            cumulative,
            stream,
            label=f"{stream} staged records {start}",
        )
        if actual != cumulative:
            raise Refused(
                f"{stream} staged rollup IDs/event counts do not match source slice"
            )
        stream_state.update(
            state="verified",
            verified_at=int(self.clock()),
            rows=sum(value["copies"] for value in expected.values()),
            event_records=sum(
                value["records"] * value["copies"] for value in expected.values()
            ),
            expected_fingerprint=fingerprint(expected),
        )
        self._write_journal(journal)

    def backfill(self) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        self._assert_origin_unchanged(journal)
        for slice_record in journal["slices"]:
            for stream in STREAMS:
                self._stage_stream(journal, slice_record, stream)
            self._stage_history_slice(journal, slice_record)
        journal["phase"] = "backfilled"
        self._write_journal(journal)
        return {"status": "backfilled", "slices": len(journal["slices"])}

    @staticmethod
    def _history_stable_fields(contract: dict[str, Any]) -> list[str]:
        receipt_fields = {"received_time", "latest_received_time"}
        return [
            field
            for field in contract.get("expected_row_fields", [])
            if field not in receipt_fields
        ]

    def _history_expected(
        self,
        journal,
        contract,
        start,
        end,
        *,
        event_bounds: dict[str, str] | None = None,
    ):
        time_bounds = event_bounds or {
            "earliest_time": str(journal["event_earliest"]),
            "latest_time": str(journal["event_latest"]),
        }
        rows = self._query(
            journal,
            contract["expected_row_query"],
            start,
            end,
            label=f"network client history expected keys {start}",
            persist_result_rows=False,
            earliest_time=time_bounds["earliest_time"],
            latest_time=time_bounds["latest_time"],
        )
        allowed_status = set(contract["validation"].get("allowed_mapping_statuses", []))
        fields = self._history_stable_fields(contract)
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            key = str(row.get("_key", ""))
            status = str(row.get("mapping_status", ""))
            version = str(row.get("contract_version", ""))
            if (
                not ROLLUP_ID_RE.fullmatch(key)
                or version != str(contract["contract_version"])
                or status not in allowed_status
                or not row.get("source")
                or not row.get("source_authority")
                or not row.get("native_id")
                or not row.get("event_fingerprint")
            ):
                raise Refused(
                    "network client history source rows failed key/schema checks"
                )
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in fields
            }
            previous = grouped.get(key)
            if previous is None:
                received_min = _number(row.get("received_time"))
                received_max = _number(row.get("latest_received_time"))
                if received_max is None:
                    received_max = received_min
                grouped[key] = {
                    "stable": stable,
                    "received_min": received_min,
                    "received_max": received_max,
                    "fingerprint": fingerprint(stable),
                    "mapping_status": status,
                }
            else:
                if previous["stable"] != stable:
                    raise Refused(
                        "history replay key has conflicting normalized fields"
                    )
                receipt = _number(row.get("received_time"))
                latest = _number(row.get("latest_received_time"))
                if latest is None:
                    latest = receipt
                if receipt is not None:
                    previous["received_min"] = min(
                        receipt
                        if previous["received_min"] is None
                        else previous["received_min"],
                        receipt,
                    )
                if latest is not None:
                    previous["received_max"] = max(
                        latest
                        if previous["received_max"] is None
                        else previous["received_max"],
                        latest,
                    )
        return grouped

    def _history_baseline_snapshot(self, interface):
        contract = interface["staged_collections"]["network_client_history"]
        baseline = {}
        for row in self._collection_rows(contract["collection"]):
            key = str(row.get("_key", ""))
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in self._history_stable_fields(contract)
            }
            received = _number(row.get("received_time"))
            latest = _number(row.get("latest_received_time"))
            if latest is None:
                latest = received
            if not key or received is None or latest is None:
                raise Refused("preexisting network client history row is incomplete")
            key_hash = fingerprint(key)
            if key_hash in baseline:
                raise Refused("preexisting network client history has duplicate keys")
            baseline[key_hash] = {
                "stable_fingerprint": fingerprint(stable),
                "received_min": received,
                "received_max": latest,
            }
        return baseline

    @staticmethod
    def _history_receipt_manifest(expected):
        return {
            fingerprint(key): {
                "stable_fingerprint": value["fingerprint"],
                "received_min": value["received_min"],
                "received_max": value["received_max"],
            }
            for key, value in expected.items()
        }

    def _cumulative_history_expected(self, journal, contract, through_end):
        combined = {}
        auxiliary = (journal.get("cutover") or {}).get("history_bridge_slices", [])
        for item in [*journal["slices"], *auxiliary]:
            # A one-minute history-only bridge may intentionally be staged
            # just ahead of the current five-minute summary slice. Keep its
            # already-retained receipts in the cumulative equality check.
            if (
                item["end"] > through_end
                and item.get("history", {}).get("state") != "verified"
            ):
                continue
            receipts = item.get("history", {}).get("expected_receipts")
            if receipts is None:
                expected = self._history_expected(
                    journal, contract, item["start"], item["end"]
                )
                receipts = {
                    fingerprint(key): {
                        "stable_fingerprint": value["fingerprint"],
                        "received_min": value["received_min"],
                        "received_max": value["received_max"],
                    }
                    for key, value in expected.items()
                }
            for key_hash, value in receipts.items():
                previous = combined.get(key_hash)
                if previous is None:
                    combined[key_hash] = dict(value)
                    continue
                if previous["stable_fingerprint"] != value["stable_fingerprint"]:
                    raise Refused("history replay key conflicts across staged slices")
                for receipt_field, reducer in (
                    ("received_min", min),
                    ("received_max", max),
                ):
                    left, right = previous[receipt_field], value[receipt_field]
                    if left is None:
                        previous[receipt_field] = right
                    elif right is not None:
                        previous[receipt_field] = reducer(left, right)
        for cycle in (
            (journal.get("cutover") or {})
            .get("scheduled_history", {})
            .get("cycles", [])
        ):
            for key_hash, value in cycle.get("expected_receipts", {}).items():
                previous = combined.get(key_hash)
                if previous is None:
                    combined[key_hash] = dict(value)
                    continue
                if previous["stable_fingerprint"] != value["stable_fingerprint"]:
                    raise Refused("history key conflicts across scheduled windows")
                for receipt_field, reducer in (
                    ("received_min", min),
                    ("received_max", max),
                ):
                    left, right = previous[receipt_field], value[receipt_field]
                    if left is None:
                        previous[receipt_field] = right
                    elif right is not None:
                        previous[receipt_field] = reducer(left, right)
        return combined

    def _validate_history_rows(self, contract, expected, actual_rows, baseline=None):
        fields = set(contract["fields"])
        actual = {}
        actual_by_hash = {}
        for row in actual_rows:
            key = str(row.get("_key", ""))
            if key in actual:
                raise Refused("network client history collection has duplicate keys")
            # KV Store REST adds ownership metadata to outputlookup rows.
            # It is not a source field or part of the normalized history hash.
            if "_user" in row and not isinstance(row["_user"], str):
                raise Refused("network client history ownership metadata is malformed")
            if not (fields | {"_user"}).issuperset(row):
                raise Refused(
                    "network client history row has fields outside its contract"
                )
            actual[key] = row
            actual_by_hash[fingerprint(key)] = row
        baseline = baseline or {}
        expected_by_hash = {
            (key if "stable_fingerprint" in value else fingerprint(key)): value
            for key, value in expected.items()
        }
        for key_hash in set(expected_by_hash) & set(baseline):
            expected_row = expected_by_hash[key_hash]
            baseline_row = baseline[key_hash]
            stable_fp = expected_row.get("stable_fingerprint") or fingerprint(
                expected_row["stable"]
            )
            if stable_fp != baseline_row["stable_fingerprint"]:
                raise Refused("preexisting history key conflicts with source evidence")
            expected_row["received_min"] = min(
                expected_row["received_min"], baseline_row["received_min"]
            )
            expected_row["received_max"] = max(
                expected_row["received_max"], baseline_row["received_max"]
            )
        expected_hashes = set(expected_by_hash)
        if set(actual_by_hash) != expected_hashes | set(baseline):
            return None
        stable_fields = self._history_stable_fields(contract)
        for key_hash, expected_row in expected_by_hash.items():
            row = actual_by_hash[key_hash]
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in stable_fields
            }
            expected_stable_fingerprint = expected_row.get("stable_fingerprint")
            if expected_stable_fingerprint is not None:
                stable_matches = fingerprint(stable) == expected_stable_fingerprint
            else:
                stable_matches = stable == expected_row["stable"]
            if not stable_matches:
                raise Refused(
                    "network client history row differs from normalized source evidence"
                )
            got_min = _number(row.get("received_time"))
            got_max = _number(row.get("latest_received_time"))
            if (
                got_min is None
                or got_max is None
                or got_min != expected_row["received_min"]
                or got_max != expected_row["received_max"]
            ):
                raise Refused("network client history receipt merge is incomplete")
        for key_hash, expected_row in baseline.items():
            row = actual_by_hash[key_hash]
            stable = {
                field: self._normalize_history_field(field, row.get(field))
                for field in stable_fields
            }
            if fingerprint(stable) != expected_row["stable_fingerprint"]:
                raise Refused("preexisting network client history row was changed")
            # A source replay may legitimately extend a preexisting receipt
            # range. The cumulative source expectation above validates the
            # exact merged extrema in that case.
            if key_hash in expected_hashes:
                continue
            if (
                _number(row.get("received_time")) != expected_row["received_min"]
                or _number(row.get("latest_received_time"))
                != expected_row["received_max"]
            ):
                raise Refused("preexisting network client history receipt changed")
        return actual

    @staticmethod
    def _normalize_history_field(field: str, value: Any) -> Any:
        if value is None:
            return None
        if field in {"contract_version", "source_time", "collected_time"}:
            number = _number(value)
            if number is not None:
                return number
        if isinstance(value, (dict, list)):
            return canonical(value).decode("utf-8")
        return str(value)

    def _stage_history_slice(self, journal, slice_record):
        self._assert_origin_unchanged(journal)
        state = slice_record["history"]
        if state.get("state") == "verified":
            return
        if state.get("state") in {"dispatch_pending", "dispatch_unknown"}:
            raise Uncertain(
                "network client history dispatch requires SID reconciliation"
            )
        interface, _ = self._interface()
        contract = interface["staged_collections"]["network_client_history"]
        if "history_baseline" not in journal:
            journal["history_baseline"] = self._history_baseline_snapshot(interface)
            self._write_journal(journal)
        start, end = slice_record["start"], slice_record["end"]
        request_bounds = state.get("request_bounds")
        if request_bounds is None:
            request_bounds = {
                "earliest_time": str(journal["event_earliest"]),
                "latest_time": str(journal["event_latest"]),
                "index_earliest": str(start),
                "index_latest": str(end),
            }
        elif request_bounds != {
            "earliest_time": str(request_bounds.get("earliest_time", "")),
            "latest_time": str(request_bounds.get("latest_time", "")),
            "index_earliest": str(start),
            "index_latest": str(end),
        }:
            raise Refused("history slice request bounds changed on resume")
        event_bounds = {
            "earliest_time": request_bounds["earliest_time"],
            "latest_time": request_bounds["latest_time"],
        }
        expected = self._history_expected(
            journal, contract, start, end, event_bounds=event_bounds
        )
        expected_fingerprint = fingerprint(
            {key: value["fingerprint"] for key, value in expected.items()}
        )
        if (
            state.get("expected_fingerprint") is not None
            and state.get("expected_fingerprint") != expected_fingerprint
        ):
            raise Refused("history slice source changed after its durable expectation")
        intent_fingerprint = fingerprint(
            {
                "migration_id": journal["migration_id"],
                "slice": [start, end],
                "request_bounds": request_bounds,
                "expected": expected_fingerprint,
            }
        )
        if (
            state.get("intent_fingerprint") is not None
            and state.get("intent_fingerprint") != intent_fingerprint
        ):
            raise Refused("history slice writer intent changed on resume")
        state["expected_receipts"] = {
            fingerprint(key): {
                "stable_fingerprint": value["fingerprint"],
                "received_min": value["received_min"],
                "received_max": value["received_max"],
            }
            for key, value in expected.items()
        }
        self._write_journal(journal)
        cumulative = self._cumulative_history_expected(journal, contract, end)
        state.update(
            state="expected",
            request_bounds=request_bounds,
            intent_fingerprint=intent_fingerprint,
            expected_keys=sorted(expected),
            expected_fingerprint=expected_fingerprint,
        )
        self._write_journal(journal)
        if expected:
            self._dispatch_writer(
                journal,
                contract["builder_search"],
                request_bounds,
                label=f"network client history slice {start}",
                intent_fingerprint=intent_fingerprint,
            )
        for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
            self._assert_origin_unchanged(journal)
            actual_rows = self._collection_rows(contract["collection"])
            actual = self._validate_history_rows(
                contract, cumulative, actual_rows, journal["history_baseline"]
            )
            if actual is not None:
                state.update(
                    state="verified",
                    verified_at=int(self.clock()),
                    row_count=len(expected),
                    actual_fingerprint=fingerprint(
                        {
                            key: fingerprint(
                                {
                                    field: actual[key].get(field)
                                    for field in self._history_stable_fields(contract)
                                }
                            )
                            for key in sorted(expected)
                        }
                    ),
                )
                self._write_journal(journal)
                return
            self._wait_before_summary_retry(attempt)
        raise Refused(
            "network client history rows did not become visible in the collection"
        )

    def _stage_catalog(self, journal):
        """Build and verify the separate V2 catalog before any public switch."""
        self._assert_origin_unchanged(journal)
        interface, _ = self._interface()
        contract = interface["staged_collections"]["application_catalog_v2"]
        bounds = contract.get("dispatch_bounds")
        if (
            not isinstance(bounds, dict)
            or bounds.get("earliest_time") != "-1h@h"
            or bounds.get("latest_time") != "@h"
        ):
            raise Refused("catalog dispatch bounds are not the shipped bounded window")
        state = journal.setdefault("catalog", {})
        input_fingerprint = fingerprint(
            {
                "slices": [
                    {
                        "start": item["start"],
                        "end": item["end"],
                        "streams": {
                            stream: item["streams"][stream].get("expected_fingerprint")
                            or fingerprint(item["streams"][stream].get("expected", {}))
                            for stream in STREAMS
                        },
                    }
                    for item in journal["slices"]
                ],
                "scheduled_cycles": {
                    stream: [
                        {
                            "index_bounds": cycle["index_bounds"],
                            "expected_fingerprint": cycle["expected_fingerprint"],
                        }
                        for cycle in stream_state.get("cycles", [])
                    ]
                    for stream, stream_state in (
                        (journal.get("cutover") or {}).get("scheduled_streams") or {}
                    ).items()
                },
            }
        )
        same_generation = state.get("input_fingerprint") == input_fingerprint
        prior_bounds = state.get("dispatch_bounds") if same_generation else None
        if isinstance(prior_bounds, dict) and all(
            _integer(prior_bounds.get(key)) is not None
            for key in ("earliest_time", "latest_time")
        ):
            event_earliest = str(_integer(prior_bounds["earliest_time"]))
            event_latest = str(_integer(prior_bounds["latest_time"]))
        else:
            window_end = int(self.clock()) // 3600 * 3600
            event_earliest = str(window_end - 3600)
            event_latest = str(window_end)
        status_rows = self._query(
            journal,
            contract["status_query"],
            None,
            None,
            label="v2 catalog status and expected rows",
            earliest_time=event_earliest,
            latest_time=event_latest,
            persist_result_rows=False,
        )
        status = [row for row in status_rows if row.get("adm_kind") == "status"]
        results = [row for row in status_rows if row.get("adm_kind") == "result"]
        if (
            len(status) != 1
            or _integer(status[0].get("adm_catalog_invalid")) != 0
            or any(
                row.get("adm_kind") not in {"status", "result"} for row in status_rows
            )
        ):
            raise Refused("v2 catalog build status is missing, invalid, or ambiguous")
        fields = contract["fields"]
        empty_key = contract["validation"].get("empty_snapshot_key")
        stable_fields = [field for field in fields if field != "updated"]

        numeric_fields = {
            "pods",
            "first_seen",
            "last_seen",
            "peers",
            "conversations_1h",
            "blocked_1h",
            "unknown_peers_1h",
            "window_start",
            "window_end",
        }
        count_fields = {
            "pods",
            "peers",
            "conversations_1h",
            "blocked_1h",
            "unknown_peers_1h",
        }

        def stable(rows):
            normalized = {}
            for key, value in rows.items():
                item = {}
                for field in stable_fields:
                    raw = value.get(field)
                    if field in numeric_fields and not (
                        key == empty_key and raw is None
                    ):
                        if isinstance(raw, bool) or not isinstance(
                            raw, (str, int, float)
                        ):
                            raise Refused("catalog numeric field is malformed")
                        try:
                            number = Decimal(str(raw))
                        except InvalidOperation:
                            raise Refused(
                                "catalog numeric field is malformed"
                            ) from None
                        if (
                            not number.is_finite()
                            or number < 0
                            or abs(number.as_tuple().exponent) > 128
                            or number.adjusted() > 128
                            or (
                                field in count_fields
                                and number != number.to_integral_value()
                            )
                        ):
                            raise Refused("catalog numeric field is malformed")
                        # Exact decimal comparison avoids rounding large counters.
                        raw = format(number, "f")
                        if "." in raw:
                            raw = raw.rstrip("0").rstrip(".")
                        if number == 0:
                            raw = "0"
                    item[field] = raw
                normalized[key] = item
            return normalized

        expected = {}
        for row in results:
            key = str(row.get("_key", ""))
            if not key or key in expected or any(field not in row for field in fields):
                raise Refused("v2 catalog builder returned invalid or duplicate rows")
            expected[key] = {field: row.get(field) for field in fields}
        expected_stable_fingerprint = fingerprint(stable(expected))
        legacy_expected_fingerprint = fingerprint(
            {
                key: {field: value.get(field) for field in stable_fields}
                for key, value in expected.items()
            }
        )
        prior_fingerprint = state.get("expected_fingerprint")
        if same_generation and prior_fingerprint not in (
            None,
            expected_stable_fingerprint,
            legacy_expected_fingerprint,
        ):
            # The catalog is a rewritable derived collection built from live
            # workload and identity state, so unchanged staged input with a new
            # output is a new build. Refuse only while the prior generation's
            # writer could still be running or its outcome is unknown; a job
            # with a recorded SID is settled here by reading it to completion.
            self._settle_prior_catalog_writer_jobs(journal, contract["writer_search"])
            state.setdefault("superseded_generations", []).append(
                {
                    "build_generation": state.get("build_generation"),
                    "expected_fingerprint": prior_fingerprint,
                }
            )
            same_generation = False
        if (
            same_generation
            and prior_fingerprint == legacy_expected_fingerprint
            and prior_fingerprint != expected_stable_fingerprint
        ):
            state["legacy_expected_fingerprint"] = prior_fingerprint
        state["numeric_canonicalizer"] = "exact-decimal-v1"
        skip_dispatch = same_generation and state.get("state") == "verified"
        build_generation = int(state.get("build_generation", 0)) + (
            0 if same_generation else 1
        )
        state.update(
            state="expected",
            input_fingerprint=input_fingerprint,
            build_generation=build_generation,
            expected_keys=sorted(expected),
            expected_fingerprint=expected_stable_fingerprint,
            status_fingerprint=fingerprint(status[0]),
            dispatch_bounds={
                "earliest_time": event_earliest,
                "latest_time": event_latest,
            },
        )
        self._write_journal(journal)

        if not skip_dispatch:
            self._dispatch_writer(
                journal,
                contract["writer_search"],
                {"earliest_time": event_earliest, "latest_time": event_latest},
                label=f"v2 application catalog generation {state['build_generation']}",
                intent_fingerprint=fingerprint(
                    {
                        "build_generation": build_generation,
                        "input_fingerprint": input_fingerprint,
                    }
                ),
            )
        read_rows = self._query(
            journal,
            contract["read_query"],
            None,
            None,
            label="v2 catalog complete readback query",
            earliest_time=event_earliest,
            latest_time=event_latest,
            persist_result_rows=False,
        )
        actual = {}
        for row in read_rows:
            key = str(row.get("_key", ""))
            is_empty_marker = key == empty_key
            if (
                not key
                or key in actual
                or (not is_empty_marker and any(field not in row for field in fields))
            ):
                raise Refused(
                    "v2 catalog read query has missing fields or duplicate keys"
                )
            actual[key] = {field: row.get(field) for field in fields}
        collection_rows = self._collection_rows(contract["collection"])
        collection = {}
        for row in collection_rows:
            key = str(row.get("_key", ""))
            is_empty_marker = key == empty_key
            if (
                not key
                or key in collection
                or (not is_empty_marker and any(field not in row for field in fields))
            ):
                raise Refused(
                    "v2 catalog collection has missing fields or duplicate keys"
                )
            collection[key] = {field: row.get(field) for field in fields}
        if stable(actual) != stable(collection):
            raise Refused("v2 catalog REST and complete query reads disagree")
        expected_collection_keys = {empty_key} if not expected else set(expected)
        if set(collection) != expected_collection_keys:
            raise Refused("v2 catalog collection contains missing or stale keys")
        if any(
            stable({key: collection.get(key, {})}).get(key)
            != stable({key: value}).get(key)
            for key, value in expected.items()
        ):
            raise Refused("v2 catalog collection does not contain every computed row")
        if not expected:
            marker = collection.get(empty_key, {})
            if (
                set(collection) != {empty_key}
                or _number(marker.get("updated")) is None
                or _number(marker.get("updated")) <= 0
            ):
                raise Refused(
                    "complete empty v2 catalog did not write its sole reserved marker"
                )
        elif empty_key in collection:
            raise Refused("non-empty v2 catalog contains the reserved empty marker")
        for row in collection.values():
            if _number(row.get("updated")) is None or _number(row.get("updated")) <= 0:
                raise Refused("v2 catalog row has no valid update timestamp")
        state.update(
            state="verified",
            verified_at=int(self.clock()),
            rows=len(expected),
            collection_rows=len(collection),
            actual_fingerprint=fingerprint(stable(actual)),
            complete_paged_read=True,
        )
        self._write_journal(journal)

    def _validate_history_coverage(self, journal, interface) -> dict[str, Any]:
        """Re-read source history and the full KV collection before cutover."""
        contract = interface["staged_collections"]["network_client_history"]
        expected_by_slice = {}
        combined = {}
        all_history_slices = [
            *journal["slices"],
            *((journal.get("cutover") or {}).get("history_bridge_slices") or []),
        ]
        for item in all_history_slices:
            start, end = item["start"], item["end"]
            history_state = item.get("history") or {}
            request_bounds = history_state.get("request_bounds")
            if request_bounds is None:
                request_bounds = {
                    "earliest_time": str(journal["event_earliest"]),
                    "latest_time": str(journal["event_latest"]),
                    "index_earliest": str(start),
                    "index_latest": str(end),
                }
            if (
                not isinstance(request_bounds, dict)
                or str(request_bounds.get("index_earliest")) != str(start)
                or str(request_bounds.get("index_latest")) != str(end)
                or not request_bounds.get("earliest_time")
                or not request_bounds.get("latest_time")
            ):
                raise Refused("history slice has invalid pinned source request bounds")
            event_bounds = {
                "earliest_time": str(request_bounds["earliest_time"]),
                "latest_time": str(request_bounds["latest_time"]),
            }
            expected = self._history_expected(
                journal, contract, start, end, event_bounds=event_bounds
            )
            for key, value in expected.items():
                previous = combined.get(key)
                if previous is None:
                    combined[key] = dict(value)
                else:
                    if previous["stable"] != value["stable"]:
                        raise Refused(
                            "history replay key conflicts across staged slices"
                        )
                    for receipt_field, reducer in (
                        ("received_min", min),
                        ("received_max", max),
                    ):
                        left, right = previous[receipt_field], value[receipt_field]
                        if left is None:
                            previous[receipt_field] = right
                        elif right is not None:
                            previous[receipt_field] = reducer(left, right)
            expected_by_slice[id(item)] = expected
        scheduled_history = (journal.get("cutover") or {}).get("scheduled_history", {})
        for cycle in scheduled_history.get("cycles", []):
            bounds = cycle.get("index_bounds") or []
            if len(bounds) != 2:
                raise Refused("scheduled history evidence has invalid index bounds")
            expected = self._history_expected(
                journal,
                contract,
                int(bounds[0]),
                int(bounds[1]),
                event_bounds=cycle["event_bounds"],
            )
            if fingerprint(expected) != cycle.get("expected_fingerprint"):
                raise Refused("scheduled history source changed after its audit")
            for key, value in expected.items():
                previous = combined.get(key)
                if previous is None:
                    combined[key] = dict(value)
                    continue
                if previous["stable"] != value["stable"]:
                    raise Refused(
                        "history replay key conflicts across scheduled windows"
                    )
                for receipt_field, reducer in (
                    ("received_min", min),
                    ("received_max", max),
                ):
                    left, right = previous[receipt_field], value[receipt_field]
                    if left is None:
                        previous[receipt_field] = right
                    elif right is not None:
                        previous[receipt_field] = reducer(left, right)
            cycle["final_validated_at"] = int(self.clock())
            cycle["final_rows"] = len(expected)
        if (
            scheduled_history.get("cycles")
            and _integer(scheduled_history.get("observation_epoch")) is None
        ):
            raise Refused("scheduled history audit boundary is not journaled")
        rows = self._collection_rows(contract["collection"])
        if "history_baseline" not in journal:
            raise Refused("immutable pre-migration history baseline is missing")
        actual = None
        for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
            actual = self._validate_history_rows(
                contract, combined, rows, journal["history_baseline"]
            )
            if actual is not None:
                break
            if attempt < SUMMARY_INDEX_WAIT_ATTEMPTS:
                self._wait_before_summary_retry(attempt)
                rows = self._collection_rows(contract["collection"])
        if actual is None:
            raise Refused(
                "final history collection has missing or unexpected source keys"
            )
        for item in all_history_slices:
            if id(item) not in expected_by_slice:
                continue
            expected = expected_by_slice[id(item)]
            stable_expected = {
                key: value["fingerprint"] for key, value in sorted(expected.items())
            }
            stable_actual = {
                key: fingerprint(
                    {
                        field: self._normalize_history_field(
                            field, actual[key].get(field)
                        )
                        for field in self._history_stable_fields(contract)
                    }
                )
                for key in sorted(expected)
            }
            if stable_actual != stable_expected:
                raise Refused(
                    "final history rows differ from their staged source evidence"
                )
            item["history"]["final_validation"] = {
                "validated_at": int(self.clock()),
                "rows": len(expected),
                "fingerprint": fingerprint(stable_actual),
            }
            item["history"]["actual_fingerprint"] = fingerprint(stable_actual)
        self._write_journal(journal)
        return {
            "keys": len(combined),
            "fingerprint": fingerprint(
                {key: value["fingerprint"] for key, value in sorted(combined.items())}
            ),
            "validated_at": int(self.clock()),
        }

    def validate(self, scenario: dict[str, Any] | None = None) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        interface, interface_hash = self._interface()
        self._assert_origin_unchanged(journal)
        incomplete = [
            (slice_record["start"], stream)
            for slice_record in journal["slices"]
            for stream, state in [
                *slice_record["streams"].items(),
                ("network_client_history", slice_record["history"]),
            ]
            if state.get("state") != "verified"
        ]
        if incomplete:
            raise Refused(
                "every conversation and traffic slice must validate before cutover"
            )
        validation_id = uuid.uuid4().hex
        self._verify_preexisting_index(journal, final_pass=True)
        for stream, spec in STREAMS.items():
            expected_all = {}
            for (source, rollup_id), value in self._preexisting_v2_map(journal).items():
                if source == spec["source"]:
                    expected_all = _add_record_maps(
                        expected_all,
                        {rollup_id: value},
                        label=f"final {stream} baseline",
                    )
            for slice_record in journal["slices"]:
                self._assert_origin_unchanged(journal)
                start, end = slice_record["start"], slice_record["end"]
                query = (
                    self._writer_query(spec, journal)
                    + " | fields "
                    + " ".join(V2_ROW_FIELDS[stream])
                )
                expected_rows = self._query(
                    journal,
                    query,
                    start,
                    end,
                    label=f"final {stream} expected output {start} {validation_id}",
                )
                expected = self._record_map(expected_rows, stream)
                expected_all = _add_record_maps(
                    expected_all, expected, label=f"final {stream} source slices"
                )
            scheduled_state = (
                (journal.get("cutover") or {}).get("scheduled_streams") or {}
            ).get(stream) or {}
            for cycle in scheduled_state.get("cycles", []):
                if cycle.get("state") == "verified":
                    expected_all = _add_record_maps(
                        expected_all,
                        cycle.get("expected") or {},
                        label=f"final {stream} scheduled cycles",
                    )
            self._assert_origin_unchanged(journal)
            actual = self._poll_persisted_rows(
                journal,
                expected_all,
                stream,
                label=f"final {stream} staged records {validation_id}",
            )
            if expected_all != actual:
                raise Refused(
                    f"final {stream} staged coverage does not match source data"
                )
            for slice_record in journal["slices"]:
                slice_record["streams"][stream]["final_validation"] = {
                    "expected_fingerprint": fingerprint(expected_all),
                    "actual_fingerprint": fingerprint(actual),
                    "validated_at": int(self.clock()),
                }
        history_final = self._validate_history_coverage(journal, interface)
        scheduled_cycles = (journal.get("cutover") or {}).get("scheduled_streams") or {}
        audit_upper = (
            self._scheduled_output_watermark(journal)
            if any(state.get("cycles") for state in scheduled_cycles.values())
            else None
        )
        journal["staged_ingestion_window"] = self._validate_migration_ingestion_window(
            journal, upper_bound=audit_upper
        )
        self._stage_catalog(journal)
        journal = self._load()
        journal["coverage"] = {
            stream: {
                "slices": len(journal["slices"]),
                "rows": sum(
                    item["streams"][stream].get("rows", 0) for item in journal["slices"]
                ),
                "event_records": sum(
                    item["streams"][stream].get("event_records", 0)
                    for item in journal["slices"]
                ),
                "from_index_time": journal["range"]["start"],
                "through_index_time": journal["range"]["end"],
            }
            for stream in STREAMS
        }
        journal["coverage"]["network_client_history"] = {
            "slices": len(journal["slices"]),
            "rows": sum(
                item["history"].get("row_count", 0) for item in journal["slices"]
            ),
            "fingerprint": fingerprint(
                [
                    item["history"].get("actual_fingerprint")
                    for item in journal["slices"]
                ]
            ),
            "final_validation": history_final,
        }
        journal["coverage"]["application_catalog_v2"] = {
            "rows": journal["catalog"].get("rows", 0),
            "collection_rows": journal["catalog"].get("collection_rows", 0),
            "fingerprint": journal["catalog"].get("actual_fingerprint"),
        }
        surfaces = []
        public_surface_error = None
        if scenario is not None:
            schema = interface.get("scenario_schema") or {}
            required_scenario = schema.get("required_fields")
            if not isinstance(required_scenario, list) or set(required_scenario) != set(
                scenario
            ):
                raise Refused(
                    "validation scenario fields do not match the authoritative schema"
                )
            surfaces = self._public_surface_evidence(journal, interface, scenario)
        else:
            public_surface_error = (
                "deployment-specific validation scenario was not supplied"
            )
        candidate = {
            "schema": 1,
            "migration_id": journal["migration_id"],
            "interface_sha256": interface_hash,
            "origin_fingerprint": journal["origin_fingerprint"],
            "coverage": journal["coverage"],
            "history": journal["coverage"]["network_client_history"],
            "catalog": journal["coverage"]["application_catalog_v2"],
            "slice_fingerprints": [
                {
                    "start": item["start"],
                    "end": item["end"],
                    "streams": {
                        name: item["streams"][name]["final_validation"]
                        for name in STREAMS
                    },
                }
                for item in journal["slices"]
            ],
            "scenario_sha256": fingerprint(scenario) if scenario is not None else None,
            "scenario": scenario,
            "public_surfaces": surfaces,
            "cutover_eligible": bool(surfaces) and scenario is not None,
            "reason": public_surface_error,
        }
        if len(canonical(candidate)) > MAX_CANDIDATE_BYTES:
            raise Refused(
                "validated candidate evidence exceeds its bound; validate a shorter range"
            )
        candidate_path = self.journal.path.with_suffix(".candidate.json")
        candidate_hash = self.journal.write_artifact(candidate_path, candidate)
        if journal.get("phase") != "cutover_in_progress":
            journal["phase"] = "coverage_validated"
        journal["candidate_sha256"] = candidate_hash
        journal["candidate_cutover_eligible"] = candidate["cutover_eligible"]
        self._write_journal(journal)
        return {
            "status": "coverage_validated",
            "coverage": journal["coverage"],
            "candidate_sha256": candidate_hash,
            "cutover_eligible": candidate["cutover_eligible"],
        }

    def _mutation_target(self, mutation: dict[str, Any]) -> dict[str, Any]:
        entry = self._single_entry(mutation["rest_target"])
        content = entry.get("content") or {}
        if mutation["field"] not in content:
            raise Refused("cutover target field is unavailable")
        return {
            "value": content[mutation["field"]],
            "args": content.get("args", ""),
            "acl": entry.get("acl") or {},
        }

    @staticmethod
    def _macro_args_parts(name: str, value: Any) -> tuple[str, ...]:
        if isinstance(value, str):
            parts = tuple(part.strip() for part in value.split(",")) if value else ()
        elif isinstance(value, list) and all(isinstance(part, str) for part in value):
            parts = tuple(part.strip() for part in value)
        else:
            raise Refused("parameterized macro args have an unsupported REST type")
        if any(not part or "," in part for part in parts):
            raise Refused("parameterized macro args contain an invalid argument")
        match = re.search(r"\((\d+)\)$", name)
        expected_count = int(match.group(1)) if match else 0
        if len(parts) != expected_count:
            raise Refused("parameterized macro args do not match the macro arity")
        return parts

    @classmethod
    def _macro_args_equal(cls, name: str, actual: Any, expected: Any) -> bool:
        return cls._macro_args_parts(name, actual) == cls._macro_args_parts(
            name, expected
        )

    @classmethod
    def _macro_args_payload(cls, name: str, value: Any) -> str:
        parts = cls._macro_args_parts(name, value)
        return ", ".join(parts) if isinstance(value, list) else value

    @staticmethod
    def _mutation_equal(mutation: dict[str, Any], actual: Any, expected: Any) -> bool:
        if mutation["kind"] == "saved_search":
            return _config_equal(mutation["field"], actual, expected)
        if mutation["kind"] == "macro_definition":
            return _macro_definition_equal(actual, expected)
        return actual == expected

    def _assert_cutover_origin_compatible(self, journal: dict[str, Any]) -> None:
        for execution in reversed(journal.get("temporary_manual_executions", [])):
            if execution.get("state") != "restored":
                self._recover_temporary_manual_writer(journal, execution["name"])
        plan = journal.get("cutover", {}).get("mutations", [])
        for mutation in plan:
            actual = self._mutation_target(mutation)
            if actual["acl"] != mutation["acl"]:
                raise Refused("cutover target ACL drifted from the journaled snapshot")
            if mutation["kind"] == "macro_definition" and not self._macro_args_equal(
                mutation["name"], actual["args"], mutation.get("args", "")
            ):
                raise Refused("parameterized macro arguments drifted from the journal")
            if not any(
                self._mutation_equal(mutation, actual["value"], expected)
                for expected in (mutation["before"], mutation["after"])
            ):
                raise Refused("cutover target drifted from both journaled states")
        current_snapshot = self.snapshot(allow_activation=True)
        origin = journal.get("origin") or {}
        # Normalize only the allowlisted fields that this journal may mutate;
        # all other effective configuration, ACL and mapping inputs must
        # continue to match the original fingerprint.
        for name, macro in current_snapshot["macros"].items():
            origin_macro = origin["macros"][name]
            if not self._macro_args_equal(
                name, macro["args"], origin_macro.get("args", "")
            ):
                raise Refused(
                    "parameterized macro arguments drifted from the origin snapshot"
                )
            # REST clients may expose repeated args as a list or as one string.
            # Retain the immutable origin representation for fingerprinting.
            macro["args"] = origin_macro.get("args", "")
        for mutation in plan:
            if mutation["kind"] == "macro_definition":
                current_snapshot["macros"][mutation["name"]]["definition"] = origin[
                    "macros"
                ][mutation["name"]]["definition"]
            else:
                current_snapshot["saved_searches"][mutation["name"]]["content"][
                    mutation["field"]
                ] = origin["saved_searches"][mutation["name"]]["content"][
                    mutation["field"]
                ]
        if fingerprint(current_snapshot) != journal.get("origin_fingerprint"):
            raise Refused("non-selector configuration, ACL, profile, or target drifted")

    def _apply_mutation(
        self, journal: dict[str, Any], mutation: dict[str, Any]
    ) -> None:
        actual = self._mutation_target(mutation)
        if actual["acl"] != mutation["acl"]:
            raise Refused(
                "cutover target ACL changed; refusing to write grants or overwrite ACLs"
            )
        value = actual["value"]
        if mutation["kind"] == "macro_definition" and not self._macro_args_equal(
            mutation["name"], actual["args"], mutation.get("args", "")
        ):
            raise Refused("parameterized macro arguments drifted from the journal")
        if mutation.get("state") == "request_unknown" and self._mutation_equal(
            mutation, value, mutation["before"]
        ):
            raise Uncertain(
                "configuration update remains ambiguous; inspect target and reconcile manually"
            )
        if self._mutation_equal(mutation, value, mutation["after"]):
            mutation["state"] = "applied"
            if _integer(mutation.get("verified_at")) is None:
                mutation["verified_at"] = int(self.clock())
            else:
                mutation["revalidated_at"] = int(self.clock())
            self._write_journal(journal)
            return
        if not self._mutation_equal(mutation, value, mutation["before"]):
            raise Refused("cutover target value changed outside this journal")
        mutation["state"] = "request_pending"
        mutation["request_started_at"] = int(self.clock())
        self._write_journal(journal)
        try:
            payload = {mutation["field"]: mutation["after"]}
            if mutation["kind"] == "macro_definition":
                payload["args"] = self._macro_args_payload(
                    mutation["name"], mutation.get("args", "")
                )
            self._request(
                "POST",
                mutation["rest_target"],
                payload,
            )
        except Refused:
            observed = self._mutation_target(mutation)
            args_match = mutation[
                "kind"
            ] != "macro_definition" or self._macro_args_equal(
                mutation["name"], observed["args"], mutation.get("args", "")
            )
            if (
                observed["acl"] != mutation["acl"]
                or not args_match
                or not self._mutation_equal(
                    mutation, observed["value"], mutation["after"]
                )
            ):
                mutation["state"] = "rejected"
                self._write_journal(journal)
                raise
        except MigrationError:
            observed = self._mutation_target(mutation)
            args_match = mutation[
                "kind"
            ] != "macro_definition" or self._macro_args_equal(
                mutation["name"], observed["args"], mutation.get("args", "")
            )
            if (
                observed["acl"] == mutation["acl"]
                and args_match
                and self._mutation_equal(mutation, observed["value"], mutation["after"])
            ):
                pass
            elif args_match and self._mutation_equal(
                mutation, observed["value"], mutation["before"]
            ):
                mutation["state"] = "request_unknown"
                self._write_journal(journal)
                raise Uncertain(
                    "configuration update outcome is unknown; readback shows the prior value"
                ) from None
            else:
                raise Refused(
                    "configuration update left an unrecognized value"
                ) from None
        observed = self._mutation_target(mutation)
        if observed["acl"] != mutation["acl"]:
            raise Refused(
                "configuration update changed ACLs; refusing further migration writes"
            )
        if mutation["kind"] == "macro_definition" and not self._macro_args_equal(
            mutation["name"], observed["args"], mutation.get("args", "")
        ):
            raise Refused("configuration update changed parameterized macro arguments")
        if not self._mutation_equal(mutation, observed["value"], mutation["after"]):
            mutation["state"] = "readback_failed"
            self._write_journal(journal)
            raise Refused("configuration update did not match its journaled target")
        mutation["state"] = "applied"
        if _integer(mutation.get("verified_at")) is None:
            mutation["verified_at"] = int(self.clock())
        else:
            mutation["revalidated_at"] = int(self.clock())
        self._write_journal(journal)

    def _build_cutover_mutations(
        self, journal: dict[str, Any], interface: dict[str, Any]
    ) -> list[dict[str, Any]]:
        origin = journal["origin"]
        mutations = []
        selectors = interface["activation"]["cutover_selectors"]
        # Pause the legacy writer first. Drain is a separate gate before any V2
        # schedule or public reader is activated.
        writer_contracts = interface["activation"]["writer_contracts"]
        legacy = next(
            item
            for item in writer_contracts
            if item["name"] == "ADM - Conversation rollup"
        )
        for writer in [legacy] + [
            item for item in writer_contracts if item is not legacy
        ]:
            name = writer["name"]
            transition = writer["state_transition"]
            before = origin["saved_searches"][name]["content"].get("disabled")
            if before is None:
                raise Refused(
                    "writer disabled state is missing from the origin snapshot"
                )
            after = transition.get("disabled_after")
            if name == legacy["name"]:
                after = 1
            elif _config_equal("disabled", before, after):
                continue
            mutations.append(
                {
                    "id": writer["id"] + ":disabled",
                    "kind": "saved_search",
                    "name": name,
                    "rest_target": writer["rest_target"],
                    "field": "disabled",
                    "before": before,
                    "after": after,
                    "acl": origin["saved_searches"][name]["acl"],
                    "state": "pending",
                }
            )
            if name == legacy["name"]:
                mutations[-1]["drain_after"] = True
        selector_order = [
            item for item in selectors if item["name"] != "adm_data_contract_version"
        ]
        selector_order.extend(
            item for item in selectors if item["name"] == "adm_data_contract_version"
        )
        for selector in selector_order:
            name = selector["name"]
            prior = origin["macros"][name]
            if not _macro_definition_equal(prior["definition"], selector["before"]):
                raise Refused(
                    "selector does not match the captured v1 effective definition"
                )
            mutations.append(
                {
                    "id": selector["id"],
                    "kind": "macro_definition",
                    "name": name,
                    "rest_target": selector["rest_target"],
                    "field": "definition",
                    # Keep the exact REST bytes for rollback; comparisons use
                    # the canonical SPL form above.
                    "before": prior["definition"],
                    "after": selector["after"],
                    "args": prior.get("args", ""),
                    "acl": prior["acl"],
                    "state": "pending",
                }
            )
        return mutations

    def _drain_legacy_writer(self, journal: dict[str, Any], timeout: int = 30) -> None:
        for _ in range(timeout):
            entries = self._entries(JOBS + "?count=0")
            active = []
            for entry in entries:
                content = entry.get("content") or {}
                label = content.get("savedsearch_name") or content.get("label")
                if label == "ADM - Conversation rollup" and _job_active(content):
                    active.append(_job_sid(entry))
            if not active:
                journal["cutover"]["legacy_writer_drained_at"] = int(self.clock())
                self._write_journal(journal)
                return
            self.sleep(1)
        raise Refused("legacy writer did not drain within the bounded wait")

    def _catch_up_after_pause(
        self, journal: dict[str, Any], scenario: dict[str, Any]
    ) -> None:
        watermark = (
            int(self.clock()) // SLICE_SECONDS * SLICE_SECONDS - 2 * SLICE_SECONDS
        )
        old_end = int(journal["range"]["end"])
        if watermark > old_end:
            if watermark - int(journal["range"]["start"]) > MAX_BACKFILL_SECONDS:
                raise Refused(
                    "paused-writer catch-up would exceed the seven-day bound; rollback or prepare a new range"
                )
            extra = plan_slices(old_end, watermark, int(self.clock()))
            journal["slices"].extend(
                {
                    **time_slice,
                    "streams": {name: {"state": "pending"} for name in STREAMS},
                    "history": {"state": "pending"},
                    "handoff_catchup": True,
                }
                for time_slice in extra
            )
            journal["range"]["end"] = watermark
            # The absolute event-time bound is refreshed only after the legacy
            # writer is paused; each dispatch still journals its exact bounds.
            journal["event_latest"] = str(int(self.clock()) + 15 * 60)
            journal["cutover"]["source_watermark"] = watermark
            journal["cutover"]["catchup_slices"] = len(extra)
            self._write_journal(journal)
            for slice_record in journal["slices"]:
                if not slice_record.get("handoff_catchup"):
                    continue
                for stream in STREAMS:
                    self._stage_stream(journal, slice_record, stream)
                self._stage_history_slice(journal, slice_record)
        else:
            journal["cutover"]["source_watermark"] = old_end
            journal["cutover"]["catchup_slices"] = 0
            self._write_journal(journal)
        # Re-run every closed-slice comparison and all public smoke queries
        # against the post-pause watermark before changing any reader selector.
        self.validate(scenario)
        refreshed = self.journal.read()
        if not refreshed:
            raise Refused("journal disappeared during paused-writer validation")
        refreshed["phase"] = "cutover_in_progress"
        refreshed["cutover"] = journal["cutover"]
        refreshed["cutover"]["post_pause_validation_at"] = int(self.clock())
        self._write_journal(refreshed)

    @staticmethod
    def _absolute_index_bounds(entry: dict[str, Any]) -> tuple[int, int] | None:
        """Resolve the shipped V2 scheduler window from explicit job metadata.

        Splunk's `indexEarliestTime`/`indexLatestTime` are observed event times,
        not dispatch bounds. Accept only the shipped relative index pair and
        a matching absolute search window, which gives a verified scheduler
        anchor. Do not infer the anchor from the SID or job creation time.
        """
        content = entry.get("content") or {}
        request = content.get("request") or {}
        if (
            request.get("index_earliest") != "-10m@m"
            or request.get("index_latest") != "-5m@m"
        ):
            return None
        earliest = _integer(content.get("searchEarliestTime"))
        latest = _integer(content.get("searchLatestTime"))
        if earliest is None or latest is None:
            return None
        anchor_from_earliest = earliest + 24 * 60 * 60
        anchor_from_latest = latest - 15 * 60
        if (
            anchor_from_earliest != anchor_from_latest
            or anchor_from_earliest % SLICE_SECONDS
        ):
            return None
        anchor = anchor_from_earliest
        lower = anchor // SLICE_SECONDS * SLICE_SECONDS - 2 * SLICE_SECONDS
        upper = lower + SLICE_SECONDS
        return lower, upper

    @staticmethod
    def _absolute_history_bounds(entry: dict[str, Any]) -> tuple[int, int] | None:
        """Resolve the history builder's distinct ten-minute-to-now window."""
        content = entry.get("content") or {}
        request = content.get("request") or {}
        if (
            request.get("earliest_time") != "0"
            or request.get("latest_time") != "+15m"
            or request.get("index_earliest") != "-10m@m"
            or request.get("index_latest") != "@m"
        ):
            return None
        earliest = _integer(content.get("searchEarliestTime"))
        latest = _integer(content.get("searchLatestTime"))
        if earliest not in (None, 0) or latest is None:
            return None
        anchor = latest - 15 * 60
        if anchor % SLICE_SECONDS != 60:
            return None
        return anchor - 2 * SLICE_SECONDS, anchor

    def _first_scheduled_writer_bounds(
        self,
        name: str,
        journal: dict[str, Any] | None = None,
        *,
        lower_epoch: int | None = None,
        upper_epoch: int | None = None,
        latest: bool = False,
    ) -> tuple[int, int] | None:
        """Find a confirmed scheduled slice, never a manual backfill dispatch."""
        cycles = self._scheduled_writer_cycles(
            name,
            journal,
            lower_epoch=lower_epoch,
            upper_epoch=upper_epoch,
        )
        if not cycles:
            return None
        selected = cycles[-1] if latest else cycles[0]
        return tuple(selected["index_bounds"])

    def _scheduled_writer_cycles(
        self,
        name: str,
        journal: dict[str, Any] | None,
        *,
        lower_epoch: int | None = None,
        upper_epoch: int | None = None,
    ) -> list[dict[str, Any]]:
        """List scheduler-owned slices with matching scheduler.log successes."""
        jobs = self._entries(JOBS + "?count=0")
        candidates: list[dict[str, Any]] = []
        manual_sids = {
            item.get("sid")
            for item in (journal or {}).get("jobs", [])
            if item.get("sid")
        }
        for entry in jobs:
            job = entry.get("content") or {}
            if not (
                _strict_bool(job.get("isSavedSearch")) is True
                and (job.get("savedsearch_name") or job.get("label")) == name
            ):
                continue
            sid = _job_sid(entry)
            label = job.get("label")
            # Splunk scheduler invocations have scheduler-owned SIDs/labels;
            # saved-search dispatch endpoints produce the saved-search label
            # and are separately recorded in this migration's journal.
            if sid in manual_sids or not (
                isinstance(sid, str)
                and sid.startswith("scheduler__")
                or isinstance(label, str)
                and label.startswith("scheduler__")
            ):
                continue
            try:
                saved_search_label = json.loads(job.get("savedSearchLabel", "{}"))
            except (TypeError, json.JSONDecodeError):
                raise Refused("scheduler-owned writer job has invalid saved-search ACL")
            if (
                job.get("provenance") != "scheduler"
                or job.get("label") != name
                or saved_search_label
                != {"owner": "nobody", "app": "splunk_adm", "sharing": "app"}
            ):
                raise Refused("scheduler-owned writer job identity is ambiguous")
            if (entry.get("acl") or {}).get("app") != "splunk_adm" or (
                entry.get("acl") or {}
            ).get("owner") != SAVEDSEARCH_DISPATCH_OWNER:
                raise Refused(
                    "scheduled writer job identity does not match the contract"
                )
            bounds = self._absolute_index_bounds(entry)
            if bounds is None:
                raise Refused(
                    "scheduler-owned writer job has unresolved request bounds"
                )
            anchor = bounds[0] + 2 * SLICE_SECONDS
            in_scope = (lower_epoch is None or anchor >= lower_epoch) and (
                upper_epoch is None or anchor < upper_epoch
            )
            exact_empty_warning = self._expected_empty_summary_warning(name, job)
            complete = (
                job.get("dispatchState") == "DONE"
                and _strict_bool(job.get("isDone")) is True
                and _strict_bool(job.get("isFinalized")) is False
                and _strict_bool(job.get("eventIsTruncated")) is False
                and _integer(job.get("dropCount")) == 0
                and _job_messages_complete(job.get("messages"), exact_empty_warning)
            )
            if in_scope and not complete:
                raise Refused("scheduled writer job overlaps the observation boundary")
            if not complete:
                continue
            if in_scope and self._scheduler_log_confirms(
                journal,
                sid,
                name,
                bounds,
                lower_epoch=lower_epoch,
                upper_epoch=upper_epoch,
            ):
                event_start = _integer(job.get("searchEarliestTime"))
                event_end = _integer(job.get("searchLatestTime"))
                if event_start is None or event_end is None:
                    continue
                candidates.append(
                    {
                        "sid": sid,
                        "index_bounds": list(bounds),
                        "event_bounds": {
                            "earliest_time": str(event_start),
                            "latest_time": str(event_end),
                        },
                        "anchor": anchor,
                        "empty_summary_warning": exact_empty_warning,
                    }
                )
        candidates.sort(key=lambda item: item["index_bounds"][0])
        if len({tuple(item["index_bounds"]) for item in candidates}) != len(candidates):
            raise Refused("multiple scheduler jobs claim the same source slice")
        anchors = [item["anchor"] for item in candidates]
        if any(
            right - left != SLICE_SECONDS for left, right in zip(anchors, anchors[1:])
        ):
            raise Refused(
                "scheduled writer evidence has a missing or overlapping cycle"
            )
        return candidates

    def _scheduled_history_cycles(
        self,
        journal: dict[str, Any],
        *,
        lower_epoch: int,
        upper_epoch: int,
    ) -> list[dict[str, Any]]:
        """Inventory complete scheduler-owned history windows through a boundary."""
        name = "ADM - Network client history builder"
        jobs = self._entries(JOBS + "?count=0")
        candidates = []
        manual_sids = {
            item.get("sid") for item in journal.get("jobs", []) if item.get("sid")
        }
        for entry in jobs:
            content = entry.get("content") or {}
            if not (
                _strict_bool(content.get("isSavedSearch")) is True
                and (content.get("savedsearch_name") or content.get("label")) == name
            ):
                continue
            sid = _job_sid(entry)
            label = content.get("label")
            if sid in manual_sids or not (
                isinstance(sid, str)
                and sid.startswith("scheduler__")
                or isinstance(label, str)
                and label.startswith("scheduler__")
            ):
                continue
            try:
                saved_search_label = json.loads(content.get("savedSearchLabel", "{}"))
            except (TypeError, json.JSONDecodeError):
                raise Refused("scheduled history job has invalid saved-search ACL")
            if (
                content.get("provenance") != "scheduler"
                or content.get("label") != name
                or saved_search_label
                != {"owner": "nobody", "app": "splunk_adm", "sharing": "app"}
                or (entry.get("acl") or {}).get("app") != "splunk_adm"
                or (entry.get("acl") or {}).get("owner") != SAVEDSEARCH_DISPATCH_OWNER
            ):
                raise Refused("scheduled history job identity is ambiguous")
            bounds = self._absolute_history_bounds(entry)
            if bounds is None:
                raise Refused("scheduled history job has unresolved request bounds")
            anchor = bounds[1]
            in_scope = lower_epoch < anchor < upper_epoch
            complete = (
                content.get("dispatchState") == "DONE"
                and _strict_bool(content.get("isDone")) is True
                and _strict_bool(content.get("isFinalized")) is False
                and _strict_bool(content.get("eventIsTruncated")) is False
                and _integer(content.get("dropCount")) == 0
                and _job_messages_complete(content.get("messages"))
            )
            if in_scope and not complete:
                raise Refused("scheduled history job overlaps the observation boundary")
            if not complete:
                continue
            if in_scope and self._scheduler_log_confirms(
                journal,
                sid,
                name,
                bounds,
                lower_epoch=lower_epoch,
                upper_epoch=upper_epoch,
                history_window=True,
            ):
                candidates.append(
                    {
                        "sid": sid,
                        "index_bounds": list(bounds),
                        "event_bounds": {
                            "earliest_time": "0",
                            "latest_time": str(anchor + 15 * 60),
                        },
                        "anchor": anchor,
                    }
                )
        candidates.sort(key=lambda item: item["index_bounds"][0])
        if len({tuple(item["index_bounds"]) for item in candidates}) != len(candidates):
            raise Refused("multiple history scheduler jobs claim the same slice")
        anchors = [item["anchor"] for item in candidates]
        if any(
            right - left != SLICE_SECONDS for left, right in zip(anchors, anchors[1:])
        ):
            raise Refused(
                "scheduled history evidence has a missing or overlapping cycle"
            )
        return candidates

    @staticmethod
    def _history_next_anchor(enabled_after: int) -> int:
        first = enabled_after // SLICE_SECONDS * SLICE_SECONDS + 60
        return first if first > enabled_after else first + SLICE_SECONDS

    def _history_writer_activation_epoch(self, journal: dict[str, Any]) -> int | None:
        name = "ADM - Network client history builder"
        activation = [
            _integer(item.get("verified_at"))
            for item in (journal.get("cutover") or {}).get("mutations", [])
            if item.get("kind") == "saved_search"
            and item.get("name") == name
            and _strict_bool(item.get("after")) is False
            and item.get("state") == "applied"
        ]
        if activation:
            if len(activation) != 1 or activation[0] is None:
                raise Refused("history writer activation time is ambiguous")
            return activation[0]
        origin_disabled = (
            ((journal.get("origin") or {}).get("saved_searches") or {})
            .get(name, {})
            .get("content", {})
            .get("disabled")
        )
        if _strict_bool(origin_disabled) is False:
            return _integer(journal.get("created_at"))
        return None

    def _stage_scheduled_history_evidence(
        self, journal: dict[str, Any], cycles: list[dict[str, Any]]
    ) -> None:
        interface, _ = self._interface()
        contract = interface["staged_collections"]["network_client_history"]
        state = journal["cutover"].setdefault("scheduled_history", {"cycles": []})
        prior = {
            tuple(item.get("index_bounds", [])): item
            for item in state.get("cycles", [])
        }
        current = []
        for cycle in cycles:
            bounds = tuple(cycle["index_bounds"])
            expected = self._history_expected(
                journal,
                contract,
                bounds[0],
                bounds[1],
                event_bounds=cycle["event_bounds"],
            )
            expected_fp = fingerprint(expected)
            previous = prior.get(bounds)
            if previous and previous.get("sid") != cycle.get("sid"):
                raise Refused("history scheduler SID changed for a validated window")
            item = {
                **cycle,
                "expected_fingerprint": expected_fp,
                "expected_receipts": self._history_receipt_manifest(expected),
                "rows": len(expected),
                "validated_at": int(self.clock()),
            }
            if previous and previous.get("expected_fingerprint") != expected_fp:
                item["prior_expected_fingerprints"] = [
                    *previous.get("prior_expected_fingerprints", []),
                    previous["expected_fingerprint"],
                ]
                item["source_revision_at"] = int(self.clock())
            current.append(item)
        state.update(cycles=current)
        self._write_journal(journal)

    def _stage_history_gap_before_first_cycle(
        self,
        journal: dict[str, Any],
        first_cycle_start: int,
    ) -> None:
        history_slices = [
            *journal.get("slices", []),
            *((journal.get("cutover") or {}).get("history_bridge_slices") or []),
        ]
        covered_end = max(
            (
                int(item["end"])
                for item in history_slices
                if item.get("history", {}).get("state") == "verified"
            ),
            default=int(journal["range"]["end"]),
        )
        if first_cycle_start <= covered_end:
            return
        if first_cycle_start - covered_end > MAX_BACKFILL_SECONDS:
            raise Refused("history scheduler gap exceeds the seven-day recovery bound")
        self._stage_history_gap(journal, covered_end, first_cycle_start)

    def _stage_history_gap(self, journal: dict[str, Any], start: int, end: int) -> None:
        if end <= start:
            return
        if end - start > MAX_BACKFILL_SECONDS:
            raise Refused("history scheduler gap exceeds the seven-day recovery bound")
        if start % 60 or end % 60:
            raise Refused("history scheduler gap is not minute aligned")
        gap = []
        cursor = start
        while cursor < end:
            next_end = min(cursor + 60, end)
            gap.append(
                {
                    "start": cursor,
                    "end": next_end,
                    "history": {"state": "pending"},
                    "history_bridge": True,
                }
            )
            cursor = next_end
        bridge = journal["cutover"].setdefault("history_bridge_slices", [])
        existing = {(item["start"], item["end"]): item for item in bridge}
        for item in gap:
            key = (item["start"], item["end"])
            existing.setdefault(key, item)
        bridge[:] = sorted(existing.values(), key=lambda item: item["start"])
        self._write_journal(journal)
        for item in bridge:
            if item["start"] >= start and item["end"] <= end:
                self._stage_history_slice(journal, item)

    def _stage_history_tail_through_summary(
        self, journal: dict[str, Any], summary_end: int
    ) -> None:
        verified_ends = [
            int(item["end"])
            for item in [
                *journal.get("slices", []),
                *((journal.get("cutover") or {}).get("history_bridge_slices") or []),
            ]
            if item.get("history", {}).get("state") == "verified"
        ]
        scheduled_ends = [
            int(bounds[1])
            for cycle in (
                (journal.get("cutover") or {})
                .get("scheduled_history", {})
                .get("cycles", [])
            )
            for bounds in [cycle.get("index_bounds") or []]
            if len(bounds) == 2
        ]
        covered_end = max(
            [*verified_ends, *scheduled_ends],
            default=int(journal["range"]["end"]),
        )
        if covered_end < summary_end:
            self._stage_history_gap(journal, covered_end, summary_end)

    def _scheduler_log_confirms(
        self,
        journal: dict[str, Any] | None,
        sid: str,
        name: str,
        bounds: tuple[int, int],
        *,
        lower_epoch: int | None = None,
        upper_epoch: int | None = None,
        history_window: bool = False,
    ) -> bool:
        """Require one successful scheduler.log row matching this exact SID."""
        if not isinstance(journal, dict):
            return False
        started = (
            lower_epoch
            if lower_epoch is not None
            else _integer((journal.get("cutover") or {}).get("started_at"))
        )
        if started is None:
            return False
        lower, upper = bounds
        anchor = lower + 2 * SLICE_SECONDS
        query = (
            'search index=_internal source=*scheduler.log* app="splunk_adm" '
            f"| where sid={json.dumps(sid)} AND savedsearch_name={json.dumps(name)} "
            "| table sid savedsearch_name scheduled_time dispatch_time status"
        )
        observation_upper = int(self.clock()) + 60
        if upper_epoch is not None:
            observation_upper = min(observation_upper, upper_epoch)
        rows = self._query(
            journal,
            query,
            started,
            observation_upper,
            label=f"scheduler log confirmation {name} {sid}",
            earliest_time=str(started),
            latest_time=str(observation_upper),
            persist_result_rows=False,
        )
        matches = [
            row
            for row in rows
            if row.get("sid") == sid
            and row.get("savedsearch_name") == name
            and row.get("status") == "success"
            and _integer(row.get("scheduled_time")) == anchor
            and (
                (dispatch := _integer(row.get("dispatch_time"))) is not None
                and dispatch >= anchor
                and dispatch < observation_upper
            )
        ]
        expected_upper = anchor if history_window else anchor - SLICE_SECONDS
        return len(rows) == 1 and len(matches) == 1 and upper == expected_upper

    @staticmethod
    def _v1_stable_row(row: dict[str, Any]) -> dict[str, Any]:
        numeric = {
            "_time",
            "server_port",
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
        }
        stable = {}
        for field in V1_ROW_FIELDS:
            if field == "encapsulation":
                continue
            value = row.get(field)
            if value in ("", "null", "None"):
                value = None
            if field in numeric and value is not None:
                parsed = _number(value)
                if parsed is not None:
                    value = int(parsed) if parsed.is_integer() else parsed
            if field == "observations":
                value = _observations_without_netflow_interfaces(
                    value, row.get("observer")
                )
            elif field == "vlan_observations":
                value = _vlan_observations_without_interface_names(
                    value, row.get("vlan_observations_truncated")
                )
            stable[field] = value
        return stable

    @classmethod
    def _v1_record_map(cls, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        observed = {}
        for row in rows:
            rollup_id = str(row.get("rollup_id") or "")
            records = _integer(row.get("records"))
            if (
                not ROLLUP_ID_RE.fullmatch(rollup_id)
                or records is None
                or records <= 0
                or row.get("adm_record")
                not in {"conversation", "hubble_xlate", "hubble_l7"}
            ):
                raise Refused("V1 recovery output has invalid stable rollup material")
            content = cls._v1_stable_row(row)
            digest = fingerprint(
                {"canonicalizer": SUMMARY_CANONICALIZER_VERSION, "row": content}
            )
            if rollup_id in observed:
                if observed[rollup_id]["content_digest"] != digest:
                    raise Refused("V1 recovery output conflicts for a stable rollup ID")
                observed[rollup_id]["copies"] += 1
            else:
                observed[rollup_id] = {
                    "content": content,
                    "content_digest": digest,
                    "copies": 1,
                }
        return observed

    def _v1_source_query(self, journal: dict[str, Any]) -> str:
        interface, _ = self._interface()
        writer = next(
            item
            for item in interface["activation"]["writer_contracts"]
            if item["name"] == "ADM - Conversation rollup"
        )
        entry = self._saved_search(writer["name"])
        content = self._normalize_saved_search_schedule(
            entry.get("content") or {}, writer["fields"]
        )
        for field, expected in writer["fields"].items():
            if field == "disabled":
                if _strict_bool(content.get(field)) is True:
                    continue
                origin_disabled = (
                    (journal.get("origin") or {})
                    .get("saved_searches", {})
                    .get(writer["name"], {})
                    .get("content", {})
                    .get("disabled")
                )
                if _strict_bool(
                    origin_disabled
                ) is not False and not self._writer_enabled_by_journal(
                    journal, writer["name"]
                ):
                    raise Refused("V1 recovery writer is enabled outside its journal")
            elif not _config_equal(field, content.get(field), expected):
                raise Refused(
                    "V1 recovery writer no longer matches its immutable contract"
                )
        current = self.snapshot(allow_activation=True)
        if current.get("macro_inventory") != (journal.get("origin") or {}).get(
            "macro_inventory"
        ):
            raise Refused("V1 writer macro dependencies changed during cutover")
        return writer["source_query"].strip()

    def _v1_expected_rows(
        self,
        journal: dict[str, Any],
        bounds: tuple[int, int],
        event_bounds: dict[str, str],
        label: str,
    ) -> dict[str, dict[str, Any]]:
        query = self._v1_source_query(journal) + " | fields " + " ".join(V1_ROW_FIELDS)
        rows = self._query(
            journal,
            query,
            bounds[0],
            bounds[1],
            label=label,
            earliest_time=event_bounds["earliest_time"],
            latest_time=event_bounds["latest_time"],
        )
        return self._v1_record_map(rows)

    def _v1_persisted_rows(
        self,
        journal: dict[str, Any],
        expected: dict[str, dict[str, Any]],
        event_bounds: dict[str, str],
        label: str,
    ) -> dict[str, dict[str, Any]]:
        if not expected:
            return {}
        # A later scheduler cycle can have a narrower raw-event window than
        # an earlier retained summary row. Rollup _time is derived from the
        # flow bucket and can precede that raw-event window, so use bounds
        # that cover every expected retained row as well as the caller's
        # window. ID, material, and multiplicity checks below remain exact.
        retained_times = [
            number
            for row in expected.values()
            if (number := _number(row.get("content", {}).get("_time"))) is not None
        ]
        requested_earliest = _number(event_bounds.get("earliest_time"))
        requested_latest = _number(event_bounds.get("latest_time"))
        retained_earliest = min(retained_times, default=None)
        retained_latest = max(retained_times, default=None)
        read_earliest = min(
            (
                value
                for value in (requested_earliest, retained_earliest)
                if value is not None
            ),
            default=0,
        )
        read_latest = max(
            (
                value
                for value in (
                    requested_latest,
                    retained_latest + 1 if retained_latest is not None else None,
                )
                if value is not None
            ),
            default=read_earliest + 1,
        )
        retained_event_bounds = {
            "earliest_time": f"{read_earliest:.15g}",
            "latest_time": f"{read_latest:.15g}",
        }
        observed: dict[str, dict[str, Any]] = {}
        ids = sorted(expected)
        for offset in range(0, len(ids), ROLLUP_ID_QUERY_BATCH):
            chunk = ids[offset : offset + ROLLUP_ID_QUERY_BATCH]
            query = (
                f'| search index={V1_INDEX} source="adm:conversation" '
                f"rollup_id IN ({', '.join(json.dumps(item) for item in chunk)}) "
                "| fields " + " ".join(V1_ROW_FIELDS)
            )
            rows = self._query(
                journal,
                query,
                None,
                None,
                label=f"{label} batch {offset // ROLLUP_ID_QUERY_BATCH + 1}",
                earliest_time=retained_event_bounds["earliest_time"],
                latest_time=retained_event_bounds["latest_time"],
                persist_result_rows=False,
            )
            observed = _add_record_maps(
                observed,
                self._v1_record_map(rows),
                label="V1 retained summary rows",
            )
        if any(key not in expected for key in observed):
            raise Refused("V1 summary index contains unexplained rollup IDs")
        return observed

    def _assert_empty_summary_index_window(
        self,
        journal: dict[str, Any],
        index: str,
        source: str,
        lower_indextime: int,
        upper_indextime: int,
        label: str,
        *,
        allowed_rollup_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Prove a zero-result dispatch added no unexplained retained rows.

        A later successful cycle can legitimately write to the same source
        while the empty cycle is being audited. Those rows are accepted only
        when their IDs were independently derived from bounded, validated
        cycle or manual-write manifests; the complete-window audit still
        compares all retained material fields against those manifests.
        """
        if lower_indextime < 0 or upper_indextime < lower_indextime:
            raise Refused("empty summary audit has invalid index-time bounds")
        query = (
            f"search index={index} source={json.dumps(source)} "
            f"| where _indextime>={lower_indextime} "
            f"AND _indextime<={upper_indextime} "
            "| fields " + " ".join(V1_ROW_FIELDS)
        )
        rows = self._query(
            journal,
            query,
            lower_indextime,
            upper_indextime + 1,
            label=label,
            earliest_time="0",
            latest_time="+10y",
            persist_result_rows=False,
        )
        allowed = allowed_rollup_ids or set()
        observed_ids = []
        for row in rows:
            rollup_id = str(row.get("rollup_id", ""))
            if not ROLLUP_ID_RE.fullmatch(rollup_id) or rollup_id not in allowed:
                raise Refused(
                    "zero-result summary writer has retained rows in its audit window outside validated manifests"
                )
            observed_ids.append(rollup_id)
        return {
            "index": index,
            "source": source,
            "lower_indextime": lower_indextime,
            "upper_indextime": upper_indextime,
            "retained_rows": 0,
            "observed_manifest_rows": len(observed_ids),
            "allowed_manifest_fingerprint": fingerprint(sorted(allowed)),
            "retained_fingerprint": fingerprint(sorted(observed_ids)),
            "validated_at": int(self.clock()),
        }

    def _verify_v1_raw_retention(
        self, journal: dict[str, Any], start: int, end: int
    ) -> dict[str, Any]:
        entries = self._entries(
            APP + "/configs/conf-macros?count=10000", max_count=MAX_RESULTS
        )
        definitions = {
            str(entry.get("name")): (entry.get("content") or {}).get("definition", "")
            for entry in entries
            if entry.get("name")
        }
        pending = ["adm_conversation_rollup"]
        seen = set()
        source_indexes = set()
        ref_re = re.compile(r"`([^`]+)`")
        while pending:
            call = pending.pop()
            base = call.split("(", 1)[0]
            args = call[len(base) + 1 : -1] if call.startswith(base + "(") else ""
            depth = 0
            commas = 0
            for character in args:
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                elif character == "," and depth == 0:
                    commas += 1
            arity = 0 if not args else commas + 1
            name = f"{base}({arity})" if arity else base
            if name in seen:
                continue
            seen.add(name)
            definition = definitions.get(name)
            if definition is None and name.endswith("(0)"):
                definition = definitions.get(base)
            if not isinstance(definition, str):
                raise Refused("V1 raw-source macro dependency cannot be resolved")
            if name.startswith("adm_index_") or base.startswith("adm_index_"):
                match = re.search(r"\bindex\s*=\s*([A-Za-z0-9_.-]+)", definition)
                if match:
                    source_indexes.add(match.group(1))
            pending.extend(ref_re.findall(definition))
        if not source_indexes:
            raise Refused("V1 raw-source index dependencies are not identifiable")
        try:
            index_entries = self._entries(
                "/services/data/indexes?count=0", max_count=MAX_RESULTS
            )
        except Exception:
            raise Refused("V1 raw-source retention metadata is unavailable") from None
        indexed = {
            str(
                (entry.get("content") or {}).get("title", entry.get("name"))
            ): entry.get("content") or {}
            for entry in index_entries
        }
        retention = {}
        needed = end - start
        for name in sorted(source_indexes):
            value = _integer((indexed.get(name) or {}).get("frozenTimePeriodInSecs"))
            if value is None or value <= 0 or value < needed:
                raise Refused(
                    "raw-source retention does not cover the V1 recovery window"
                )
            retention[name] = value
        return {"from": start, "through": end, "indexes": retention}

    def _capture_v1_pre_pause(self, journal: dict[str, Any]) -> dict[str, Any]:
        """Require a real, complete V1 scheduler slice before pausing V1."""
        now = int(self.clock())
        lower = max(0, now - 3 * SLICE_SECONDS)
        cycles = self._scheduled_writer_cycles(
            "ADM - Conversation rollup",
            journal,
            lower_epoch=lower,
            upper_epoch=now + 1,
        )
        if not cycles:
            raise Refused(
                "enabled V1 writer has no confirmed scheduler slice to anchor rollback"
            )
        cycle = cycles[-1]
        if now - cycle["anchor"] > 2 * SLICE_SECONDS:
            raise Refused(
                "last successful V1 scheduler slice is too old to anchor rollback"
            )
        bounds = tuple(cycle["index_bounds"])
        expected = self._v1_expected_rows(
            journal, bounds, cycle["event_bounds"], "pre-pause V1 expected output"
        )
        observed_cycle_ids: set[str] = set()
        for observed_cycle in cycles:
            observed_expected = self._v1_expected_rows(
                journal,
                tuple(observed_cycle["index_bounds"]),
                observed_cycle["event_bounds"],
                f"pre-pause V1 observed cycle {observed_cycle['index_bounds'][0]}",
            )
            observed_cycle_ids.update(observed_expected)
        empty_summary_proof = None
        if cycle.get("empty_summary_warning") is True:
            if expected:
                raise Refused(
                    "V1 scheduler reported an empty summary while source rows exist"
                )
            empty_summary_proof = self._assert_empty_summary_index_window(
                journal,
                V1_INDEX,
                "adm:conversation",
                int(cycle["anchor"]),
                now,
                "pre-pause empty V1 summary audit",
                allowed_rollup_ids=observed_cycle_ids,
            )
        actual = self._v1_persisted_rows(
            journal, expected, cycle["event_bounds"], "pre-pause V1 summary readback"
        )
        if actual != expected:
            raise Refused(
                "last V1 scheduler slice is not completely retained in adm_summary"
            )
        state = {
            **cycle,
            "expected": expected,
            "expected_fingerprint": fingerprint(expected),
            "retained_fingerprint": fingerprint(actual),
            "captured_at": now,
            **(
                {"empty_summary_proof": empty_summary_proof}
                if empty_summary_proof is not None
                else {}
            ),
        }
        journal["v1_pre_pause"] = state
        self._write_journal(journal)
        return state

    def _verified_v1_manual_recovery_ids(
        self, journal: dict[str, Any], recovery: dict[str, Any]
    ) -> set[str]:
        """Return IDs from manual slices with durable, exact write evidence."""
        jobs_by_sid: dict[str, list[dict[str, Any]]] = {}
        for job in journal.get("jobs", []):
            sid = job.get("sid")
            if isinstance(sid, str) and sid:
                jobs_by_sid.setdefault(sid, []).append(job)

        allowed: set[str] = set()
        for key, item in recovery.get("expected_slices", {}).items():
            if not isinstance(item, dict) or item.get("state") != "verified":
                continue
            bounds = item.get("index_bounds")
            event_bounds = item.get("event_bounds")
            expected = item.get("expected")
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or not all(isinstance(value, int) for value in bounds)
                or key != f"{bounds[0]}:{bounds[1]}"
                or bounds[1] <= bounds[0]
                or not isinstance(event_bounds, dict)
                or not isinstance(expected, dict)
                or item.get("expected_fingerprint") != fingerprint(expected)
            ):
                raise Refused("verified V1 manual recovery manifest is malformed")
            normalized = self._v1_record_map(
                [
                    value["content"]
                    for value in expected.values()
                    for _ in range(value.get("copies", 0))
                ]
            )
            if normalized != expected:
                raise Refused("verified V1 manual recovery content changed")
            ids = set(expected)
            if not ids:
                continue
            sids = item.get("manual_job_sids")
            if not isinstance(sids, list) or not sids:
                raise Refused("V1 manual recovery manifest has no durable writer SID")
            matched = set()
            for sid in sids:
                records = jobs_by_sid.get(sid, []) if isinstance(sid, str) else []
                if len(records) != 1:
                    raise Refused("V1 manual recovery writer SID is ambiguous")
                job = records[0]
                request_bounds = job.get("request_bounds") or {}
                job_state = job.get("job_state") or {}
                if (
                    job.get("kind") != "saved_search"
                    or job.get("label") != "ADM - Conversation rollup"
                    or job.get("state") != "complete"
                    or str(request_bounds.get("index_earliest")) != str(bounds[0])
                    or str(request_bounds.get("index_latest")) != str(bounds[1])
                    or str(request_bounds.get("earliest_time"))
                    != str(event_bounds.get("earliest_time"))
                    or str(request_bounds.get("latest_time"))
                    != str(event_bounds.get("latest_time"))
                    or not job.get("search_fingerprint")
                    or _integer(job.get("result_count"))
                    != sum(item["copies"] for item in expected.values())
                    or job_state.get("dispatchState") != "DONE"
                    or not _truth(job_state.get("isDone"))
                    or _truth(job_state.get("isFinalized"))
                    or job_state.get("eventIsTruncated") not in (False, "0", 0)
                    or _integer(job_state.get("dropCount")) != 0
                    or _integer(job_state.get("resultCount"))
                    != sum(item["copies"] for item in expected.values())
                    or not _job_messages_complete(job_state.get("messages"))
                ):
                    raise Refused("V1 manual recovery writer evidence is incomplete")
                matched.add(sid)
            if matched != set(sids):
                raise Refused("V1 manual recovery writer SID set changed")
            allowed.update(ids)
        return allowed

    def _reconcile_pending_v1_manual_slices(
        self,
        journal: dict[str, Any],
        recovery: dict[str, Any],
        scheduled_expected: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Adopt completed manual SIDs before later empty-cycle audits."""
        jobs_by_bounds: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for job in journal.get("jobs", []):
            if (
                job.get("kind") == "saved_search"
                and job.get("label") == "ADM - Conversation rollup"
                and job.get("state") in {"complete", "running", "dispatch_unknown"}
                and isinstance(job.get("sid"), str)
                and job.get("sid")
            ):
                bounds = job.get("request_bounds") or {}
                first = str(bounds.get("index_earliest", ""))
                last = str(bounds.get("index_latest", ""))
                jobs_by_bounds.setdefault((first, last), []).append(job)

        for key, item in recovery.get("expected_slices", {}).items():
            if not isinstance(item, dict) or item.get("state") != "expected":
                continue
            bounds = item.get("index_bounds")
            event_bounds = item.get("event_bounds")
            expected = item.get("expected")
            if (
                not isinstance(bounds, list)
                or len(bounds) != 2
                or not all(isinstance(value, int) for value in bounds)
                or key != f"{bounds[0]}:{bounds[1]}"
                or bounds[1] <= bounds[0]
                or not isinstance(event_bounds, dict)
                or not isinstance(expected, dict)
                or item.get("expected_fingerprint") != fingerprint(expected)
            ):
                raise Refused("pending V1 manual recovery manifest is malformed")
            if not expected:
                continue
            expected = self._v1_record_map(
                [
                    value["content"]
                    for value in expected.values()
                    for _ in range(value.get("copies", 0))
                ]
            )
            if expected != item.get("expected"):
                raise Refused("pending V1 manual recovery content changed")
            writer_intent = fingerprint(
                {
                    "migration_id": journal["migration_id"],
                    "rollback_resume_epoch": recovery.get("resume_activation_epoch"),
                    "slice": bounds,
                    "expected": item["expected_fingerprint"],
                }
            )
            jobs = [
                job
                for job in jobs_by_bounds.get((str(bounds[0]), str(bounds[1])), [])
                if job.get("intent_fingerprint") == writer_intent
            ]
            if not jobs:
                continue
            if len(jobs) != 1:
                raise Refused("pending V1 recovery has ambiguous complete writer SIDs")
            job = jobs[0]
            output_rows = self._completed_job_rows(journal, job)
            if self._v1_record_map(output_rows) != expected:
                raise Refused("pending V1 manual recovery SID output changed")
            request_bounds = job.get("request_bounds") or {}
            job_state = job.get("job_state") or {}
            if (
                str(request_bounds.get("earliest_time"))
                != str(event_bounds.get("earliest_time"))
                or str(request_bounds.get("latest_time"))
                != str(event_bounds.get("latest_time"))
                or not job.get("sid")
                or not job.get("search_fingerprint")
                or _integer(job.get("result_count"))
                != sum(item["copies"] for item in expected.values())
                or job_state.get("dispatchState") != "DONE"
                or not _truth(job_state.get("isDone"))
                or _truth(job_state.get("isFinalized"))
                or job_state.get("eventIsTruncated") not in (False, "0", 0)
                or _integer(job_state.get("dropCount")) != 0
                or _integer(job_state.get("resultCount"))
                != sum(item["copies"] for item in expected.values())
                or not _job_messages_complete(job_state.get("messages"))
            ):
                raise Refused("pending V1 manual recovery writer SID is incomplete")
            source_expected = self._v1_expected_rows(
                journal,
                tuple(bounds),
                event_bounds,
                f"V1 pending recovery source verification {bounds[0]}",
            )
            pending_cumulative = {}
            for prior in recovery.get("expected_slices", {}).values():
                if prior is not item and prior.get("state") == "verified":
                    pending_cumulative = _add_record_maps(
                        pending_cumulative,
                        prior.get("expected") or {},
                        label="V1 pending recovery retained intents",
                    )
            pending_cumulative = _add_record_maps(
                pending_cumulative,
                expected,
                label="V1 pending recovery retained intents",
            )
            for scheduled_manifest in (scheduled_expected or {}).values():
                pending_cumulative = _add_record_maps(
                    pending_cumulative,
                    scheduled_manifest,
                    label="V1 pending recovery scheduled intents",
                )
            actual = self._v1_persisted_rows(
                journal,
                pending_cumulative,
                event_bounds,
                f"V1 pending recovery retained verification {bounds[0]}",
            )
            if source_expected != expected or actual != pending_cumulative:
                raise Refused(
                    "pending V1 manual recovery SID lacks exact source and retained parity"
                )
            item.update(
                state="verified",
                verified_at=int(self.clock()),
                manual_job_sids=[job["sid"]],
            )
            self._write_journal(journal)

    def _v1_recovery_window(
        self, journal: dict[str, Any], resume_epoch: int
    ) -> dict[str, Any] | None:
        """Backfill V1's missed raw slices through confirmed resumed schedules."""
        pre_pause = journal.get("v1_pre_pause")
        if not isinstance(pre_pause, dict):
            raise Refused("V1 rollback has no validated pre-pause scheduler boundary")
        observation = int(self.clock())
        cycles = self._scheduled_writer_cycles(
            "ADM - Conversation rollup",
            journal,
            lower_epoch=resume_epoch + 1,
            upper_epoch=observation + 1,
        )
        if not cycles:
            return None
        expected_first_anchor = (resume_epoch // SLICE_SECONDS + 1) * SLICE_SECONDS
        if cycles[0]["anchor"] != expected_first_anchor:
            raise Refused("first resumed V1 scheduler boundary is missing")
        pre_end = _integer(pre_pause.get("index_bounds", [None, None])[1])
        if pre_end is None or cycles[0]["index_bounds"][0] < pre_end:
            raise Refused("resumed V1 scheduler slice overlaps its pre-pause boundary")
        end = cycles[-1]["index_bounds"][1]
        if end - pre_end > MAX_BACKFILL_SECONDS:
            raise Refused(
                "V1 rollback recovery exceeds the seven-day slice bound; V1 is "
                "already resumed and the journal stays rollback_in_progress. See "
                "'If rollback refuses on the seven-day bound' in "
                "docs/CISCO_CONTRACT_MIGRATION.md"
            )
        retention = self._verify_v1_raw_retention(journal, pre_end, end)
        first_resumed_start = cycles[0]["index_bounds"][0]
        gap_slices = (
            plan_slices(pre_end, first_resumed_start, observation)
            if first_resumed_start > pre_end
            else []
        )
        if gap_slices and (
            gap_slices[0]["start"] != pre_end
            or gap_slices[-1]["end"] != cycles[0]["index_bounds"][0]
        ):
            raise Refused("V1 rollback gap is not a complete set of closed slices")

        rollback = journal.setdefault("rollback", {})
        recovery = rollback.setdefault(
            "v1_recovery",
            {
                "state": "recovering",
                "resume_activation_epoch": resume_epoch,
                "expected_slices": {},
                "scheduler_cycles": {},
            },
        )
        recovery.setdefault("expected_slices", {})
        recovery.setdefault("scheduler_cycles", {})
        empty_proofs = recovery.setdefault("empty_summary_proofs", {})
        if recovery.get("resume_activation_epoch") != resume_epoch:
            raise Refused("V1 rollback resume epoch changed in the durable journal")
        recovery["observation_epoch"] = observation
        recovery["raw_retention"] = retention
        # Record the empty-cycle proof before any manual V1 gap writes. That
        # makes retries idempotent. Other completed scheduler cycles can
        # legitimately have rows in this later observation window, so their
        # independently queried IDs form the allowlist for the retained-row
        # audit; the final recovery audit verifies their full contents.
        scheduled_expected: dict[str, dict[str, Any]] = {}
        for observed_cycle in cycles:
            bounds = tuple(observed_cycle["index_bounds"])
            scheduled_expected[observed_cycle["sid"]] = self._v1_expected_rows(
                journal,
                bounds,
                observed_cycle["event_bounds"],
                f"V1 resumed scheduler source audit {bounds[0]}",
            )
        self._reconcile_pending_v1_manual_slices(journal, recovery, scheduled_expected)
        allowed_scheduler_ids = {
            rollup_id
            for expected_rows in scheduled_expected.values()
            for rollup_id in expected_rows
        }
        allowed_manual_ids = self._verified_v1_manual_recovery_ids(journal, recovery)
        allowed_empty_audit_ids = allowed_scheduler_ids | allowed_manual_ids
        for cycle in cycles:
            if cycle.get("empty_summary_warning") is not True:
                continue
            bounds = tuple(cycle["index_bounds"])
            key = f"{bounds[0]}:{bounds[1]}"
            prior = empty_proofs.get(key)
            if prior is not None:
                if prior.get("sid") != cycle.get("sid"):
                    raise Refused("V1 empty-cycle proof SID changed on resume")
                continue
            expected = scheduled_expected[cycle["sid"]]
            if expected:
                raise Refused(
                    "resumed V1 scheduler reported empty output while source rows exist"
                )
            proof = self._assert_empty_summary_index_window(
                journal,
                V1_INDEX,
                "adm:conversation",
                int(cycle["anchor"]),
                observation,
                f"V1 resumed empty summary audit {bounds[0]}",
                allowed_rollup_ids=allowed_empty_audit_ids,
            )
            empty_proofs[key] = {
                "sid": cycle["sid"],
                "index_bounds": list(bounds),
                **proof,
            }
            self._write_journal(journal)

        def validate_expected(
            bounds: tuple[int, int], event_bounds: dict[str, str], label: str
        ) -> dict[str, dict[str, Any]]:
            return self._v1_expected_rows(journal, bounds, event_bounds, label)

        for raw_slice in gap_slices:
            start, finish = raw_slice["start"], raw_slice["end"]
            anchor = start + 2 * SLICE_SECONDS
            event_bounds = {
                "earliest_time": str(anchor - 24 * 60 * 60),
                "latest_time": str(anchor + 15 * 60),
            }
            intent = f"{start}:{finish}"
            existing_state = recovery["expected_slices"].get(intent)
            expected = validate_expected(
                (start, finish), event_bounds, f"V1 recovery expected {start}"
            )
            expected_hash = fingerprint(expected)
            if (
                existing_state
                and existing_state.get("expected_fingerprint") != expected_hash
            ):
                raise Refused("V1 recovery source changed after its bounded read")
            recovery["expected_slices"][intent] = {
                "index_bounds": [start, finish],
                "event_bounds": event_bounds,
                "expected": expected,
                "expected_fingerprint": expected_hash,
                "state": "expected",
            }
            self._write_journal(journal)
            cumulative_expected = {}
            for prior_intent, item in recovery["expected_slices"].items():
                if prior_intent != intent and item.get("state") == "verified":
                    cumulative_expected = _add_record_maps(
                        cumulative_expected,
                        item.get("expected") or {},
                        label="V1 recovery manual intents",
                    )
            for item in recovery["scheduler_cycles"].values():
                cumulative_expected = _add_record_maps(
                    cumulative_expected,
                    item.get("expected") or {},
                    label="V1 recovery scheduled intents",
                )
            for observed_cycle in cycles:
                observed_key = (
                    f"{observed_cycle['index_bounds'][0]}:"
                    f"{observed_cycle['index_bounds'][1]}"
                )
                if observed_key in recovery["scheduler_cycles"]:
                    continue
                cumulative_expected = _add_record_maps(
                    cumulative_expected,
                    scheduled_expected[observed_cycle["sid"]],
                    label="V1 recovery scheduled intents",
                )
            expected_with_current = _add_record_maps(
                cumulative_expected, expected, label="V1 recovery current intent"
            )
            already = self._v1_persisted_rows(
                journal,
                expected_with_current,
                event_bounds,
                f"V1 recovery existing rows {start}",
            )
            if already not in (cumulative_expected, expected_with_current):
                raise Refused(
                    "V1 recovery retained rows do not cover the expected source slice"
                )
            writer_intent = fingerprint(
                {
                    "migration_id": journal["migration_id"],
                    "rollback_resume_epoch": resume_epoch,
                    "slice": [start, finish],
                    "expected": expected_hash,
                }
            )
            matching_jobs = [
                job
                for job in journal.get("jobs", [])
                if job.get("kind") == "saved_search"
                and job.get("label") == "ADM - Conversation rollup"
                and job.get("request_bounds")
                == {
                    "index_earliest": str(start),
                    "index_latest": str(finish),
                    "earliest_time": event_bounds["earliest_time"],
                    "latest_time": event_bounds["latest_time"],
                }
                and job.get("intent_fingerprint") == writer_intent
            ]
            dispatch_jobs = [
                job
                for job in matching_jobs
                if job.get("sid")
                or job.get("state")
                not in {"rejected", "configuration_pending", "preparation_aborted"}
            ]
            if expected:
                if len(dispatch_jobs) > 1:
                    raise Refused("V1 recovery slice has ambiguous writer intents")
                if already == expected_with_current and not dispatch_jobs:
                    raise Refused(
                        "V1 recovery retained rows have no exact journaled writer SID"
                    )
                bounds = {
                    "index_earliest": str(start),
                    "index_latest": str(finish),
                    "earliest_time": event_bounds["earliest_time"],
                    "latest_time": event_bounds["latest_time"],
                }
                output_rows = self._dispatch_writer(
                    journal,
                    "ADM - Conversation rollup",
                    bounds,
                    label=f"V1 rollback recovery slice {start}",
                    intent_fingerprint=writer_intent,
                    persist_result_rows=True,
                )
                if self._v1_record_map(output_rows) != expected:
                    raise Refused(
                        "V1 recovery writer output differs from raw-source expectation"
                    )
                cumulative_expected = _add_record_maps(
                    cumulative_expected, expected, label="V1 recovery manual intents"
                )
                for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
                    observed = self._v1_persisted_rows(
                        journal,
                        cumulative_expected,
                        event_bounds,
                        f"V1 recovery readback {start}",
                    )
                    if observed == cumulative_expected:
                        break
                    self._wait_before_summary_retry(attempt)
                else:
                    raise Refused("V1 recovery summary rows did not become visible")
                matching_jobs = [
                    job
                    for job in journal.get("jobs", [])
                    if job.get("kind") == "saved_search"
                    and job.get("label") == "ADM - Conversation rollup"
                    and job.get("request_bounds")
                    == {
                        "index_earliest": str(start),
                        "index_latest": str(finish),
                        "earliest_time": event_bounds["earliest_time"],
                        "latest_time": event_bounds["latest_time"],
                    }
                    and job.get("intent_fingerprint") == writer_intent
                ]
            recovery["expected_slices"][intent] = {
                "index_bounds": [start, finish],
                "event_bounds": event_bounds,
                "expected": expected,
                "expected_fingerprint": expected_hash,
                "state": "verified",
                "verified_at": int(self.clock()),
                "manual_job_sids": [
                    job.get("sid")
                    for job in matching_jobs
                    if job.get("state") == "complete" and job.get("sid")
                ],
            }
            if (
                expected
                and len(recovery["expected_slices"][intent]["manual_job_sids"]) != 1
            ):
                raise Refused(
                    "V1 recovery slice has no complete exact-bound writer SID"
                )
            self._write_journal(journal)
            self._verified_v1_manual_recovery_ids(journal, recovery)

        for cycle in cycles:
            bounds = tuple(cycle["index_bounds"])
            key = f"{bounds[0]}:{bounds[1]}"
            expected = validate_expected(
                bounds,
                cycle["event_bounds"],
                f"V1 resumed scheduler expected {bounds[0]}",
            )
            if cycle.get("empty_summary_warning") is True and expected:
                raise Refused(
                    "resumed V1 scheduler reported empty output while source rows exist"
                )
            cumulative_expected = {}
            for item in recovery["expected_slices"].values():
                if item.get("state") == "verified":
                    cumulative_expected = _add_record_maps(
                        cumulative_expected,
                        item.get("expected") or {},
                        label="V1 recovery manual intents",
                    )
            observed_keys = {
                f"{item['index_bounds'][0]}:{item['index_bounds'][1]}"
                for item in cycles
            }
            for scheduled_key, scheduled_item in recovery["scheduler_cycles"].items():
                if scheduled_key not in observed_keys:
                    cumulative_expected = _add_record_maps(
                        cumulative_expected,
                        scheduled_item.get("expected") or {},
                        label="V1 recovery scheduled intents",
                    )
            for observed_cycle in cycles:
                scheduled_map = scheduled_expected[observed_cycle["sid"]]
                cumulative_expected = _add_record_maps(
                    cumulative_expected,
                    scheduled_map,
                    label="V1 observed scheduled recovery intents",
                )
            prior_cycle = recovery["scheduler_cycles"].get(key)
            expected_fingerprint = fingerprint(expected)
            if prior_cycle is not None:
                if (
                    prior_cycle.get("sid") != cycle["sid"]
                    or prior_cycle.get("expected_fingerprint") != expected_fingerprint
                ):
                    raise Refused("V1 scheduled recovery intent changed on resume")
            for attempt in range(1, SUMMARY_INDEX_WAIT_ATTEMPTS + 1):
                actual = self._v1_persisted_rows(
                    journal,
                    cumulative_expected,
                    cycle["event_bounds"],
                    f"V1 resumed scheduler readback {bounds[0]}",
                )
                if actual == cumulative_expected:
                    break
                self._wait_before_summary_retry(attempt)
            if actual != cumulative_expected:
                raise Refused("resumed V1 scheduler output is not completely retained")
            recovery["scheduler_cycles"][key] = {
                "sid": cycle["sid"],
                "index_bounds": list(bounds),
                "event_bounds": cycle["event_bounds"],
                "expected": expected,
                "expected_fingerprint": expected_fingerprint,
                "retained_fingerprint": fingerprint(actual),
                "state": "verified",
                "verified_at": int(self.clock()),
                **(
                    {"empty_summary_proof": empty_proofs[key]}
                    if key in empty_proofs
                    else {}
                ),
            }
            self._write_journal(journal)

        # The first observation drives gap planning; manual backfill runs and
        # readback happen afterwards. Re-inventory at a later, independent
        # boundary so the final raw-index audit includes those writes and
        # accounts for every scheduler dispatch visible through that boundary.
        audit_observation = int(self.clock())
        fresh_cycles = self._scheduled_writer_cycles(
            "ADM - Conversation rollup",
            journal,
            lower_epoch=resume_epoch + 1,
            upper_epoch=audit_observation + 1,
        )
        fresh_keys = [tuple(item["index_bounds"]) for item in fresh_cycles]
        original_keys = [tuple(item["index_bounds"]) for item in cycles]
        if fresh_keys[: len(original_keys)] != original_keys:
            raise Refused("V1 scheduler inventory changed previously validated cycles")
        if len(fresh_keys) > len(original_keys):
            retries = int(recovery.get("inventory_retries", 0)) + 1
            recovery.update(
                audit_observation_epoch=audit_observation,
                inventory_retries=retries,
            )
            self._write_journal(journal)
            if retries > 8:
                raise Refused("V1 scheduler kept advancing during bounded recovery")
            return self._v1_recovery_window(journal, resume_epoch)
        for previous, fresh in zip(cycles, fresh_cycles):
            if previous.get("sid") != fresh.get("sid") or previous.get(
                "event_bounds"
            ) != fresh.get("event_bounds"):
                raise Refused("V1 scheduler slice source bounds changed on re-audit")
        observation = audit_observation
        recovery["audit_observation_epoch"] = observation
        recovery["observation_epoch"] = observation
        self._write_journal(journal)

        expected_all = {}
        for group in (recovery["expected_slices"], recovery["scheduler_cycles"]):
            for item in group.values():
                for rollup_id, row in item["expected"].items():
                    expected_all = _add_record_maps(
                        expected_all,
                        {rollup_id: row},
                        label="V1 recovery source slices",
                    )
        if expected_all:
            query = (
                f'search index={V1_INDEX} source="adm:conversation" '
                f"| where _indextime>={resume_epoch} AND _indextime<={observation} "
                "| fields " + " ".join(V1_ROW_FIELDS)
            )
            retained_rows = self._query(
                journal,
                query,
                0,
                observation + 900,
                label="complete V1 rollback recovery window",
                earliest_time="0",
                latest_time=str(observation + 900),
                persist_result_rows=False,
            )
            retained = self._v1_record_map(retained_rows)
            if retained != expected_all:
                raise Refused(
                    "V1 rollback window has missing or unexplained summary rows"
                )
        else:
            # Empty expected windows must still prove there were no retained rows.
            query = (
                f'search index={V1_INDEX} source="adm:conversation" '
                f"| where _indextime>={resume_epoch} AND _indextime<={observation} "
                "| fields " + " ".join(V1_ROW_FIELDS)
            )
            if self._query(
                journal,
                query,
                0,
                observation + 900,
                label="empty V1 rollback recovery window",
                earliest_time="0",
                latest_time=str(observation + 900),
                persist_result_rows=False,
            ):
                raise Refused(
                    "V1 rollback expected an empty retained window but found rows"
                )
        recovery.update(
            state="verified",
            completed_at=int(self.clock()),
            observed_through=cycles[-1]["index_bounds"][1],
            expected_rollups=len(expected_all),
            expected_fingerprint=fingerprint(expected_all),
            retained_fingerprint=fingerprint(expected_all),
        )
        self._write_journal(journal)
        return recovery

    def _bridge_to_first_scheduled_cycle(
        self, journal: dict[str, Any], scenario: dict[str, Any]
    ) -> bool:
        """Validate every scheduler cycle available through a durable watermark."""
        writer_enable_times = [
            _integer(item.get("verified_at"))
            for item in journal["cutover"]["mutations"]
            if item.get("kind") == "saved_search"
            and item.get("name") in {spec["saved_search"] for spec in STREAMS.values()}
            and _strict_bool(item.get("after")) is False
            and item.get("state") == "applied"
        ]
        if len(writer_enable_times) != len(STREAMS) or any(
            value is None for value in writer_enable_times
        ):
            raise Refused("both V2 writer enablement times are not journaled")
        enabled_after = max(writer_enable_times)
        # Freeze an independent wall-clock boundary before listing jobs. A
        # maximum timestamp from expected rows can hide a later unexpected
        # writer row, so the final index audit is bounded by this observation.
        observed_at = int(self.clock())
        journal["cutover"]["schedule_observation_epoch"] = observed_at
        journal["cutover"]["schedule_observation_recorded_at"] = observed_at
        event_latest = _integer(journal.get("event_latest"))
        journal["event_latest"] = str(max(event_latest or 0, observed_at + 15 * 60))
        self._write_journal(journal)
        cycles_by_stream = {
            stream: self._scheduled_writer_cycles(
                spec["saved_search"],
                journal,
                lower_epoch=enabled_after + 1,
                upper_epoch=observed_at + 1,
            )
            for stream, spec in STREAMS.items()
        }
        history_enabled_after = self._history_writer_activation_epoch(journal)
        history_cycles = (
            self._scheduled_history_cycles(
                journal,
                lower_epoch=history_enabled_after,
                upper_epoch=observed_at + 1,
            )
            if history_enabled_after is not None
            else []
        )
        cycle_keys = {
            stream: [tuple(cycle["index_bounds"]) for cycle in cycles]
            for stream, cycles in cycles_by_stream.items()
        }
        if any(not cycles for cycles in cycles_by_stream.values()) or (
            history_enabled_after is not None and not history_cycles
        ):
            journal["cutover"]["state"] = "awaiting_first_scheduled_cycle"
            journal["cutover"]["scheduled_cycle_checked_at"] = int(self.clock())
            journal["cutover"]["scheduled_cycle_evidence"] = cycle_keys
            journal["cutover"]["history_cycle_evidence"] = [
                cycle["index_bounds"] for cycle in history_cycles
            ]
            self._write_journal(journal)
            return False
        if len({tuple(value) for value in cycle_keys.values()}) != 1:
            raise Refused("V2 scheduled writers do not share the same completed slices")
        common_bounds = [tuple(value) for value in cycle_keys.values()][0]
        if not common_bounds:
            return False
        expected_first_anchor = (enabled_after // SLICE_SECONDS + 1) * SLICE_SECONDS
        if common_bounds[0][0] + 2 * SLICE_SECONDS != expected_first_anchor:
            raise Refused("first scheduled V2 cycle is missing after writer enablement")
        if history_enabled_after is not None:
            expected_history_anchor = self._history_next_anchor(history_enabled_after)
            if history_cycles[0]["anchor"] != expected_history_anchor:
                raise Refused("first scheduled history builder cycle is missing")
            self._stage_scheduled_history_evidence(journal, history_cycles)
            self._stage_history_gap_before_first_cycle(
                journal,
                int(history_cycles[0]["index_bounds"][0]),
            )
        empty_proofs = journal["cutover"].setdefault("empty_summary_proofs", {})
        cycle_expected: dict[str, dict[str, dict[str, Any]]] = {
            stream: {} for stream in cycles_by_stream
        }
        for stream, cycles in cycles_by_stream.items():
            spec = STREAMS[stream]
            for cycle in cycles:
                query = (
                    self._writer_query(spec, journal)
                    + " | fields "
                    + " ".join(V2_ROW_FIELDS[stream])
                )
                rows = self._query(
                    journal,
                    query,
                    cycle["index_bounds"][0],
                    cycle["index_bounds"][1],
                    label=f"scheduled {stream} manifest {cycle['index_bounds'][0]}",
                    earliest_time=cycle["event_bounds"]["earliest_time"],
                    latest_time=cycle["event_bounds"]["latest_time"],
                )
                cycle_expected[stream][cycle["sid"]] = self._record_map(rows, stream)

        def expected_with_observed_schedules(stream: str) -> dict[str, Any]:
            combined = self._cumulative_v2_expected(journal, stream)
            recorded_bounds = {
                tuple(item.get("index_bounds", []))
                for item in (
                    journal["cutover"]
                    .get("scheduled_streams", {})
                    .get(stream, {})
                    .get("cycles", [])
                )
            }
            for observed_cycle in cycles_by_stream[stream]:
                if tuple(observed_cycle["index_bounds"]) in recorded_bounds:
                    continue
                combined = _add_record_maps(
                    combined,
                    cycle_expected[stream][observed_cycle["sid"]],
                    label=f"V2 observed scheduled {stream} intents",
                )
            return combined

        allowed_v2_ids = {
            rollup_id
            for expected_by_sid in cycle_expected.values()
            for expected_rows in expected_by_sid.values()
            for rollup_id in expected_rows
        }
        for slice_record in journal.get("slices", []):
            for stream in STREAMS:
                allowed_v2_ids.update(
                    (slice_record.get("streams", {}).get(stream) or {})
                    .get("expected", {})
                    .keys()
                )
        for stream, cycles in cycles_by_stream.items():
            spec = STREAMS[stream]
            for cycle in cycles:
                if cycle.get("empty_summary_warning") is not True:
                    continue
                bounds = tuple(cycle["index_bounds"])
                proof_key = f"{stream}:{cycle['sid']}"
                prior = empty_proofs.get(proof_key)
                if prior is not None:
                    if prior.get("index_bounds") != list(bounds):
                        raise Refused("V2 empty-cycle proof bounds changed on resume")
                    continue
                if cycle_expected[stream][cycle["sid"]]:
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
                proof = self._assert_empty_summary_index_window(
                    journal,
                    V2_INDEX,
                    spec["source"],
                    int(cycle["anchor"]),
                    observed_at,
                    f"empty scheduled {stream} retained-row audit {bounds[0]}",
                    allowed_rollup_ids=allowed_v2_ids,
                )
                empty_proofs[proof_key] = {
                    "sid": cycle["sid"],
                    "index_bounds": list(bounds),
                    **proof,
                }
                self._write_journal(journal)
        # Stage each gap once, then validate both writers for the same cycle
        # before moving the range watermark. Processing a stream at a time
        # used to advance `range.end` on the first stream and make the second
        # stream look like an overlap on every real non-empty handoff.
        staged_extra = sum(
            1 for item in journal["slices"] if item.get("handoff_bridge") is True
        )
        prior_by_stream = {
            stream: {
                tuple(item.get("index_bounds", [])): item
                for item in (
                    journal["cutover"]
                    .get("scheduled_streams", {})
                    .get(stream, {})
                    .get("cycles", [])
                )
            }
            for stream in STREAMS
        }
        for cycle_bounds in common_bounds:
            start, end = cycle_bounds
            range_end = int(journal["range"]["end"])
            previously_checkpointed = end <= range_end
            if start < range_end and not previously_checkpointed:
                raise Refused("scheduled V2 slice overlaps a staged or earlier slice")
            if previously_checkpointed:
                for stream, cycles in cycles_by_stream.items():
                    cycle = next(
                        item
                        for item in cycles
                        if tuple(item["index_bounds"]) == cycle_bounds
                    )
                    prior = prior_by_stream[stream].get(cycle_bounds)
                    if (
                        not isinstance(prior, dict)
                        or prior.get("sid") != cycle.get("sid")
                        or prior.get("event_bounds") != cycle.get("event_bounds")
                        or prior.get("index_bounds") != list(cycle_bounds)
                    ):
                        raise Refused(
                            "scheduled V2 cycle overlaps the staged range without matching durable evidence"
                        )
                    spec = STREAMS[stream]
                    query = (
                        self._writer_query(spec, journal)
                        + " | fields "
                        + " ".join(V2_ROW_FIELDS[stream])
                    )
                    expected_rows = self._query(
                        journal,
                        query,
                        start,
                        end,
                        label=f"resumed scheduled {stream} expected output {start}",
                        earliest_time=cycle["event_bounds"]["earliest_time"],
                        latest_time=cycle["event_bounds"]["latest_time"],
                    )
                    expected = self._record_map(expected_rows, stream)
                    if cycle.get("empty_summary_warning") is True and expected:
                        raise Refused(
                            "scheduled writer reported empty output while source rows exist"
                        )
                    if cycle.get("empty_summary_warning") is True and not isinstance(
                        prior.get("empty_summary_proof"), dict
                    ):
                        raise Refused(
                            "empty scheduled writer has no independent retained-index proof"
                        )
                    cumulative_expected = expected_with_observed_schedules(stream)
                    actual = self._poll_persisted_rows(
                        journal,
                        cumulative_expected,
                        stream,
                        label=f"resumed scheduled {stream} output {start}",
                    )
                    if actual != cumulative_expected or fingerprint(
                        expected
                    ) != prior.get("expected_fingerprint"):
                        raise Refused(
                            "previously checkpointed scheduled V2 evidence changed"
                        )
                continue
            if start > range_end:
                gap = plan_slices(range_end, start, int(self.clock()))
                if not gap or gap[0]["start"] != range_end or gap[-1]["end"] != start:
                    raise Refused("scheduled V2 handoff gap is not fully sliceable")
                by_bounds = {
                    (item.get("start"), item.get("end")): item
                    for item in journal["slices"]
                    if item.get("handoff_bridge") is True
                }
                bridge_slices = []
                for time_slice in gap:
                    key = (time_slice["start"], time_slice["end"])
                    slice_record = by_bounds.get(key)
                    if slice_record is None:
                        slice_record = {
                            **time_slice,
                            "streams": {name: {"state": "pending"} for name in STREAMS},
                            "history": {"state": "pending"},
                            "handoff_bridge": True,
                        }
                        journal["slices"].append(slice_record)
                        by_bounds[key] = slice_record
                        staged_extra += 1
                        self._write_journal(journal)
                    bridge_slices.append(slice_record)
                for slice_record in bridge_slices:
                    for bridge_stream in STREAMS:
                        recorded_bounds = {
                            tuple(item.get("index_bounds", []))
                            for item in (
                                journal["cutover"]
                                .get("scheduled_streams", {})
                                .get(bridge_stream, {})
                                .get("cycles", [])
                            )
                        }
                        observed_manifests = [
                            cycle_expected[bridge_stream][cycle["sid"]]
                            for cycle in cycles_by_stream[bridge_stream]
                            if tuple(cycle["index_bounds"]) not in recorded_bounds
                        ]
                        self._stage_stream(
                            journal,
                            slice_record,
                            bridge_stream,
                            observed_scheduled_expected=observed_manifests,
                        )
                    self._stage_history_slice(journal, slice_record)

            cycle_evidence = {}
            for stream, cycles in cycles_by_stream.items():
                cycle = next(
                    item
                    for item in cycles
                    if tuple(item["index_bounds"]) == cycle_bounds
                )
                spec = STREAMS[stream]
                query = (
                    self._writer_query(spec, journal)
                    + " | fields "
                    + " ".join(V2_ROW_FIELDS[stream])
                )
                expected_rows = self._query(
                    journal,
                    query,
                    start,
                    end,
                    label=f"scheduled {stream} expected output {start}",
                    earliest_time=cycle["event_bounds"]["earliest_time"],
                    latest_time=cycle["event_bounds"]["latest_time"],
                )
                expected = self._record_map(expected_rows, stream)
                if cycle.get("empty_summary_warning") is True and expected:
                    raise Refused(
                        "scheduled writer reported empty output while source rows exist"
                    )
                actual = self._poll_persisted_rows(
                    journal,
                    expected_with_observed_schedules(stream),
                    stream,
                    label=f"scheduled {stream} output {start}",
                )
                cumulative_expected = expected_with_observed_schedules(stream)
                if actual != cumulative_expected:
                    raise Refused(
                        f"scheduled {stream} output is not fully indexed and validated"
                    )
                cycle_evidence[stream] = {
                    "state": "verified",
                    **cycle,
                    "expected": expected,
                    "expected_fingerprint": fingerprint(expected),
                    "actual_fingerprint": fingerprint(actual),
                    "rows": len(expected),
                    "validated_at": int(self.clock()),
                    **(
                        {
                            "empty_summary_proof": empty_proofs[
                                f"{stream}:{cycle['sid']}"
                            ]
                        }
                        if cycle.get("empty_summary_warning") is True
                        else {}
                    ),
                }

            for stream, evidence in cycle_evidence.items():
                journal["cutover"].setdefault("scheduled_streams", {}).setdefault(
                    stream, {"cycles": []}
                )["cycles"].append(evidence)
            journal["range"]["end"] = end
            self._write_journal(journal)
        for stream in STREAMS:
            recorded = [
                tuple(cycle["index_bounds"])
                for cycle in journal["cutover"]["scheduled_streams"][stream]["cycles"]
            ]
            if recorded != list(common_bounds):
                raise Refused("scheduled writer evidence is missing a contiguous cycle")
        journal["cutover"]["bridge_slices"] = staged_extra
        journal["cutover"]["manual_bridge_writes"] = [
            {
                "index_bounds": [item["start"], item["end"]],
                "history_fingerprint": item.get("history", {}).get(
                    "actual_fingerprint"
                ),
                "stream_fingerprints": {
                    stream: item.get("streams", {})
                    .get(stream, {})
                    .get("actual_fingerprint")
                    for stream in STREAMS
                },
                "job_sids": [
                    job.get("sid")
                    for job in journal.get("jobs", [])
                    if job.get("state") == "complete"
                    and job.get("request_bounds", {}).get("index_earliest")
                    == str(item["start"])
                    and job.get("request_bounds", {}).get("index_latest")
                    == str(item["end"])
                ],
            }
            for item in journal["slices"]
            if item.get("handoff_bridge") is True
        ]
        journal["cutover"]["state"] = "validating_scheduled_cycles"

        # Manual bridge output is written after the first schedule inventory.
        # Take a later independent boundary, then inventory scheduler jobs
        # again through that boundary before auditing the summary index. This
        # both covers the manual SIDs and proves there is no unaccounted
        # scheduled writer output after the initial inventory.
        if history_enabled_after is not None:
            self._stage_history_tail_through_summary(journal, int(common_bounds[-1][1]))
        audit_observed_at = int(self.clock())
        fresh_cycles = {
            stream: self._scheduled_writer_cycles(
                spec["saved_search"],
                journal,
                lower_epoch=enabled_after + 1,
                upper_epoch=audit_observed_at + 1,
            )
            for stream, spec in STREAMS.items()
        }
        fresh_history_cycles = (
            self._scheduled_history_cycles(
                journal,
                lower_epoch=history_enabled_after,
                upper_epoch=audit_observed_at + 1,
            )
            if history_enabled_after is not None
            else []
        )
        fresh_bounds = {
            stream: [tuple(item["index_bounds"]) for item in cycles]
            for stream, cycles in fresh_cycles.items()
        }
        if any(
            bounds != fresh_bounds[next(iter(STREAMS))]
            for bounds in fresh_bounds.values()
        ):
            raise Refused("V2 scheduler inventories disagree at the audit boundary")
        latest_bounds = next(iter(fresh_bounds.values()))
        if latest_bounds[: len(common_bounds)] != list(common_bounds):
            raise Refused("V2 scheduler inventory changed previously validated cycles")
        if len(latest_bounds) > len(common_bounds):
            retries = int(journal["cutover"].get("bridge_inventory_retries", 0)) + 1
            journal["cutover"].update(
                schedule_observation_epoch=audit_observed_at,
                schedule_observation_recorded_at=audit_observed_at,
                bridge_inventory_retries=retries,
            )
            self._write_journal(journal)
            if retries > 8:
                raise Refused(
                    "V2 scheduler kept advancing during bounded migration audit"
                )
            return self._bridge_to_first_scheduled_cycle(journal, scenario)
        if history_enabled_after is not None:
            current_history = [tuple(item["index_bounds"]) for item in history_cycles]
            latest_history = [
                tuple(item["index_bounds"]) for item in fresh_history_cycles
            ]
            if latest_history[: len(current_history)] != current_history:
                raise Refused("history scheduler inventory changed validated cycles")
            if len(latest_history) > len(current_history):
                retries = (
                    int(journal["cutover"].get("history_inventory_retries", 0)) + 1
                )
                journal["cutover"].update(
                    history_observation_epoch=audit_observed_at,
                    history_inventory_retries=retries,
                )
                self._write_journal(journal)
                if retries > 8:
                    raise Refused(
                        "history scheduler kept advancing during bounded migration audit"
                    )
                return self._bridge_to_first_scheduled_cycle(journal, scenario)
            for previous, current in zip(history_cycles, fresh_history_cycles):
                if (
                    previous["sid"] != current["sid"]
                    or previous["event_bounds"] != current["event_bounds"]
                ):
                    raise Refused("history scheduler source bounds changed on re-audit")
            self._stage_scheduled_history_evidence(journal, fresh_history_cycles)
            journal["cutover"]["history_observation_epoch"] = audit_observed_at
            journal["cutover"]["scheduled_history"]["observation_epoch"] = (
                audit_observed_at
            )
        for stream, cycles in fresh_cycles.items():
            for cycle in cycles:
                if tuple(cycle["index_bounds"]) not in common_bounds:
                    raise Refused("V2 scheduler audit found an unvalidated cycle")
                prior = {
                    tuple(item.get("index_bounds", [])): item
                    for item in journal["cutover"]
                    .get("scheduled_streams", {})
                    .get(stream, {})
                    .get("cycles", [])
                }.get(tuple(cycle["index_bounds"]))
                if prior and (
                    prior.get("sid") != cycle.get("sid")
                    or prior.get("event_bounds") != cycle.get("event_bounds")
                ):
                    raise Refused(
                        "V2 scheduled cycle source bounds changed on re-audit"
                    )
        journal["cutover"]["schedule_observation_epoch"] = audit_observed_at
        journal["cutover"]["schedule_observation_recorded_at"] = audit_observed_at
        journal["event_latest"] = str(
            max(int(journal["event_latest"]), audit_observed_at + 15 * 60)
        )
        self._write_journal(journal)
        # Refresh history/catalog/public-surface evidence against all bridged
        # and scheduler-produced rows. The ingestion audit uses the journaled
        # row-derived watermark, so later ordinary scheduler writes are outside
        # this completed migration window.
        self.validate(scenario)
        journal = self._load()
        journal["cutover"]["scheduled_cycle_bounds"] = {
            "index_earliest": common_bounds[0][0],
            "index_latest": common_bounds[-1][1],
        }
        journal["cutover"]["scheduled_watermark_at"] = int(self.clock())
        journal["cutover"]["state"] = "scheduled_cycle_validated"
        self._write_journal(journal)
        return True

    def cutover(self) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        if journal.get("phase") not in {"coverage_validated", "cutover_in_progress"}:
            if journal.get("phase") == "cutover":
                self._assert_cutover_origin_compatible(journal)
                for mutation in (journal.get("cutover") or {}).get("mutations", []):
                    if not self._mutation_equal(
                        mutation,
                        self._mutation_target(mutation)["value"],
                        mutation["after"],
                    ):
                        raise Refused(
                            "completed cutover is no longer fully active; reconcile the journaled target"
                        )
                return {"status": "cutover", "migration_id": journal["migration_id"]}
            raise Refused("coverage must be validated before cutover")
        # Derived from the locked journal, never from a path stored in it.
        candidate_path = self.journal.path.with_suffix(".candidate.json")
        try:
            candidate_bytes = self._read_result_artifact_file(
                candidate_path, MAX_CANDIDATE_BYTES
            )
            candidate = json.loads(candidate_bytes)
        except (Refused, UnicodeError, json.JSONDecodeError):
            raise Refused("validated candidate evidence is unavailable") from None
        if hashlib.sha256(candidate_bytes).hexdigest() != journal.get(
            "candidate_sha256"
        ):
            raise Refused("validated candidate evidence changed")
        if (
            not isinstance(candidate, dict)
            or candidate.get("migration_id") != journal.get("migration_id")
            or candidate.get("interface_sha256") != journal.get("interface_sha256")
            or candidate.get("origin_fingerprint") != journal.get("origin_fingerprint")
            or candidate.get("cutover_eligible") is not True
        ):
            raise Refused(
                "catalog, topology, Find, health, drilldown and public reader smoke evidence is incomplete"
            )
        scenario = candidate.get("scenario")
        if not isinstance(scenario, dict) or fingerprint(scenario) != candidate.get(
            "scenario_sha256"
        ):
            raise Refused(
                "candidate does not contain its deployment validation scenario"
            )
        interface, _ = self._interface()
        if journal.get("phase") == "coverage_validated":
            self._assert_origin_unchanged(journal)
            legacy_enabled = (
                (journal.get("origin") or {})
                .get("saved_searches", {})
                .get("ADM - Conversation rollup", {})
                .get("content", {})
                .get("disabled")
            )
            if _strict_bool(legacy_enabled) is False and not isinstance(
                journal.get("v1_pre_pause"), dict
            ):
                self._capture_v1_pre_pause(journal)
            mutations = self._build_cutover_mutations(journal, interface)
            journal["cutover"] = {
                "state": "in_progress",
                "started_at": int(self.clock()),
                "mutations": mutations,
                "scenario_sha256": candidate["scenario_sha256"],
                "scenario": scenario,
            }
            journal["phase"] = "cutover_in_progress"
            self._write_journal(journal)
        else:
            self._assert_cutover_origin_compatible(journal)
            mutations = journal.get("cutover", {}).get("mutations")
            if not isinstance(mutations, list) or not mutations:
                raise Refused(
                    "partial cutover journal has no allowlisted mutation plan"
                )
        mutation_ids = [item["id"] for item in mutations]
        for mutation_id in mutation_ids:
            # Always mutate the object held by the latest durable journal. The
            # catch-up validation below rewrites the journal, so references
            # captured before that point are stale and would lose readbacks.
            journal = self._load()
            mutations = journal.get("cutover", {}).get("mutations", [])
            mutation = next(
                (item for item in mutations if item.get("id") == mutation_id), None
            )
            if mutation is None:
                raise Refused("cutover mutation disappeared from its journal")
            if (
                mutation.get("name") == "ADM - Conversation rollup"
                and mutation.get("field") == "disabled"
                and _strict_bool(mutation.get("after")) is True
                and (journal.get("origin") or {})
                .get("saved_searches", {})
                .get("ADM - Conversation rollup", {})
                .get("content", {})
                .get("disabled")
                is not None
                and _strict_bool(
                    journal["origin"]["saved_searches"]["ADM - Conversation rollup"][
                        "content"
                    ]["disabled"]
                )
                is False
                and not isinstance(journal.get("v1_pre_pause"), dict)
            ):
                self._capture_v1_pre_pause(journal)
                journal = self._load()
                mutation = next(
                    item
                    for item in journal["cutover"]["mutations"]
                    if item["id"] == mutation_id
                )
            if mutation["kind"] == "macro_definition" and not journal["cutover"].get(
                "scheduled_cycle_bounds"
            ):
                if not self._bridge_to_first_scheduled_cycle(journal, scenario):
                    return {
                        "status": "awaiting_first_scheduled_cycle",
                        "migration_id": journal["migration_id"],
                    }
                journal = self._load()
                mutation = next(
                    item
                    for item in journal["cutover"]["mutations"]
                    if item["id"] == mutation_id
                )
            self._assert_cutover_origin_compatible(journal)
            self._apply_mutation(journal, mutation)
            if mutation.get("drain_after") and not journal["cutover"].get(
                "post_pause_validation_at"
            ):
                self._drain_legacy_writer(journal)
                self._catch_up_after_pause(journal, scenario)
                journal = self._load()
                mutations = journal["cutover"]["mutations"]
        journal = self._load()
        if not journal["cutover"].get("scheduled_cycle_bounds"):
            raise Refused("first scheduled v2 writer cycle is not validated")
        journal["cutover"]["public_selector_evidence"] = self._public_selector_smoke(
            journal,
            interface,
            scenario,
            phase="public_after_invoke",
        )
        journal["phase"] = "cutover"
        journal["cutover"].update(state="complete", completed_at=int(self.clock()))
        self._write_journal(journal)
        return {"status": "cutover", "migration_id": journal["migration_id"]}

    def rollback(self) -> dict[str, Any]:
        self.qualify()
        journal = self._load()
        if journal.get("phase") not in {
            "cutover",
            "cutover_in_progress",
            "rollback_in_progress",
        }:
            raise Refused(
                "rollback is available only for a journaled complete or partial cutover"
            )
        origin_legacy = (
            (journal.get("origin") or {})
            .get("saved_searches", {})
            .get("ADM - Conversation rollup", {})
            .get("content", {})
            .get("disabled")
        )
        if _strict_bool(origin_legacy) is False:
            if not isinstance(journal.get("v1_pre_pause"), dict):
                raise Refused(
                    "enabled-origin rollback lacks a validated pre-pause V1 slice"
                )
            # request_pending, request_unknown, readback_failed and applied may
            # all have enabled V1 and must reach the reconcile path below. A
            # not-started request proves nothing by itself, and a rejected one
            # only means the readback differed (e.g. ACL) while the value may
            # already equal the target, so a live read decides both.
            v1_resume = next(
                (
                    item
                    for item in (journal.get("rollback") or {}).get("mutations", [])
                    if item.get("name") == "ADM - Conversation rollup"
                    and item.get("field") == "disabled"
                ),
                None,
            )
            v1_possibly_resumed = v1_resume is not None and (
                v1_resume.get("state") not in {"pending", "rejected"}
                or not self._mutation_equal(
                    v1_resume,
                    self._mutation_target(v1_resume)["value"],
                    v1_resume["before"],
                )
            )
            pre_end = _integer(
                (journal["v1_pre_pause"].get("index_bounds") or [None, None])[-1]
            )
            if pre_end is None:
                raise Refused(
                    "enabled-origin rollback lacks a validated pre-pause V1 slice"
                )
            if not v1_possibly_resumed and (
                rollback_recovery_horizon_seconds(int(self.clock()) - pre_end)
                > MAX_BACKFILL_SECONDS
            ):
                consequence = (
                    "the journal stays rollback_in_progress with V1 paused and V2 public"
                    if journal.get("phase") == "rollback_in_progress"
                    else "nothing was changed"
                )
                raise Refused(
                    "enabled-origin rollback can no longer recover the paused V1 "
                    "window and finish inside the seven-day bound (the gap slices "
                    "are written one search each, so the required time grows with "
                    f"the gap); {consequence}. See 'If rollback refuses on the "
                    "seven-day bound' in docs/CISCO_CONTRACT_MIGRATION.md"
                )
        if journal.get("phase") == "rollback_in_progress":
            rollback_mutations = journal.get("rollback", {}).get("mutations", [])
        else:
            self._assert_cutover_origin_compatible(journal)
            forward = journal.get("cutover", {}).get("mutations")
            if not isinstance(forward, list) or not forward:
                raise Refused("cutover journal has no mutation plan to restore")
            rollback_mutations = []
            for mutation in reversed(forward):
                reverse = {
                    key: mutation[key]
                    for key in (
                        "id",
                        "kind",
                        "name",
                        "rest_target",
                        "field",
                        "acl",
                        "args",
                    )
                    if key in mutation
                }
                reverse.update(
                    before=mutation["after"],
                    after=mutation["before"],
                    state="pending",
                    drain_after=False,
                )
                rollback_mutations.append(reverse)
            journal["rollback"] = {
                "state": "in_progress",
                "started_at": int(self.clock()),
                "mutations": rollback_mutations,
            }
            journal["phase"] = "rollback_in_progress"
            self._write_journal(journal)

        if _strict_bool(origin_legacy) is False:
            # Resume only the immutable V1 writer first. Keep public V2
            # selectors and V2 writers in their cutover state until every
            # missed raw slice and the first resumed scheduler boundary have
            # exact expected-versus-retained coverage.
            v1_mutation = next(
                (
                    item
                    for item in rollback_mutations
                    if item.get("kind") == "saved_search"
                    and item.get("name") == "ADM - Conversation rollup"
                    and item.get("field") == "disabled"
                ),
                None,
            )
            if v1_mutation is None:
                raise Refused("rollback plan has no V1 writer resume mutation")
            journal = self._load()
            v1_mutation = next(
                item
                for item in journal["rollback"]["mutations"]
                if item.get("id") == v1_mutation["id"]
            )
            self._assert_cutover_origin_compatible(journal)
            if v1_mutation.get("state") != "applied":
                self._apply_mutation(journal, v1_mutation)
            journal = self._load()
            v1_mutation = next(
                item
                for item in journal["rollback"]["mutations"]
                if item.get("name") == "ADM - Conversation rollup"
                and item.get("field") == "disabled"
            )
            resume_epoch = _integer(
                journal.get("rollback", {})
                .get("v1_recovery", {})
                .get("resume_activation_epoch")
            )
            if resume_epoch is None:
                resume_epoch = _integer(v1_mutation.get("verified_at"))
                if resume_epoch is None:
                    raise Refused("V1 writer resume time is not durably verified")
                journal["rollback"].setdefault("v1_recovery", {})[
                    "resume_activation_epoch"
                ] = resume_epoch
                self._write_journal(journal)
            recovery = self._v1_recovery_window(journal, resume_epoch)
            if recovery is None:
                journal = self._load()
                journal["rollback"]["state"] = "awaiting_v1_recovery"
                journal["rollback"]["checked_at"] = int(self.clock())
                self._write_journal(journal)
                return {
                    "status": "awaiting_v1_recovery",
                    "migration_id": journal["migration_id"],
                }
            rollback_mutations = journal["rollback"].get("mutations", [])

        rollback_ids = [item.get("id") for item in rollback_mutations]
        if any(not isinstance(item, str) for item in rollback_ids):
            raise Refused("rollback journal contains a malformed mutation")
        for mutation_id in rollback_ids:
            journal = self._load()
            rollback_mutations = journal.get("rollback", {}).get("mutations", [])
            mutation = next(
                (item for item in rollback_mutations if item.get("id") == mutation_id),
                None,
            )
            if mutation is None:
                raise Refused("rollback mutation disappeared from its journal")
            if (
                _strict_bool(origin_legacy) is False
                and mutation.get("name") == "ADM - Conversation rollup"
                and mutation.get("field") == "disabled"
                and mutation.get("state") == "applied"
            ):
                continue
            self._assert_cutover_origin_compatible(journal)
            self._apply_mutation(journal, mutation)
        interface, _ = self._interface()
        scenario = journal.get("cutover", {}).get("scenario")
        if not isinstance(scenario, dict):
            raise Refused("rollback journal has no public validation scenario")
        journal["rollback"]["public_selector_evidence"] = self._public_selector_smoke(
            journal,
            interface,
            scenario,
            phase="rollback_before_invoke",
        )
        journal["phase"] = "rolled_back"
        journal["rollback"].update(state="complete", completed_at=int(self.clock()))
        self._write_journal(journal)
        return {"status": "rolled_back", "migration_id": journal["migration_id"]}


def _api_from_stdin(uri: str, ca_file: str | None):
    if not sys.stdin.isatty():
        token = sys.stdin.readline().strip()
    else:
        import getpass

        token = getpass.getpass("Splunk session key: ")
    if not token or "\n" in token or "\r" in token:
        raise Refused("session key must be supplied via stdin")
    bin_root = ROOT / "splunk_app" / "splunk_adm" / "bin"
    sys.path.insert(0, str(bin_root))
    sys.path.insert(0, str(bin_root / "lib"))
    from adm_recovery_lib.rest import Rest

    return Rest(token, uri=uri, ca_file=ca_file)


def _read_scenario(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        info = path.lstat()
        if (
            not path.is_file()
            or path.is_symlink()
            or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise Refused(
                "scenario must be an owner-only regular JSON file under 64 KiB"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except Refused:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise Refused("validation scenario is unreadable or invalid JSON") from None
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise Refused(
            "validation scenario must map string field names to string values"
        )
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, default=JOURNAL_DEFAULT)
    parser.add_argument("--management-uri", default="https://localhost:8089")
    parser.add_argument("--ca-file")
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare")
    prepare.add_argument(
        "--start", required=True, type=int, help="inclusive UTC epoch, 5-minute aligned"
    )
    prepare.add_argument(
        "--end", required=True, type=int, help="exclusive UTC epoch, 5-minute aligned"
    )
    actions.add_parser("backfill")
    reconcile = actions.add_parser("reconcile")
    reconcile.add_argument(
        "--sid", required=True, help="operator-discovered SID for an ambiguous dispatch"
    )
    validate = actions.add_parser("validate")
    validate.add_argument(
        "--scenario", type=Path, help="owner-only deployment validation scenario JSON"
    )
    actions.add_parser("cutover")
    actions.add_parser("rollback")
    actions.add_parser("status")
    args = parser.parse_args(argv)
    try:
        journal = Journal(args.journal)
        if args.action == "status":
            print(
                json.dumps(
                    journal.read() or {"status": "uninitialized"},
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        api = _api_from_stdin(args.management_uri, args.ca_file)
        migration = Migration(api, journal)
        with migration.operation_locked():
            if args.action == "prepare":
                result = migration.prepare(args.start, args.end)
            elif args.action == "backfill":
                result = migration.backfill()
            elif args.action == "reconcile":
                result = migration.reconcile(args.sid)
            elif args.action == "validate":
                result = migration.validate(_read_scenario(args.scenario))
            elif args.action == "cutover":
                result = migration.cutover()
            elif args.action == "rollback":
                result = migration.rollback()
            else:
                result = journal.read() or {"status": "uninitialized"}
    except MigrationError as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True))
        return 2
    except OSError as exc:
        reason = f"local file or TLS setup failed: {exc.strerror or type(exc).__name__}"
        print(json.dumps({"status": "refused", "reason": reason}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
