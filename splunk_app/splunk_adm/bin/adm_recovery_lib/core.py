"""Bounded, opt-in automated assisted recovery for qualified standalone Splunk.

Claims are insert-only. Unknown outcomes never retry a dispatch or reclaim a
lease. Milestone 1 leaves uncertain records for manual reconciliation; there
is intentionally no supervisor or crash takeover here.
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
import time
from urllib.parse import quote, urlencode
import uuid

from .planner import TARGET_WINDOWS, build_recovery_plan, validate_recovery_plan
from .rest import ApiError, is_transport_timeout

APP = "/servicesNS/nobody/splunk_adm"
STATE = APP + "/storage/collections/data/adm_recovery_state"
AUDIT = APP + "/storage/collections/data/adm_recovery_audit"
ROLLUP = "ADM - Conversation rollup"
# Must equal adm_settings_lib.rest.QUALIFIED_VERSIONS; each patch is live-qualified.
QUALIFIED_VERSIONS = frozenset({"10.6.0.5"})
FIELDS = (
    "search",
    "cron_schedule",
    "disabled",
    "is_scheduled",
    "dispatchAs",
    "dispatch.earliest_time",
    "dispatch.latest_time",
    "dispatch.index_earliest",
    "dispatch.index_latest",
    "realtime_schedule",
)


class Refused(RuntimeError):
    pass


class Uncertain(RuntimeError):
    pass


def truth(value):
    return str(value).lower() in ("1", "true")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def slot_key(target, scheduled_time):
    return "slot_" + digest([target, int(scheduled_time)])


def target_key(target):
    return "target_" + digest(target)


@dataclass
class Settings:
    enabled: bool = False
    initial_backlog_limit: int = 4
    total_slot_limit: int = 8
    slot_timeout_seconds: int = 120
    pause_cap_seconds: int = 1080
    action_deadline_seconds: int = 1260
    lease_seconds: int = 1800
    preflight_seconds: int = 60
    cleanup_seconds: int = 120
    manifest_count_limit: int = 10000

    def validate(self):
        ceilings = Settings()
        for key, value in vars(self).items():
            if key in ("enabled", "lease_seconds"):
                continue
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > getattr(ceilings, key)
            ):
                raise Refused("budget outside qualified limits: " + key)
        if self.lease_seconds != 1800:
            raise Refused("fixed 30-minute lease is required")
        if self.total_slot_limit < self.initial_backlog_limit:
            raise Refused("total slot budget must cover the initial backlog budget")


class Recovery:
    def __init__(
        self,
        api,
        settings=None,
        wall=time.time,
        monotonic=time.monotonic,
        sleep=time.sleep,
    ):
        self.api = api
        self.settings = settings or Settings()
        self.wall, self.clock, self.sleep = wall, monotonic, sleep
        self.owner = uuid.uuid4().hex
        self.started = self.clock()
        self.deadline = self.started + self.settings.preflight_seconds
        self.lock = None
        self.current = None
        self.unknown_dispatch = False
        self.active_sid = None
        self.completed = []
        self.slot_seconds = 0.0

    def request(self, method, path, data=None, json_body=False):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise Uncertain("invocation deadline reached")
        request_timeout = min(30, remaining)
        try:
            return self.api.request(
                method,
                path,
                data=data,
                json_body=json_body,
                timeout=request_timeout,
            )
        except Exception as exc:
            if is_transport_timeout(exc):
                reason = (
                    "invocation deadline reached"
                    if request_timeout == remaining or self.clock() >= self.deadline
                    else "management request timed out"
                )
                raise Uncertain(reason) from None
            raise

    def audit(self, event, **fields):
        record = {
            "_key": uuid.uuid4().hex,
            "owner": self.owner,
            "event": event,
            "time": self.wall(),
            **fields,
        }
        self.request("POST", AUDIT, record, json_body=True)

    def state(self, key):
        try:
            return self.request("GET", STATE + "/" + quote(key, safe=""))
        except ApiError as exc:
            if exc.status == 404:
                return None
            raise

    def insert(self, record):
        try:
            self.request("POST", STATE, record, json_body=True)
        except ApiError as exc:
            if exc.status == 409:
                raise Refused("existing claim; no takeover") from None
            raise
        if self.state(record["_key"]).get("owner") != self.owner:
            raise Uncertain("claim readback does not match owner")

    def save(self, record, **changes):
        persisted = self.state(record["_key"])
        if (
            not persisted
            or persisted.get("owner") != self.owner
            or self.wall() >= record["expires_at"]
        ):
            raise Uncertain("claim ownership or lease is no longer valid")
        record.update(changes, updated=self.wall())
        self.request("POST", STATE + "/" + record["_key"], record, json_body=True)
        self.audit(
            record["state"],
            name=record["name"],
            scheduled_time=record.get("scheduled_time"),
            sid=record.get("sid"),
            earliest=record.get("earliest"),
            latest=record.get("latest"),
            index_earliest=record.get("index_earliest"),
            index_latest=record.get("index_latest"),
            configuration=record.get("configuration"),
            before=record.get("before"),
            changed_fields=record.get("changed_fields"),
            local_override_retained=record.get("local_override_retained"),
        )

    def target(self, name):
        return self.request("GET", APP + "/saved/searches/" + quote(name, safe=""))[
            "entry"
        ][0]

    @staticmethod
    def snapshot(entry):
        content = entry["content"]
        return {
            key: str(int(content[key]))
            if isinstance(content.get(key), bool)
            else str(content.get(key, ""))
            for key in FIELDS
        }

    def configuration(self):
        entries = self.request("GET", APP + "/configs/conf-macros?count=0")["entry"]
        return digest(
            sorted(
                (entry["name"], entry["content"].get("definition", ""))
                for entry in entries
            )
        )

    def qualify_deployment(self):
        """Require the observed standalone shape before any recovery mutation.

        A version match and a missing SHC flag alone are insufficient: a Cloud
        search head or a standalone search head with remote peers is not the
        qualified single-instance deployment. Unknown fields fail closed.
        """

        def content(path):
            response = self.request("GET", path)
            entries = response.get("entry")
            if not isinstance(entries, list) or len(entries) != 1:
                raise Refused("deployment evidence is incomplete")
            value = entries[0].get("content")
            if not isinstance(value, dict):
                raise Refused("deployment evidence is incomplete")
            return value

        server = content("/services/server/info")
        version = server.get("version")
        if not isinstance(version, str) or version not in QUALIFIED_VERSIONS:
            raise Refused(
                "only standalone Splunk Enterprise "
                + ", ".join(sorted(QUALIFIED_VERSIONS))
                + " is qualified"
            )
        # instance_type=cloud is the discriminator used by Splunk's solnlib.
        # The qualified Enterprise instance omits it. Any new value requires
        # qualification rather than being treated as Enterprise by default.
        roles = server.get("server_roles")
        qualified_roles = {"indexer", "license_master", "license_manager", "kv_store"}
        if (
            server.get("product_type") != "enterprise"
            or server.get("instance_type") not in (None, "")
            or server.get("mode") != "normal"
            or server.get("isForwarding") not in (False, "0", 0)
            or not isinstance(roles, list)
            or set(roles) != qualified_roles
        ):
            raise Refused(
                "deployment is not a qualified standalone Enterprise instance"
            )
        shc = content("/servicesNS/nobody/system/configs/conf-server/shclustering")
        if shc.get("disabled") not in (True, "1", 1):
            raise Refused("SHC or unknown SHC configuration is not qualified")
        clustering = content("/servicesNS/nobody/system/configs/conf-server/clustering")
        if clustering.get("mode") != "disabled":
            raise Refused(
                "indexer clustering or unknown clustering mode is not qualified"
            )
        peers = self.request("GET", "/services/search/distributed/peers?count=0")
        if peers.get("entry") != [] or peers.get("paging", {}).get("total") not in (
            0,
            "0",
        ):
            raise Refused(
                "remote search peers or incomplete peer evidence is not qualified"
            )

    def preflight(self, name):
        self.settings.validate()
        if not self.settings.enabled:
            raise Refused("recovery is not enabled")
        if name not in TARGET_WINDOWS:
            raise Refused("unknown target")
        who = self.request("GET", "/services/authentication/current-context")["entry"][
            0
        ]["content"]
        if not set(who.get("roles", [])) & {"admin", "sc_admin"}:
            raise Refused("administrator owner required")
        required = {"search", "schedule_search", "run_collect", "output_file"}
        if not required.issubset(who.get("capabilities", [])):
            raise Refused("owner lacks required capabilities")
        self.qualify_deployment()
        entry = self.target(name)
        for kind in ("read", "write"):
            roles = set(entry.get("acl", {}).get("perms", {}).get(kind, []))
            if not roles or roles - {"admin", "sc_admin"}:
                raise Refused("target ACL must be administrator-only")
        before = self.snapshot(entry)
        shipped = configparser.RawConfigParser()
        shipped.read(Path(__file__).resolve().parents[2] / "default/savedsearches.conf")
        if before["search"] != shipped[name]["search"]:
            raise Refused("target search differs from qualified definition")
        if truth(before["disabled"]) or not truth(before["is_scheduled"]):
            raise Refused("target must be enabled and scheduled")
        window = TARGET_WINDOWS[name]
        minute = window["offset"] // 60
        expected = {
            "cron_schedule": "*/5 * * * *"
            if not minute
            else f"{minute}-{minute + 55}/5 * * * *",
            "dispatch.earliest_time": "-24h",
            "dispatch.latest_time": "+15m",
            "dispatch.index_earliest": "-10m@m",
            "dispatch.index_latest": "-5m@m" if name == ROLLUP else "@m",
            "dispatchAs": "owner",
            "realtime_schedule": "0",
        }
        if any(before[key] != value for key, value in expected.items()):
            raise Refused("target schedule/window differs from qualified configuration")
        # A global dispatch-as override would invalidate owner-context assumptions.
        limits = self.request(
            "GET", "/servicesNS/nobody/system/configs/conf-limits/scheduler"
        )["entry"][0]["content"]
        if truth(limits.get("force_saved_search_dispatch_as_user", "0")):
            raise Refused("owner dispatch is overridden")
        self.configuration_value = self.configuration()
        return before, self.configuration_value

    def search(
        self, query, earliest="-1445m@m", latest="now", index_window=None, target=None
    ):
        data = {
            "search": query,
            "exec_mode": "normal",
            "earliest_time": str(earliest),
            "latest_time": str(latest),
        }
        if index_window:
            data.update(
                index_earliest=str(index_window[0]), index_latest=str(index_window[1])
            )
        sid = self.request("POST", APP + "/search/v2/jobs", data)["sid"]
        return self.job(sid, target=target)

    def job(self, sid, target=None):
        path = "/services/search/v2/jobs/" + quote(sid, safe="")
        while True:
            content = self.request("GET", path)["entry"][0]["content"]
            if (
                truth(content.get("isFailed"))
                or content.get("dispatchState") == "FAILED"
            ):
                raise Uncertain("search failed")
            if truth(content.get("isDone")):
                break
            self.sleep(0.25)
        if truth(content.get("isFinalized")):
            raise Uncertain("search finalized before completion")
        total = int(content.get("resultCount", -1))
        if total < 0 or total > self.settings.manifest_count_limit:
            raise Uncertain("search result count exceeds qualified limit")
        rows, notes = [], list(content.get("messages", []))
        for offset in range(0, max(total, 1), 1000):
            result = self.request("GET", path + f"/results?count=1000&offset={offset}")
            if truth(result.get("preview")):
                raise Uncertain("preview search results")
            rows.extend(result.get("results", []))
            notes.extend(result.get("messages", []))
        if len(rows) != total:
            raise Uncertain("truncated search results")
        warnings = sorted(
            set(
                item.get("type", "").upper() + ": " + item.get("text", "")
                for item in notes
                if item.get("type", "").upper() not in ("INFO", "DEBUG")
            )
        )
        if warnings:
            zero = (
                int(content.get("scanCount", -1)) == 0
                and int(content.get("eventCount", -1)) == 0
            )
            empty_rollup = (
                target == ROLLUP
                and not rows
                and warnings == ["WARN: No results to summary index."]
            )
            empty_binding = (
                target == "ADM - Service binding"
                and rows == [{"rows_written": "0"}]
                and len(warnings) == 1
                and warnings[0].startswith(
                    "WARN: Found no results to write to collection '"
                )
                and warnings[0].endswith("'.")
            )
            if not (zero and (empty_rollup or empty_binding)):
                raise Uncertain("search reported warnings or errors")
        return rows

    def history(self, name):
        return self.search(
            "| `adm_recovery_scheduler_history` | where savedsearch_name="
            + json.dumps(name)
        )

    @staticmethod
    def require_unattempted_rollups(plan, history):
        """Partial native aggregates cannot be repaired by a full-slice replay."""
        slots = {int(slot["scheduled_time"]) for slot in plan if slot["name"] == ROLLUP}
        if not slots:
            return
        for row in history:
            if row.get("savedsearch_name") != ROLLUP:
                continue
            try:
                scheduled = int(row["scheduled_time"])
            except (KeyError, TypeError, ValueError):
                raise Refused("ambiguous rollup scheduler history") from None
            if scheduled not in slots:
                continue
            # Only a recorded skip without a job is known not to have written.
            # Any SID (including a manual one), failure or unknown outcome
            # requires operator reconciliation of possible partial aggregates.
            if row.get("status") == "skipped" and not row.get("sid"):
                continue
            raise Refused(
                "rollup has prior execution evidence; manual reconciliation required"
            )

    def plan(self, name, history):
        successes = [
            row
            for row in history
            if row.get("status") == "success"
            and row.get("savedsearch_name") == name
            and str(row.get("sid", "")).startswith("scheduler__")
        ]
        if not successes:
            raise Refused("no_successful_checkpoint")
        first = min(int(row["scheduled_time"]) for row in successes)
        all_states = self.request(
            "GET",
            STATE
            + "?"
            + urlencode(
                {
                    "query": json.dumps({"record_type": "slot", "name": name}),
                    "limit": 10001,
                }
            ),
        )
        if len(all_states) > 10000:
            raise Refused("state history exceeds qualified limit")
        known = {record["scheduled_time"]: record for record in all_states}
        for record in all_states:
            if record.get("configuration") != self.configuration_value:
                raise Refused("recorded recovery configuration differs")
            if record["state"] == "recovered" or (
                record.get("owner") == self.owner and record["state"] == "verified"
            ):
                successes.append(
                    {
                        "savedsearch_name": name,
                        "status": "success",
                        "scheduled_time": record["scheduled_time"],
                    }
                )
            else:
                raise Refused("target has unresolved slot claims")
        window = TARGET_WINDOWS[name]
        now = self.wall()
        through = int(now - 1)
        through -= (through - window["offset"]) % window["period"]
        boundary = int(now) // 60 * 60 - 86400
        boundary += (window["offset"] - boundary) % window["period"]
        # Keep the preceding checkpoint as evidence, but plan only slots in
        # the detector's 24-hour window. Round through to the last closed slot
        # so seconds after that slot cannot inflate the planner's range.
        outage = max(first + 1, boundary)
        if through < outage:
            return []
        plan = build_recovery_plan(successes, outage, through, targets=[name])
        validate_recovery_plan(plan, self.wall() - 1)
        self.require_unattempted_rollups(plan, history)
        for item in plan:
            if item["scheduled_time"] in known:
                raise Refused("existing slot claim")
        return plan

    def drain(self, name, before):
        while True:
            entries = self.request("GET", "/services/search/v2/jobs?count=0")["entry"]
            active = [
                entry
                for entry in entries
                if not truth(entry["content"].get("isDone"))
                and (
                    entry["content"].get("label") == name
                    or entry["content"].get("savedsearch_name") == name
                    or entry["content"].get("search") == before["search"]
                )
            ]
            if not active:
                return
            self.sleep(0.5)

    def unchanged(self, name, before, paused=True):
        expected = dict(before)
        if paused:
            expected["is_scheduled"] = "0"
        if self.snapshot(self.target(name)) != expected:
            raise Uncertain("conflicting administrator changes")
        if self.configuration() != self.lock["configuration"]:
            raise Uncertain("macro configuration changed during recovery")

    def manifest(self, slot):
        bounds = (slot["index_earliest"], slot["index_latest"])
        raw = self.search(
            '| `adm_flows` | where adm_quality_status!="excluded" | dedup adm_acl_dn keepempty=true | stats count AS accepted_records',
            slot["earliest"],
            slot["latest"],
            bounds,
        )
        rows = self.search(
            "| `adm_conversation_rollup` | eval adm_manifest_time=_time | table adm_manifest_time rollup_id replay_protected records",
            slot["earliest"],
            slot["latest"],
            bounds,
        )
        count = int(raw[0]["accepted_records"])
        manifest = {}
        for row in rows:
            key = row.get("rollup_id", "")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", key)
                or not truth(row.get("replay_protected"))
                or key in manifest
            ):
                raise Refused("rollup manifest is not replay-protected")
            records = int(row["records"])
            if records <= 0:
                raise Refused("rollup manifest has invalid count")
            manifest[key] = {
                "records": records,
                "time": float(row["adm_manifest_time"]),
            }
        if sum(row["records"] for row in manifest.values()) != count:
            raise Refused("slice-stability count mismatch")
        # Manifest is a pre-replay slice-stability check, not proof of writes.
        return {"accepted_records": count, "rows": manifest}

    def verify_summary(self, manifest):
        expected = manifest["rows"]
        if not expected:
            return
        ids = sorted(expected)
        earliest = min(row["time"] for row in expected.values())
        latest = max(row["time"] for row in expected.values()) + 1
        observed = {}
        for offset in range(0, len(ids), 100):
            batch = ids[offset : offset + 100]
            query = (
                'search `adm_index_summary` source="adm:conversation" rollup_id IN ('
                + ",".join('"' + key + '"' for key in batch)
                + ") | stats count AS copies count(records) AS copies_with_records min(records) AS min_records max(records) AS max_records BY rollup_id"
            )
            while True:
                rows = self.search(query, earliest, latest)
                if len(rows) == len(batch):
                    break
                self.sleep(0.5)
            for row in rows:
                key = row["rollup_id"]
                if (
                    key not in expected
                    or int(row["copies"]) != int(row["copies_with_records"])
                    or int(row["min_records"]) != expected[key]["records"]
                    or int(row["max_records"]) != expected[key]["records"]
                ):
                    raise Uncertain("summary count verification failed")
                observed[key] = int(row["min_records"])
        if (
            set(observed) != set(expected)
            or sum(observed.values()) != manifest["accepted_records"]
        ):
            raise Uncertain("summary manifest verification failed")

    def replay(self, slot, before):
        self.unchanged(slot["name"], before)
        validate_recovery_plan([slot], self.wall() - 1)
        if slot["name"] == ROLLUP:
            self.require_unattempted_rollups([slot], self.history(slot["name"]))
        record = {
            "_key": slot_key(slot["name"], slot["scheduled_time"]),
            "record_type": "slot",
            **slot,
            "owner": self.owner,
            "expires_at": self.lock["expires_at"],
            "state": "claimed",
            "configuration": self.lock["configuration"],
            "updated": self.wall(),
        }
        self.insert(record)
        self.current = record
        if slot["name"] == ROLLUP:
            self.save(record, state="slice_checked", manifest=self.manifest(slot))
        self.save(record, state="dispatch_pending")
        self.unknown_dispatch = True
        data = {
            "dispatch.earliest_time": str(slot["earliest"]),
            "dispatch.latest_time": str(slot["latest"]),
            "dispatch.index_earliest": str(slot["index_earliest"]),
            "dispatch.index_latest": str(slot["index_latest"]),
            "trigger_actions": "0",
        }
        try:
            sid = self.request(
                "POST",
                APP + "/saved/searches/" + quote(slot["name"], safe="") + "/dispatch",
                data,
            )["sid"]
        except ApiError as exc:
            if 400 <= exc.status < 500:
                self.unknown_dispatch = False
            raise
        self.active_sid = sid
        self.unknown_dispatch = False
        self.save(record, state="running", sid=sid)
        output = self.job(sid, target=slot["name"])
        self.active_sid = None
        self.unchanged(slot["name"], before)
        if slot["name"] == ROLLUP:
            expected = {
                key: value["records"]
                for key, value in record["manifest"]["rows"].items()
            }
            actual = {
                row.get("rollup_id"): int(row.get("records", -1)) for row in output
            }
            if len(actual) != len(output) or actual != expected:
                raise Uncertain("replay output differs from slice-stability manifest")
            self.verify_summary(record["manifest"])
        self.save(record, state="verified", verified_at=self.wall())
        self.completed.append(record)
        self.current = None

    def restore(self, name, before):
        self.unchanged(name, before)
        self.save(self.lock, state="restore_pending")
        self.request(
            "POST",
            APP + "/saved/searches/" + quote(name, safe=""),
            {"is_scheduled": before["is_scheduled"]},
        )
        self.unchanged(name, before, paused=False)
        self.save(
            self.lock,
            state="restored",
            restored_at=self.wall(),
            local_override_retained=True,
        )

    def run(self, name):
        before = None
        try:
            before, configuration = self.preflight(name)
            if self.state(target_key(name)):
                raise Refused("target claim already exists; no takeover")
            pending = self.plan(name, self.history(name))
            validate_recovery_plan(pending, self.wall() - 1)
            if len(pending) > self.settings.initial_backlog_limit:
                raise Refused("backlog exceeds initial budget; schedule was not paused")
            if not pending:
                self.audit("noop", name=name)
                return {"status": "noop", "name": name, "slots": []}
            record = {
                "_key": target_key(name),
                "record_type": "target",
                "name": name,
                "owner": self.owner,
                "expires_at": self.wall() + self.settings.lease_seconds,
                "state": "pause_pending",
                "before": before,
                "changed_fields": ["is_scheduled"],
                "configuration": configuration,
                "updated": self.wall(),
            }
            self.insert(record)
            self.lock = record
            # The durable intent and original state exist before any REST pause.
            if self.state(record["_key"]).get("before") != before:
                raise Uncertain("pause state was not persisted")
            self.audit("pause_pending", name=name)
            self.unchanged(name, before, paused=False)
            self.request(
                "POST",
                APP + "/saved/searches/" + quote(name, safe=""),
                {"is_scheduled": "0"},
            )
            paused = self.clock()
            overall = min(
                self.started + self.settings.action_deadline_seconds,
                paused + self.settings.pause_cap_seconds,
            )
            self.deadline = min(overall, paused + 120)
            self.unchanged(name, before)
            self.save(record, state="paused", paused_at=self.wall())
            self.drain(name, before)
            while True:
                overhead = self.clock() - paused - self.slot_seconds
                if overhead > 120 or self.clock() >= overall:
                    raise Uncertain("pause or overhead budget reached")
                self.deadline = min(overall, self.clock() + (120 - overhead))
                pending = self.plan(name, self.history(name))
                if not pending:
                    # Do not hand back across a cron boundary in the final REST
                    # exchange. A boundary race is uncertain, never 'recovered'.
                    w = TARGET_WINDOWS[name]
                    next_slot = (
                        int(self.wall())
                        - ((int(self.wall()) - w["offset"]) % 300)
                        + 300
                    )
                    if next_slot - self.wall() < 30:
                        self.sleep(next_slot - self.wall() + 1)
                        continue
                    self.restore(name, before)
                    if self.wall() >= next_slot:
                        raise Uncertain("restoration crossed a scheduler boundary")
                    for item in self.completed:
                        self.save(item, state="recovered", recovered_at=self.wall())
                    self.audit("recovered", name=name, slots=len(self.completed))
                    self.request("DELETE", STATE + "/" + record["_key"])
                    return {
                        "status": "recovered",
                        "name": name,
                        "slots": [item["scheduled_time"] for item in self.completed],
                    }
                if len(self.completed) + len(pending) > self.settings.total_slot_limit:
                    raise Uncertain("total slot budget reached")
                for slot in pending:
                    start = self.clock()
                    self.deadline = min(
                        overall, start + self.settings.slot_timeout_seconds
                    )
                    try:
                        self.replay(slot, before)
                    finally:
                        self.slot_seconds += self.clock() - start
        except Exception as exc:
            if not self.lock:
                # Pre-pause refusals do not create claims or change schedules.
                reason = (
                    str(exc)
                    if isinstance(exc, (Refused, Uncertain, ApiError))
                    else type(exc).__name__
                )
                if before is not None:
                    try:
                        self.audit("refused", name=name, reason=reason)
                    except Exception:
                        pass  # Refusal remains a nonzero action result if audit is unavailable.
                return {
                    "status": "refused",
                    "name": name,
                    "reason": reason,
                }
            self.deadline = min(
                self.started + self.settings.action_deadline_seconds,
                self.clock() + self.settings.cleanup_seconds,
            )
            reason = (
                str(exc)
                if isinstance(exc, (Refused, Uncertain, ApiError))
                else type(exc).__name__
            )
            try:
                if self.current:
                    self.save(self.current, state="uncertain", reason=reason)
                # On an ordinary, known failure only, restore after proving no
                # writer remains. Unknown POST outcomes require manual cleanup.
                if not self.unknown_dispatch and not self.active_sid:
                    current = self.snapshot(self.target(name))
                    if current["is_scheduled"] == "0":
                        self.drain(name, before)
                        self.restore(name, before)
                self.save(self.lock, state="uncertain", reason=reason)
            except Exception:
                # Persisted nonterminal claims remain visible as in-progress/
                # expired uncertain; never retry writes or dispatch here.
                pass
            return {
                "status": "uncertain",
                "name": name,
                "reason": reason,
                "slots": [item["scheduled_time"] for item in self.completed],
            }
