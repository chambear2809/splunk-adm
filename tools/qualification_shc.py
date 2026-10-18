#!/usr/bin/env python3
"""Strict-TLS client and bounded checks for an explicitly owned SHC lab.

This module also implements the external client contract consumed by the two
original tests/splunk/test_distributed_interfaces.py regressions. Importing it
does not provision, reset, authenticate to, or change any lab.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MEMBERS = ("sh1", "sh2", "sh3")
ROLES = (*MEMBERS, "deployer", "idx")
APP = "/servicesNS/nobody/splunk_adm"
SETTINGS = APP + "/adm/deployment-settings"
TASK_RE = re.compile(r"adm-shc-[a-z0-9][a-z0-9-]{0,47}\Z")
STATE: dict = {}


class Refused(RuntimeError):
    """Unsafe or incomplete qualification inputs."""


class ApiError(RuntimeError):
    def __init__(self, status: int):
        self.status = status
        # Splunk error bodies can contain configuration and credential details.
        super().__init__(f"qualification request rejected (HTTP {status})")


def protected_file(path: Path) -> Path:
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise Refused("expected an owner-only regular file")
    if info.st_uid != os.getuid():
        raise Refused("qualification file belongs to another owner")
    return path


def load_state(path: Path) -> dict:
    value = json.loads(protected_file(path).read_text())
    task = value.get("task", "")
    if not TASK_RE.fullmatch(task):
        raise Refused("invalid qualification task identity")
    if set(value.get("created", {})) != set(ROLES):
        raise Refused("expected three members, deployer and remote peer")
    for role, entry in value["created"].items():
        if entry.get("name") != f"{task}-{role}":
            raise Refused("instance name does not match its task and role")
        endpoint = urllib.parse.urlsplit(entry.get("url", ""))
        if (
            endpoint.scheme != "https"
            or endpoint.hostname not in ("localhost", entry["name"])
            or endpoint.username
            or endpoint.password
            or endpoint.path
            or endpoint.query
            or endpoint.fragment
            or not endpoint.port
        ):
            raise Refused("management endpoint must be task-local verified HTTPS")
    return value


def configure(path: Path) -> dict:
    STATE.clear()
    STATE.update(load_state(path))
    return STATE


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message: str) -> None:
    if not condition:
        raise Refused(message)


def search_query(query: str) -> str:
    """Match the standalone lab's base-search versus generating-command shape."""
    value = query.strip()
    require(bool(value), "qualification search cannot be empty")
    return value if value.startswith(("|", "search ")) else "search " + value


def wait_for(check, timeout: float = 120, interval: float = 1):
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if result:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused("qualification convergence deadline expired")
        time.sleep(min(interval, remaining))


class Api:
    def __init__(self, role: str, account: str = "admin", state=None):
        self.state = STATE if state is None else state
        require(role in ROLES, "unknown qualification role")
        require(bool(self.state), "configure an external qualification state first")
        self.role, self.account = role, account
        self.url = self.state["created"][role]["url"]
        ca = protected_file(Path(self.state["ca_file"]))
        self.context = ssl.create_default_context(cafile=str(ca))
        # No CERT_NONE, hostname override, proxy credentials, or redirect fallback.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.context),
            NoRedirect(),
        )

    def json(self, method, path, data=None, raw=None, timeout=30):
        require(path.startswith("/services"), "unexpected management path")
        require(method in ("GET", "POST", "DELETE"), "unsupported request method")
        require(raw is None or data is None, "ambiguous request encoding")
        secret_file = self.state["account_files"][self.account]
        secret = json.loads(protected_file(Path(secret_file)).read_text())
        auth = base64.b64encode(
            f"{secret['username']}:{secret['password']}".encode()
        ).decode()
        sep = "&" if "?" in path else "?"
        headers = {"Authorization": "Basic " + auth}
        if raw is not None:
            headers["Content-Type"] = "application/json"
        body = raw
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(
            self.url + path + sep + "output_mode=json",
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                value = response.read()
                if method == "DELETE" and not value and 200 <= response.status < 300:
                    return {}
                return json.loads(value)
        except urllib.error.HTTPError as error:
            error.close()
            raise ApiError(error.code) from None
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            raise Refused("verified management request failed") from None

    def request(self, method, path, data=None, json_body=False, **_kwargs):
        """Adapter for the packaged recovery and migration deployment qualifiers."""
        raw = canonical(data) if json_body and data is not None else None
        return self.json(method, path, data=None if raw else data, raw=raw)

    def search(self, query, earliest=None, latest=None, timeout=600):
        require(0 < timeout <= 900, "search deadline outside qualification bound")
        deadline = time.monotonic() + timeout
        values = {"search": search_query(query), "exec_mode": "normal"}
        if earliest is not None:
            values["earliest_time"] = str(earliest)
        if latest is not None:
            values["latest_time"] = str(latest)
        result = self.json("POST", APP + "/search/v2/jobs", data=values)
        sid = result["sid"]
        path = "/services/search/v2/jobs/" + urllib.parse.quote(sid, safe="")
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "search deadline expired")
            job = self.json("GET", path, timeout=min(30, remaining))["entry"][0][
                "content"
            ]
            require(job.get("dispatchState") != "FAILED", "search failed")
            reject_messages(job.get("messages", []))
            if job.get("isDone") in (True, "1", 1):
                break
            time.sleep(min(1, remaining))
        results = self.json("GET", path + "/results?count=0")
        reject_messages(results.get("messages", []))
        evidence = {"sid": sid}
        evidence.update(
            {
                key: job[key]
                for key in (
                    "dispatchState",
                    "runDuration",
                    "scanCount",
                    "eventCount",
                    "resultCount",
                )
                if key in job
            }
        )
        return results.get("results", []), evidence


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("management redirect is forbidden")


def reject_messages(messages):
    require(
        not any(
            m.get("type", "").upper() in {"WARN", "WARNING", "ERROR", "FATAL"}
            for m in messages
        ),
        "search returned a warning or error; inspect protected server evidence",
    )


def verify_instances(state=None):
    state = STATE if state is None else state
    result = {}
    for role in ROLES:
        api = Api(role, state=state)
        content = api.json("GET", "/services/server/info")["entry"][0]["content"]
        require(
            content.get("serverName") == state["created"][role]["name"],
            "server identity mismatch",
        )
        require(content.get("version") == "10.6.0.5", "unexpected Splunk patch")
        require(content.get("product_type") == "enterprise", "unexpected platform")
        result[role] = {
            key: content.get(key)
            for key in (
                "serverName",
                "version",
                "build",
                "guid",
                "product_type",
                "server_roles",
            )
        }
        if role in MEMBERS:
            peers = api.json("GET", "/services/search/distributed/peers?count=0")[
                "entry"
            ]
            require(len(peers) == 1, "expected exactly one dedicated remote peer")
            require(
                state["created"]["idx"]["name"] in peers[0]["name"]
                and peers[0]["content"].get("status") == "Up",
                "remote search peer not ready or not task-owned",
            )
    return result


def add_remote_peer():
    """Explicit coordinator action after task identity and TLS readiness checks."""
    secret = json.loads(
        protected_file(Path(STATE["account_files"]["admin"])).read_text()
    )
    for role in MEMBERS:
        Api(role).json(
            "POST",
            "/services/search/distributed/peers",
            data={
                "name": "https://" + STATE["created"]["idx"]["name"] + ":8089",
                "remoteUsername": secret["username"],
                "remotePassword": secret["password"],
            },
        )


def verify_shc_ready():
    """Require member/KV readiness and captain evidence, never relax RF flags."""
    results = {}
    captains = set()
    memberships = set()
    expected = {
        "https://" + STATE["created"][role]["name"] + ":8089": role for role in MEMBERS
    }
    flags = ("initialized_flag", "service_ready_flag", "min_peers_joined_flag")

    def content(api, path):
        value = api.json("GET", path)
        entries = value.get("entry") if isinstance(value, dict) else None
        require(
            isinstance(entries, list)
            and len(entries) == 1
            and isinstance(entries[0], dict)
            and isinstance(entries[0].get("content"), dict),
            "SHC status response is malformed",
        )
        return entries[0]["content"]

    for role in MEMBERS:
        api = Api(role)
        require(kv_ready(role), "member KV Store is not ready")
        value = content(api, "/services/shcluster/member/info")
        require(value.get("status") == "Up", "SHC member is not Up")
        require(
            value.get("is_registered") in (True, 1, "1"),
            "SHC member is not registered",
        )
        require(value.get("maintenance_mode") is False, "SHC member is in maintenance")
        status = content(api, "/services/shcluster/status?advanced=1")
        captain, peers = status.get("captain"), status.get("peers")
        require(isinstance(captain, dict), "SHC captain evidence missing")
        captain_uri, captain_id = captain.get("mgmt_uri"), captain.get("id")
        require(
            isinstance(captain_uri, str)
            and captain_uri in expected
            and isinstance(captain_id, str)
            and bool(captain_id),
            "captain is not an identified task member",
        )
        require(
            all(captain.get(flag) in (True, 1, "1") for flag in flags),
            "captain service readiness incomplete",
        )
        stability = {
            "stable_captain": True,
            "rolling_restart_flag": False,
            "rolling_upgrade_flag": False,
            "kvstore_maintenance_status": "disabled",
        }
        require(
            all(
                captain.get(key) is expected_value
                if isinstance(expected_value, bool)
                else captain.get(key) == expected_value
                for key, expected_value in stability.items()
            ),
            "SHC captain is unstable or a maintenance operation is active",
        )
        require(
            isinstance(peers, dict) and len(peers) == len(MEMBERS),
            "SHC must report exactly the owned members",
        )
        members = {}
        for identity, peer in peers.items():
            require(
                isinstance(identity, str)
                and bool(identity)
                and isinstance(peer, dict)
                and isinstance(peer.get("mgmt_uri"), str)
                and peer["mgmt_uri"] in expected
                and peer.get("status") == "Up",
                "SHC peer identity or readiness is invalid",
            )
            require(
                peer.get("out_of_sync_node") is False
                and peer.get("manual_detention") == "off"
                and peer.get("restart_required") == "0",
                "SHC peer is out of sync, detained or awaiting restart",
            )
            members[identity] = peer["mgmt_uri"]
        require(
            set(members.values()) == set(expected),
            "SHC peer set differs from owned members",
        )
        # captain.id is the cluster GUID, not the captain member's server GUID.
        captains.add((captain_uri, captain_id))
        memberships.add(tuple(sorted(members.items())))
        results[role] = {
            "status": value["status"],
            "is_registered": value["is_registered"],
            "maintenance_mode": value["maintenance_mode"],
            "captain_uri": captain_uri,
            "captain_id": captain_id,
            "members": members,
            "peer_readiness": {
                identity: {
                    key: peer[key]
                    for key in (
                        "out_of_sync_node",
                        "manual_detention",
                        "restart_required",
                    )
                }
                for identity, peer in peers.items()
            },
            **{key: captain[key] for key in stability},
            **{flag: captain[flag] for flag in flags},
        }
    require(len(captains) == 1, "members disagree about captain")
    require(len(memberships) == 1, "members disagree about peer identities")
    captain_uri, captain_id = next(iter(captains))
    captain_role = expected[captain_uri]
    captain_content = content(Api(captain_role), "/services/shcluster/captain/info")
    for flag in flags:
        require(
            captain_content.get(flag) in (True, 1, "1"),
            "captain service readiness incomplete",
        )
    results["captain"] = {
        "role": captain_role,
        "mgmt_uri": captain_uri,
        "id": captain_id,
        **{flag: captain_content[flag] for flag in flags},
    }
    return results


def kv_ready(role):
    response = Api(role).json("GET", "/services/kvstore/status")
    entries = response.get("entry") if isinstance(response, dict) else None
    require(
        isinstance(entries, list)
        and len(entries) == 1
        and isinstance(entries[0], dict)
        and isinstance(entries[0].get("content"), dict),
        "KV status evidence incomplete",
    )
    value = entries[0]["content"]
    current, cohosted = value.get("current"), value.get("cohosted")
    if not isinstance(current, dict) or not isinstance(cohosted, dict):
        return False
    service = cohosted.get("serviceInfo")
    return (
        current.get("status") == "ready"
        and current.get("disabled") is False
        and (role not in MEMBERS or current.get("standalone") is False)
        and cohosted.get("status") == "ready"
        and isinstance(service, dict)
        and service.get("type") == "Pdl"
    )


def collection_convergence(collections):
    """Only task-unique probes are inserted/deleted; existing rows are preserved."""
    result = {}
    for collection in collections:
        require(re.fullmatch(r"adm_[a-z0-9_]+", collection), "invalid app collection")
        path = APP + "/storage/collections/data/" + collection
        key = "adm-shc-probe-" + uuid.uuid4().hex
        start = time.monotonic()
        try:
            Api("sh1").json(
                "POST", path, raw=canonical({"_key": key, "probe": "create"})
            )
            wait_for(lambda: probe_agrees(path, key, "create"))
            Api("sh2").json(
                "POST", path + "/" + key, raw=canonical({"probe": "update"})
            )
            wait_for(lambda: probe_agrees(path, key, "update"))
        finally:
            try:
                Api("sh3").json("DELETE", path + "/" + key)
            except ApiError as error:
                if error.status != 404:
                    raise
        wait_for(lambda: probe_absent(path, key))
        result[collection] = {
            "create_update_delete": "passed",
            "elapsed_seconds": round(time.monotonic() - start, 3),
        }
    return result


def probe_agrees(path, key, value):
    for role in MEMBERS:
        try:
            row = Api(role).json("GET", path + "/" + key)
        except ApiError as error:
            if error.status == 404:
                return False
            raise
        if row.get("probe") != value:
            return False
    return True


def probe_absent(path, key):
    for role in MEMBERS:
        try:
            Api(role).json("GET", path + "/" + key)
            return False
        except ApiError as error:
            if error.status != 404:
                raise
    return True


def assert_denied(api, method, path, **kwargs):
    try:
        api.json(method, path, **kwargs)
    except ApiError as error:
        require(error.status in (401, 403, 404), "unexpected denial status")
        return error.status
    raise Refused("restricted operation unexpectedly succeeded")


def restricted_acl(private_collections, writer_searches):
    """The coordinator must create a role/account matching shipped reader ACLs."""
    results = {}
    for role in MEMBERS:
        viewer = Api(role, "viewer")
        outcomes = {}
        for collection in private_collections:
            outcomes[collection] = assert_denied(
                viewer,
                "GET",
                APP
                + "/storage/collections/data/"
                + urllib.parse.quote(collection, safe=""),
            )
        outcomes["settings_post"] = assert_denied(viewer, "POST", SETTINGS, raw=b"{}")
        for name in writer_searches:
            saved = Api(role).json(
                "GET", APP + "/saved/searches/" + urllib.parse.quote(name, safe="")
            )["entry"][0]["content"]
            require(
                saved.get("disabled") in (False, 0, "0"),
                "disabled writer cannot prove dispatch authorization",
            )
            outcomes[name] = assert_denied(
                viewer,
                "POST",
                APP
                + "/saved/searches/"
                + urllib.parse.quote(name, safe="")
                + "/dispatch",
                data={},
            )
        results[role] = outcomes
    return results


def verify_scheduler(saved_search, minimum_slot, maximum_slot):
    """Observe real scheduled successes; never dispatch or modify a saved search."""
    require(
        re.fullmatch(r"ADM - [A-Za-z0-9 ()_-]+", saved_search), "invalid search name"
    )
    require(0 < minimum_slot <= maximum_slot, "invalid scheduler interval")
    query = (
        'search index=_internal sourcetype=scheduler savedsearch_name="'
        + saved_search
        + '" status=success | where scheduled_time>='
        + str(int(minimum_slot))
        + " AND scheduled_time<="
        + str(int(maximum_slot))
        + " | stats values(sid) AS sids dc(sid) AS successes by scheduled_time"
    )
    rows, job = Api("sh1").search(
        query, str(minimum_slot - 300), str(maximum_slot + 900)
    )
    require(bool(rows), "no actual successful scheduler slot observed")
    require(
        all(int(row["successes"]) == 1 for row in rows),
        "scheduler slot has multiple success SIDs",
    )
    expected = set(
        range(
            ((int(minimum_slot) + 299) // 300) * 300,
            (int(maximum_slot) // 300) * 300 + 1,
            300,
        )
    )
    require(
        bool(expected)
        and {int(float(row["scheduled_time"])) for row in rows} == expected,
        "not every expected five-minute scheduler slot completed",
    )
    return {"slots": rows, "job": job}


def settings_race(expected_revision, payloads, namespace):
    """Coordinate two real member writes after the caller has verified readiness.

    Assertions intentionally require the stable endpoint response contract. This
    helper must be updated alongside it if that contract changes.
    """
    require(len(payloads) == 2, "race requires exactly two candidate payloads")

    def observed_revision(observed):
        require(
            isinstance(observed, dict)
            and observed.get("canWrite") is True
            and observed.get("namespace") == namespace,
            "all members must share a ready writable namespace",
        )
        require(
            "settings" in observed
            and observed.get("state") in ("absent", "configured"),
            "settings read response is malformed",
        )
        current = observed["settings"]
        if current is None:
            require(
                observed["state"] == "absent", "settings read state is inconsistent"
            )
            return None
        require(
            observed["state"] == "configured"
            and isinstance(current, dict)
            and isinstance(current.get("revision"), str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", current["revision"]) is not None,
            "settings read revision or state is malformed",
        )
        return current["revision"]

    for role in MEMBERS:
        observed = Api(role).json("GET", SETTINGS)
        require(
            observed_revision(observed) == expected_revision,
            "members have not converged on expected revision",
        )
    barrier = threading.Barrier(2)
    requests = [
        {
            "namespace": namespace,
            "expectedRevision": expected_revision,
            "requestId": str(uuid.uuid4()),
            "settings": payload,
        }
        for payload in payloads
    ]

    def write(index):
        barrier.wait(timeout=15)
        try:
            response = Api(MEMBERS[index]).json(
                "POST", SETTINGS, raw=canonical(requests[index])
            )
            return {"status": 200, "response": response}
        except ApiError as error:
            return {"status": error.status}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, range(2)))
    require(
        sorted(result["status"] for result in results) == [200, 409],
        "same-revision writes did not produce one success and one conflict",
    )
    winner = next(i for i, result in enumerate(results) if result["status"] == 200)
    winning_request = requests[winner]
    expected_settings = json.loads(canonical(winning_request["settings"]))
    # The endpoint replaces the draft revision. Derive its committed revision
    # independently from the immutable operation contract, never from the reply.
    operation_fingerprint = digest(
        [
            expected_revision,
            winning_request["requestId"],
            expected_settings["schemaVersion"],
            expected_settings["sources"],
        ]
    )
    expected_settings["revision"] = digest(["revision", operation_fingerprint])

    def exact_settings(value):
        require(
            observed_revision(value) == expected_settings["revision"]
            and canonical(value["settings"]) == canonical(expected_settings),
            "settings differ from the exact winning operation",
        )

    def committed_identity(value):
        require(
            isinstance(value, dict)
            and isinstance(value.get("committedRevision"), str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value["committedRevision"])
            is not None
            and value.get("requestId") == requests[winner]["requestId"],
            "settings commit response identity is malformed",
        )
        return value["committedRevision"]

    committed_revision = committed_identity(results[winner]["response"])
    require(
        committed_revision == expected_settings["revision"],
        "settings commit revision differs from the winning operation",
    )
    exact_settings(results[winner]["response"])
    # A duplicate after a simulated lost response must recover the same result.
    retry = Api("sh3").json("POST", SETTINGS, raw=canonical(requests[winner]))
    require(
        committed_identity(retry) == committed_revision,
        "retry changed the winning commit identity",
    )
    exact_settings(retry)

    def converged():
        for role in MEMBERS:
            observed = Api(role).json("GET", SETTINGS)
            if observed_revision(observed) != committed_revision:
                return False
            exact_settings(observed)
        return True

    wait_for(converged)
    return {
        "statuses": [result["status"] for result in results],
        "winner": winner,
        "retry_identical": True,
        "request_ids": [request["requestId"] for request in requests],
        "committed_revision": committed_revision,
        "submitted_settings_sha256": digest(winning_request["settings"]),
        "expected_committed_settings_sha256": digest(expected_settings),
        "operation_fingerprint": operation_fingerprint,
        "revision_proof": "independently derived from expectedRevision, requestId, schemaVersion and sources",
        "all_member_settings_agree": True,
    }


def assert_standalone_only(packaged_app: Path, source_root: Path):
    """Execute actual qualifiers through a GET-only adapter, without a journal."""
    sys.path.insert(0, str(Path(packaged_app) / "bin"))
    sys.path.insert(0, str(Path(source_root) / "tools"))
    from adm_recovery_lib.core import Recovery, Refused as RecoveryRefused
    from cisco_contract_migration import Migration, Refused as MigrationRefused

    require(
        Path(sys.modules[Recovery.__module__].__file__)
        .resolve()
        .is_relative_to(Path(packaged_app).resolve()),
        "recovery qualifier was imported from another candidate",
    )
    require(
        Path(sys.modules[Migration.__module__].__file__).resolve()
        == (Path(source_root) / "tools/cisco_contract_migration.py").resolve(),
        "migration qualifier was imported from another source",
    )

    class ReadOnly:
        def __init__(self, api):
            self.api, self.methods = api, []

        def request(self, method, path, **kwargs):
            self.methods.append(method)
            require(method == "GET", "deployment qualifier attempted mutation")
            return self.api.request(method, path, **kwargs)

    result = {}
    for role in MEMBERS:
        api = ReadOnly(Api(role))
        try:
            Recovery(api).qualify_deployment()
        except RecoveryRefused:
            pass
        else:
            raise Refused("recovery qualifier unexpectedly accepted SHC")
        try:
            Migration(api, None).qualify()
        except MigrationRefused:
            pass
        else:
            raise Refused("V2 migration qualifier unexpectedly accepted SHC")
        result[role] = {
            "recovery": "refused",
            "migration": "refused",
            "methods": api.methods,
        }
    return result


def write_evidence(directory: Path, name: str, value):
    """Write explicit sanitized structures, never arbitrary API response bodies."""
    require(re.fullmatch(r"[a-z0-9_-]+", name), "invalid evidence name")
    path = directory / (name + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")
    return {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


if os.environ.get("ADM_SHC_STATE"):
    configure(Path(os.environ["ADM_SHC_STATE"]))
