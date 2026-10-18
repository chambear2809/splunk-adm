"""Splunk request adapter. All calls retain the authenticated caller's token."""

import json
from pathlib import Path
from urllib.parse import urlencode

from . import SettingsError, SettingsService, canonical, digest

APP = "/servicesNS/nobody/splunk_adm"
COLLECTION = APP + "/storage/collections/data/adm_deployment_settings"


def content(value):
    entries = value.get("entry") if isinstance(value, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        raise SettingsError(
            503, "unavailable", "Configuration evidence is unavailable."
        )
    result = entries[0].get("content")
    if not isinstance(result, dict):
        raise SettingsError(
            503, "unavailable", "Configuration evidence is unavailable."
        )
    return result


def flag(value):
    if value is True or (type(value) is int and value == 1) or value == "1":
        return True
    if value is False or (type(value) is int and value == 0) or value == "0":
        return False
    return None


class SplunkStore:
    def __init__(self, session_key):
        self.session_key = session_key

    def request(self, method, path, body=None, query=None):
        import splunk.rest

        if query:
            path += "?" + urlencode(query)
        response, data = splunk.rest.simpleRequest(
            path,
            sessionKey=self.session_key,
            method=method,
            jsonargs=canonical(body) if body is not None else None,
            rawResult=True,
            raiseAllErrors=True,
        )
        if int(response.status) >= 300:
            raise SettingsError(503, "unavailable", "Splunk settings request failed.")
        return json.loads(data)

    def scan(self, limit):
        # A server-side query cap can masquerade as a short complete result.
        # Shift the sorted query by one row: an actual final page must shrink
        # by exactly its first row. Never infer completeness from length alone.
        for _attempt in range(2):
            rows = self.request(
                "GET", COLLECTION, query={"limit": limit, "skip": 0, "sort": "_key:1"}
            )
            if not isinstance(rows, list) or len(rows) > limit:
                raise SettingsError(
                    503, "unavailable", "Deployment settings scan is malformed."
                )
            keys = [row.get("_key") if isinstance(row, dict) else None for row in rows]
            if not all(isinstance(key, str) and key for key in keys) or keys != sorted(
                set(keys)
            ):
                raise SettingsError(
                    503,
                    "unavailable",
                    "Deployment settings scan is not uniquely ordered.",
                )
            if len(rows) == limit:
                # The caller requests its history bound plus one. This is
                # already an explicit overflow, never a usable snapshot.
                return rows
            shifted = self.request(
                "GET", COLLECTION, query={"limit": limit, "skip": 1, "sort": "_key:1"}
            )
            if shifted == rows[1:]:
                return rows
            # One bounded rescan can settle an insert between the two reads.
            # A stable hard cap still fails the completion proof again.
        raise SettingsError(
            503,
            "unavailable",
            "Deployment settings scan is capped or changed during its completion proof.",
        )

    def insert(self, document):
        # Collection POST is an insert. Keyed POST and batch_save are prohibited.
        return self.request("POST", COLLECTION, body=document)

    def authorization(self):
        context = content(
            self.request(
                "GET",
                "/services/authentication/current-context",
                query={"output_mode": "json"},
            )
        )
        permissions = self.request(
            "GET",
            APP + "/storage/collections/config/adm_deployment_settings",
            query={"output_mode": "json"},
        )
        entry = permissions["entry"][0]
        acl = entry.get("acl") or entry.get("content", {}).get("eai:acl", {})
        return "admin_all_objects" in context.get("capabilities", []) and acl.get(
            "can_write"
        ) in (True, 1, "1")

    def persistence(self):
        config = content(
            self.request(
                "GET",
                APP + "/configs/conf-adm_settings/persistence",
                query={"output_mode": "json"},
            )
        )
        mode = config.get("write_mode", "disabled")
        if mode not in ("single_namespace", "qualified_shc"):
            raise SettingsError(
                503,
                "unsupported",
                "Settings writes are disabled. An operator must qualify this deployment and configure adm_settings.conf write_mode.",
            )
        if config.get("platform") != "enterprise":
            raise SettingsError(
                503,
                "unsupported",
                "Settings writes require a qualified Splunk Enterprise deployment. Splunk Cloud is not qualified.",
            )
        server = content(
            self.request("GET", "/services/server/info", query={"output_mode": "json"})
        )
        # Additional runtimes require installed endpoint/concurrency evidence.
        if (
            server.get("version") not in {"10.6.0.5"}
            or server.get("product_type") != "enterprise"
        ):
            raise SettingsError(
                503,
                "unsupported",
                "This Splunk version is not qualified for settings writes.",
            )
        if (
            any(
                server.get(key) in (True, 1, "1")
                for key in ("isCloud", "isCloudInstance")
            )
            or "cloud" in str(server.get("activeLicenseGroup", "")).lower()
        ):
            raise SettingsError(
                503, "unsupported", "Splunk Cloud settings writes are not qualified."
            )
        status = content(
            self.request(
                "GET", "/services/kvstore/status", query={"output_mode": "json"}
            )
        )
        cohosted = status.get("cohosted")
        service = cohosted.get("serviceInfo") if isinstance(cohosted, dict) else None
        if (
            not isinstance(cohosted, dict)
            or cohosted.get("status") != "ready"
            or not isinstance(service, dict)
            or service.get("type") != "Pdl"
            or not isinstance(service.get("service"), str)
            or not service["service"]
        ):
            raise SettingsError(
                503,
                "unsupported",
                "The qualified cohosted PDL KV Store must be ready before saving.",
            )
        # serviceInfo.service is an ephemeral local runtime address, never a
        # deployment namespace, a routing target, or a credential destination.
        current = status.get("current")
        if not isinstance(current, dict):
            raise SettingsError(
                503, "unsupported", "KV Store readiness evidence is incomplete."
            )
        backup = current.get("backupRestoreStatus")
        if (
            current.get("status") != "ready"
            or flag(current.get("disabled")) is not False
            or not isinstance(backup, str)
            or backup.lower() != "ready"
            or current.get("migrationStatus") != "NotStarted"
            or flag(current.get("versionUpgradeInProgress")) is not False
        ):
            raise SettingsError(
                503,
                "unsupported",
                "KV Store must be ready and outside migration, upgrade, backup/restore or maintenance before saving.",
            )
        standalone = flag(current.get("standalone"))
        if standalone is None:
            raise SettingsError(
                503, "unsupported", "KV Store topology evidence is incomplete."
            )
        if mode == "single_namespace":
            server_guid, current_guid = server.get("guid"), current.get("guid")
            if (
                standalone is not True
                or not isinstance(server_guid, str)
                or not server_guid
                or current_guid != server_guid
            ):
                raise SettingsError(
                    503,
                    "unsupported",
                    "single_namespace requires one standalone search head with matching server and KV Store instance identity.",
                )
            # 10.6 standalone status has no replicaSet/members. The documented
            # instance GUID identifies the namespace without inventing either.
            identity = [mode, server_guid, current_guid]
        else:
            replica_set = current.get("replicaSet")
            if not isinstance(replica_set, str) or not replica_set:
                raise SettingsError(
                    503, "unsupported", "KV Store replica-set identity is unavailable."
                )
            members = status.get("members", {})
            members = list(members.values()) if isinstance(members, dict) else members
            if (
                standalone
                or not isinstance(members, list)
                or len(members) < 3
                or sum(
                    str(member.get("replicationStatus", "")).lower()
                    == "kv store captain"
                    for member in members
                )
                != 1
                or any(
                    str(member.get("replicationStatus", "")).lower()
                    not in ("kv store captain", "non-captain kv store member")
                    for member in members
                )
            ):
                raise SettingsError(
                    503,
                    "unsupported",
                    "qualified_shc requires a healthy qualified multi-member KV replica set.",
                )
            addresses = [member.get("hostAndPort") for member in members]
            if not all(
                isinstance(address, str) and address for address in addresses
            ) or len(set(addresses)) != len(addresses):
                raise SettingsError(
                    503,
                    "unsupported",
                    "KV Store replica membership identity is incomplete.",
                )
            identity = [mode, replica_set, sorted(addresses)]
        return digest(identity)


def handle_request(request, store, source_ids):
    method = request.get("method", "").upper()
    if method not in ("GET", "POST"):
        raise SettingsError(405, "invalid", "Only GET and POST are supported.")
    service = SettingsService(store, source_ids)
    authorized, namespace, reason = False, None, None
    try:
        authorized = store.authorization()
        if authorized:
            namespace = store.persistence()
    except SettingsError as exc:
        reason = str(exc)
    except Exception:
        reason = "Settings write capability could not be verified."
    if method == "POST":
        if not authorized:
            raise SettingsError(
                403,
                "forbidden",
                "Administrator capability and collection write permission are required.",
            )
        if namespace is None:
            raise SettingsError(
                503, "unsupported", reason or "Settings writes are unavailable."
            )
        payload = request.get("payload", "")
        if not isinstance(payload, str) or len(payload.encode()) > 32768:
            raise SettingsError(
                400, "invalid", "Settings request is too large or invalid."
            )
        try:
            payload = json.loads(payload)
        except ValueError as exc:
            raise SettingsError(
                400, "invalid", "Settings request is invalid JSON."
            ) from exc
        if not isinstance(payload, dict) or payload.pop("namespace", None) != namespace:
            raise SettingsError(
                409,
                "conflict",
                "Settings namespace changed. Your draft is preserved; reload before saving.",
            )
        result = service.write(payload)
    else:
        result = service.read()
    result.update(canWrite=authorized and namespace is not None, namespace=namespace)
    if reason:
        result["writeUnavailableReason"] = reason
    return result


def source_ids():
    path = Path(__file__).resolve().parents[1] / "adm_settings_registry.json"
    with path.open() as stream:
        registry = json.load(stream)
    return {source["id"] for source in registry["sources"] if source["selectable"]}
