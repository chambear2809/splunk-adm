"""Caller-authenticated single-head cases with opt-in reproducible evidence.

Runtime checks and configuration opt-in are not installed qualification.
"""

import hashlib
import configparser
import json
import os
from pathlib import Path
import stat
import subprocess

from .store import CaseStore, Forbidden

APP = "/servicesNS/nobody/splunk_adm"
CAPABILITY = "adm_investigate"


class HostUnavailable(Exception):
    pass


def pairs(values, *, lower=False):
    """Persistent handlers expose query/header values as pairs; reject ambiguity."""
    if values is None:
        return {}
    if not isinstance(values, list) or len(values) > 64:
        raise ValueError("Invalid request fields")
    result = {}
    for pair in values:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Invalid request fields")
        key, value = pair
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("Invalid request fields")
        key = key.lower() if lower else key
        if key in result:
            raise ValueError("Duplicate request fields")
        result[key] = value
    return result


class SplunkHost:
    def __init__(
        self,
        token,
        request=None,
        database_root=None,
        topology=None,
        native_request=None,
        source_fingerprint=None,
        configuration=None,
    ):
        self.token = token
        self.request = request or self._request
        self.database_root = database_root
        self.topology = topology or self._topology
        self.native_request = native_request
        self.source_fingerprint = source_fingerprint or self._source_fingerprint
        self.configuration = configuration or self._configuration

    @staticmethod
    def _configuration():
        # Fixed, app-scoped local control flags only. Do not require investigators
        # to read arbitrary conf endpoints, and never expose btool's raw output.
        home = Path(os.environ.get("SPLUNK_HOME", ""))
        if not home.is_absolute():
            raise HostUnavailable()
        result = subprocess.run(
            [
                str(home / "bin/splunk"),
                "btool",
                "--app=splunk_adm",
                "--user=nobody",
                "adm_investigations",
                "list",
                "persistence",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=True,
        )
        if len(result.stdout) > 16384:
            raise HostUnavailable()
        parsed = configparser.ConfigParser(interpolation=None)
        parsed.read_string(result.stdout.decode("utf-8"))
        if set(parsed.sections()) != {"persistence"}:
            raise HostUnavailable()
        return {
            key: parsed["persistence"].get(
                key, "disabled" if key == "capture_mode" else ""
            )
            for key in ("mode", "platform", "capture_mode")
        }

    @staticmethod
    def _topology():
        # Read one fixed local runtime setting; do not grant users config-reader
        # privileges or request system authentication. Nothing else from server
        # configuration is returned or logged. Avoid the persistent CLI cache.
        from splunk.clilib.cli_common import getMergedConf

        disabled = getMergedConf("server").get("shclustering", {}).get("disabled")
        return {"disabled": disabled}

    def _request(self, path):
        import splunk.rest

        response, data = splunk.rest.simpleRequest(
            path + "?output_mode=json",
            sessionKey=self.token,
            method="GET",
            rawResult=True,
            raiseAllErrors=True,
        )
        if int(response.status) != 200:
            raise HostUnavailable()
        parsed = json.loads(data)
        entries = parsed.get("entry")
        if not isinstance(entries, list) or len(entries) != 1:
            raise HostUnavailable()
        content = entries[0].get("content")
        if not isinstance(content, dict):
            raise HostUnavailable()
        return content

    def principal(self):
        if not isinstance(self.token, str) or not self.token:
            raise Forbidden("Authentication required")
        context = self.request("/services/authentication/current-context")
        principal = context.get("username")
        caps = context.get("capabilities")
        if (
            not isinstance(principal, str)
            or not principal
            or principal == "nobody"
            or not isinstance(caps, list)
            or CAPABILITY not in caps
        ):
            raise Forbidden("Investigation permission required")
        return principal

    def qualify(self):
        config = self.configuration()
        if (
            config.get("mode") != "single_search_head"
            or config.get("platform") != "enterprise"
            or config.get("capture_mode", "disabled")
            not in ("disabled", "reproducible_qualified_v1")
        ):
            raise HostUnavailable()
        server = self.request("/services/server/info")
        if (
            server.get("product_type") != "enterprise"
            or server.get("version") != "10.6.0.5"
            # Enterprise 10.6.0.5 omits these optional markers in the installed
            # standalone lab. Platform attestation remains mandatory above.
            or server.get("isCloud") not in (None, False, 0, "0")
            or server.get("isCloudInstance") not in (None, False, 0, "0")
            or server.get("activeLicenseGroup") not in ("Trial", "Enterprise")
        ):
            raise HostUnavailable()
        cluster = self.topology()
        if cluster.get("disabled") not in (True, 1, "1", "true"):
            raise HostUnavailable()
        return config

    @staticmethod
    def _source_fingerprint():
        """Bind replay to installed code and fixed source configuration, not SID.

        Configuration bytes are hashed locally and never returned or logged.
        Capturing under a different identity still reruns the source searches.
        """
        app = Path(__file__).resolve().parents[2]
        files = [app / "bin/admqualified.py"]
        files.extend(sorted((app / "bin/adm_identity_lib").glob("*.py")))
        files.extend(sorted((app / "bin/adm_cases_lib").glob("*.py")))
        digest = hashlib.sha256()
        for path in files:
            if path.is_symlink() or not path.is_file():
                raise HostUnavailable()
            digest.update(str(path.relative_to(app)).encode())
            digest.update(path.read_bytes())
        for directory in ("default", "local"):
            for name in ("adm_identity.conf", "commands.conf"):
                path = app / directory / name
                digest.update(f"{directory}/{name}".encode())
                if path.is_symlink():
                    raise HostUnavailable()
                digest.update(path.read_bytes() if path.exists() else b"<absent>")
        return digest.hexdigest()

    def database(self):
        # This path is runtime configuration, never supplied by an HTTP caller.
        root = self.database_root or os.environ.get("SPLUNK_DB")
        if not root or not Path(root).is_absolute():
            raise HostUnavailable()
        base = Path(root)
        if base.is_symlink() or not base.is_dir():
            raise HostUnavailable()
        directory = base / "splunk_adm_investigations"
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise HostUnavailable()
        database = directory / "cases.sqlite"
        # Precreate privately and refuse links or unsafe preexisting permissions.
        descriptor = (
            os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            if not database.exists()
            else None
        )
        if descriptor is not None:
            os.close(descriptor)
        info = database.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != 1
        ):
            raise HostUnavailable()
        return database

    def store(self, principal):
        config = self.qualify()
        database = self.database()

        def entitled(caller, _action, _case):
            if caller != principal or self.principal() != principal:
                return False
            return True

        if config.get("capture_mode", "disabled") == "disabled":
            # Legacy protected items are redacted by the store; notes and owner
            # revocation/deletion remain usable without source permission.
            return CaseStore(database, entitled)
        from .native import NativeComparisonSearch
        from .source import ComparisonSource

        runner = NativeComparisonSearch(self.token, request=self.native_request)

        def run(caller, query, start, end):
            if caller != principal or self.principal() != principal:
                raise Forbidden("Investigation access denied")
            return runner.run(caller, query, start, end)

        source = ComparisonSource(run, self.source_fingerprint)
        return CaseStore(
            database,
            entitled,
            capture_resolver=source.resolve,
            source_entitlement=source.entitled,
        )


def handle(request, host):
    headers = {"Cache-Control": "no-store"}
    try:
        principal = host.principal()
        method = request.get("method", "").upper()
        path = request.get("path_info", "")
        if not isinstance(path, str):
            raise ValueError("Invalid path")
        path = "/" + path.lstrip("/")
        query = pairs(request.get("query"))
        request_headers = pairs(request.get("headers"), lower=True)
        if query.pop("output_mode", "json") != "json":
            raise ValueError("Only JSON is supported")
        if method == "GET" and path == "/capabilities":
            try:
                config = host.qualify()
                available = True
            except HostUnavailable:
                config = {}
                available = False
            return (
                200,
                {
                    "available": available,
                    "evidenceWrites": available
                    and config.get("capture_mode") == "reproducible_qualified_v1",
                    "mode": (
                        "notes_and_reproducible_evidence"
                        if config.get("capture_mode") == "reproducible_qualified_v1"
                        else "notes_only"
                    ),
                    "qualified": False,
                },
                headers,
            )
        payload = request.get("payload", "")
        if not isinstance(payload, str):
            raise ValueError("Invalid payload")
        from .api import CaseAPI

        api = CaseAPI(host.store(principal))
        return api.handle(
            method,
            path,
            principal=principal,
            query=query,
            headers=request_headers,
            body=payload.encode(),
        )
    except Forbidden:
        return (
            403,
            {"code": "forbidden", "error": "Investigation access denied."},
            headers,
        )
    except ValueError:
        return (
            400,
            {"code": "invalid", "error": "Invalid investigation request."},
            headers,
        )
    except Exception:
        return (
            503,
            {
                "code": "unavailable",
                "error": "Shared investigation storage is unavailable. Keep a portable handoff.",
            },
            headers,
        )
