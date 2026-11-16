"""Authenticated, private single-head baseline host; no production source is shipped."""

import configparser
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from adm_cases_lib.splunk_host import HostUnavailable, SplunkHost as CaseRuntime, pairs
from adm_cases_lib.store import Forbidden as RuntimeForbidden

from .api import BaselineAPI
from .store import BaselineStore, Forbidden, Invalid, validate_capture


class SplunkHost:
    def __init__(
        self,
        token,
        *,
        request=None,
        database_root=None,
        topology=None,
        configuration=None,
        source_provider=None,
        clock=time.time,
    ):
        self.database_root = database_root
        self.configuration = configuration or self._configuration
        self.source_provider = source_provider
        self.clock = clock
        self.runtime = CaseRuntime(
            token,
            request=request,
            topology=topology,
            configuration=self._runtime_configuration,
        )

    @staticmethod
    def _configuration():
        home = Path(os.environ.get("SPLUNK_HOME", ""))
        if not home.is_absolute():
            raise HostUnavailable()
        result = subprocess.run(
            [
                str(home / "bin/splunk"),
                "btool",
                "--app=splunk_adm",
                "--user=nobody",
                "adm_baselines",
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
            key: parsed["persistence"].get(key, "")
            for key in ("mode", "platform", "source_mode")
        }

    def _runtime_configuration(self):
        config = self.configuration()
        if config.get("source_mode") != "unavailable":
            raise HostUnavailable()
        return {
            "mode": config.get("mode"),
            "platform": config.get("platform"),
            "capture_mode": "disabled",
        }

    def principal(self):
        return self.runtime.principal()

    def qualify(self):
        return self.runtime.qualify()

    def database(self):
        root = self.database_root or os.environ.get("SPLUNK_DB")
        if not root or not Path(root).is_absolute():
            raise HostUnavailable()
        base = Path(root)
        if base.is_symlink() or not base.is_dir():
            raise HostUnavailable()
        directory = base / "splunk_adm_baselines"
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise HostUnavailable()
        database = directory / "baselines.sqlite"
        try:
            descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
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

    def store(self, principal, source_failure):
        self.qualify()
        database = self.database()
        provider = self.source_provider

        def entitled(caller, action, _baseline):
            return (
                action != "purge"
                and caller == principal
                and self.principal() == principal
            )

        def resolve(caller, reference):
            try:
                if provider is None or self.principal() != caller:
                    raise HostUnavailable()
                return provider.resolve(caller, reference)
            except Exception:
                source_failure[0] = True
                raise

        def source_entitled(caller, reference, capture):
            if provider is None or self.principal() != caller:
                return False
            return provider.entitled(caller, reference, capture) is True

        return BaselineStore(
            database,
            entitled,
            resolve,
            source_entitlement=source_entitled,
            clock=self.clock,
        )


def _capture(host, principal, query):
    fields = {"service", "environment", "cluster", "namespace", "start", "end"}
    if set(query) != fields:
        raise ValueError("Invalid capture selection")
    selection = {}
    for key in ("service", "environment", "cluster", "namespace"):
        value = query[key]
        if (
            not value
            or value.strip() != value
            or len(value) > 256
            or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
        ):
            raise ValueError("Invalid selection")
        selection[key] = value
    for key in ("start", "end"):
        if not re.fullmatch(r"0|[1-9][0-9]{0,10}", query[key]):
            raise ValueError("Invalid window")
    window = {key: int(query[key]) for key in ("start", "end")}
    now = host.clock()
    if (
        window["end"] <= window["start"]
        or window["end"] - window["start"] > 300
        or window["end"] > now
    ):
        raise ValueError("Invalid window")
    provider = host.source_provider
    if provider is None:
        return 422, {"error": "source_unavailable"}, {"Cache-Control": "no-store"}
    try:
        result = provider.capture(principal, selection, window)
        if not isinstance(result, dict) or set(result) != {"reference", "capture"}:
            raise ValueError("Invalid source result")
        reference, capture = result["reference"], result["capture"]
        if (
            not isinstance(reference, str)
            or not reference
            or reference.strip() != reference
            or len(reference) > 4096
        ):
            raise ValueError("Invalid reference")
        validate_capture(capture)
        if (
            capture["coverage"]["requested"] != window
            or capture["coverage"]["knowledgeHorizon"] > now
        ):
            raise ValueError("Window mismatch or incomplete horizon")
        if (
            provider.resolve(principal, reference) != capture
            or provider.entitled(principal, reference, capture) is not True
        ):
            raise ValueError("Capture cannot be resolved")
        if host.principal() != principal:
            raise RuntimeForbidden()
    except RuntimeForbidden:
        raise
    except Exception:
        return 422, {"error": "source_unavailable"}, {"Cache-Control": "no-store"}
    return 200, result, {"Cache-Control": "no-store"}


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
                host.qualify()
                available = True
            except Exception:
                available = False
            return (
                200,
                {
                    "available": available,
                    "sourceAvailable": available and host.source_provider is not None,
                    "qualificationReasons": (
                        ["runtime_unqualified"] if not available else []
                    )
                    + (["source_unavailable"] if host.source_provider is None else []),
                },
                headers,
            )
        host.qualify()
        if method == "GET" and path == "/capture":
            return _capture(host, principal, query)
        if path == "/baselines/purge":
            return 403, {"error": "forbidden"}, headers
        # Reject evidence writes before opening the database when no provider exists.
        evidence_write = method == "POST" and (
            path == "/baselines"
            or re.fullmatch(
                r"/baselines/[^/]+/(?:versions|watches/[^/]+/(?:occurrences|evaluate))",
                path,
            )
        )
        if evidence_write and host.source_provider is None:
            return 422, {"error": "source_unavailable"}, headers
        payload = request.get("payload", "")
        if not isinstance(payload, str):
            raise ValueError("Invalid payload")
        failure = [False]
        api = BaselineAPI(host.store(principal, failure))
        response = api.handle(
            method,
            path,
            principal=principal,
            query=query,
            headers=request_headers,
            body=payload.encode("utf-8"),
        )
        if evidence_write and failure[0] and response[0] == 403:
            return 422, {"error": "source_unavailable"}, headers
        return response
    except (Forbidden, RuntimeForbidden):
        return 403, {"error": "forbidden"}, headers
    except (ValueError, Invalid, UnicodeEncodeError):
        return 400, {"error": "invalid_request"}, headers
    except Exception:
        return 503, {"error": "unavailable"}, headers
