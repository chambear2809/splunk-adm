#!/usr/bin/env python3
from __future__ import annotations
import configparser
import json
import sys
import time
from urllib.parse import parse_qsl, urlsplit
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lib"))
from adm_identity_lib.search import (  # noqa: E402
    bounded_query,
    reduce_rows,
    SearchError,
    NativeSearch,
    bounded_network_query,
    reduce_network_rows,
)
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch  # noqa: E402


@Configuration(type="events", streaming=False)
class AdmQualified(GeneratingCommand):
    mode = Option(require=True)
    service = Option(require=False)
    environment = Option(require=False)
    namespace = Option(require=False)
    cluster = Option(require=False)
    start = Option(require=False)
    as_of = Option(require=False)

    def generate(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read(
            [
                str(ROOT.parent / "default" / "adm_identity.conf"),
                str(ROOT.parent / "local" / "adm_identity.conf"),
            ]
        )
        profile = dict(config["profile"]) if config.has_section("profile") else {}
        if profile.get("enabled", "false").lower() not in ("true", "1"):
            raise SearchError("Qualified identity is disabled.")
        profile["enabled"] = True
        profile["namespaces"] = [
            x.strip() for x in profile.get("namespaces", "").split(",") if x.strip()
        ]
        now = time.time()
        try:
            if self.mode == "graph":
                info = self.metadata.searchinfo
                as_of = float(
                    self.as_of or getattr(info, "latest_time", None) or now - 15
                )
                start = float(
                    self.start or getattr(info, "earliest_time", None) or as_of - 120
                )
            else:
                as_of = float(self.as_of or now - 15)
                start = float(self.start or as_of - 120)
        except (TypeError, ValueError, OverflowError):
            raise SearchError("Identity search bounds must be finite.") from None
        # Catalog URLs must replay the exact same exclusive search bounds.
        # Reject nonfinite values before conversion and preserve integer epochs.
        import math

        if not math.isfinite(start) or not math.isfinite(as_of):
            raise SearchError("Identity search bounds must be finite.")
        start, as_of = int(start), int(as_of)
        query = bounded_query(
            profile,
            self.mode,
            self.service,
            self.environment,
            self.namespace,
            self.cluster,
            start,
            as_of,
        )
        service = self.metadata.searchinfo.session_key
        if not isinstance(service, str) or not service:
            raise SearchError("Caller session key is unavailable.")
        selection = {
            key: getattr(self, key)
            for key in ("service", "environment", "cluster", "namespace")
        }
        if self.mode == "graph" and not all(selection.values()):
            raise SearchError("Graph requires a complete service identity.")
        network_section = (
            dict(config["network"]) if config.has_section("network") else {}
        )
        flag = network_section.get("enabled", "false").strip().lower()
        if flag not in ("true", "false", "1", "0"):
            raise SearchError("Invalid network enabled flag.")
        network_enabled = flag in ("true", "1")
        if self.mode == "graph" and network_enabled:
            from adm_identity_lib.network_graph import configuration

            try:
                network = configuration(
                    {
                        "enabled": True,
                        "profiles": json.loads(
                            network_section.get("profiles_json", "[]")
                        ),
                        "frontends": json.loads(
                            network_section.get("frontends_json", "[]")
                        ),
                    },
                    profile,
                )
            except (ValueError, KeyError, configparser.Error) as exc:
                raise SearchError("Invalid attested network configuration.") from exc
            network_query = bounded_network_query(
                network["profiles"], profile, start, as_of
            )
        else:
            network = None
        rows = NativeSearch(
            lambda method, path, data=None: self._request(service, method, path, data)
        ).run(query)
        if network is not None:
            native_rows = NativeSearch(
                lambda method, path, data=None: self._request(
                    service, method, path, data
                )
            ).run(network_query, allow_empty=True)
            output = reduce_network_rows(
                rows, native_rows, profile, network, start, as_of, selection
            )
        else:
            output = reduce_rows(rows, profile, self.mode, start, as_of, selection)
        # SCP fixes its CSV columns from the first record. Graph records have
        # different shapes, so declare their complete union before emitting any.
        fields = sorted({key for row in output for key in row})
        for row in output:
            yield {key: row.get(key) for key in fields}

    def _request(self, session_key, method, path, data=None):
        import splunk.rest

        try:
            endpoint = urlsplit(path)
            if (
                endpoint.scheme
                or endpoint.netloc
                or not endpoint.path.startswith("/services")
            ):
                raise SearchError("Invalid local management resource.")
            args = dict(parse_qsl(endpoint.query, strict_parsing=True))
            args["output_mode"] = "json"
            response, body = splunk.rest.simpleRequest(
                endpoint.path,
                sessionKey=session_key,
                method=method,
                getargs=args,
                token=session_key.startswith("eyJ") and session_key.count(".") == 2,
                postargs=data,
                rawResult=True,
                raiseAllErrors=True,
                timeout=15,
            )
            status = int(response.status)
            if not 200 <= status < 300 or len(body) > 16 * 1024 * 1024:
                raise SearchError(
                    "identity management response failed or exceeded its bound"
                )
            return {} if method == "DELETE" else json.loads(body)
        except Exception as exc:
            # Report only the exception class, never transport content or tokens.
            raise SearchError(
                "identity management request failed (" + type(exc).__name__ + ")"
            ) from None


if __name__ == "__main__":
    dispatch(AdmQualified, sys.argv, sys.stdin, sys.stdout, __name__)
