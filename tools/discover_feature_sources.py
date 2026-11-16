#!/usr/bin/env python3
"""Bounded aggregate source discovery for the explicitly selected Cloud profile."""

from __future__ import annotations

import argparse
import base64
import json
import re
import signal
import ssl
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib import error, parse, request

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.check_local_access import _profile_errors, parse_credentials

LIMIT = 256 * 1024
MACROS = (
    "adm_index_ftd",
    "adm_index_hubble",
    "adm_index_proxy_envoy",
    "adm_index_dcn",
    "adm_index_traces",
    "adm_index_netflow",
    "adm_index_dns_stream",
    "adm_index_k8s",
    "adm_index_vmware_inv",
)
FAMILIES = {
    "cisco:sfw:estreamer": "ftd",
    "cilium:hubble:flow": "hubble",
    "atlas:proxy:envoy_access": "envoy",
    "cisco:dc:aci:class": "aci",
    "cisco:dc:aci:stats": "aci",
    "otel:traces": "otel",
    "stream:netflow": "stream",
    "stream:dns": "stream",
    "kube:object:pods": "inventory",
    "kube:object:nodes": "inventory",
    "kube:object:services": "inventory",
    "kube:object:endpointslices": "inventory",
    "kube:object:httproutes": "inventory",
    "kube:object:ingresses": "inventory",
    "vmware:inv:hostsystem": "inventory",
    "vmware:inv:vm": "inventory",
    "vmware:inv:hierarchy": "inventory",
    "cisco:dc:nd:endpoints": "inventory",
    "cisco:dc:nexus9k": "inventory",
}


class Refused(Exception):
    pass


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@contextmanager
def wall_deadline(seconds: float):
    """Bound one call without extending or losing an enclosing alarm."""
    if seconds <= 0:
        raise Refused("deadline")
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining and remaining <= seconds:
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()

    def expired(_signum, _frame):
        raise Refused("deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if remaining:
            elapsed = time.monotonic() - started
            signal.setitimer(
                signal.ITIMER_REAL, max(0.000001, remaining - elapsed), interval
            )


class Client:
    def __init__(self, uri: str, user: str, password: str):
        self.uri = uri
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.opener = request.build_opener(
            request.ProxyHandler({}),
            request.HTTPSHandler(context=ssl.create_default_context()),
            NoRedirect(),
        )

    def call(self, method: str, path: str, data=None, timeout=10):
        if not path.startswith("/services/") and not path.startswith("/servicesNS/"):
            raise Refused("invalid_path")
        encoded = None if data is None else parse.urlencode(data).encode()
        req = request.Request(
            self.uri + path,
            data=encoded,
            method=method,
            headers={"Authorization": self.auth, "Accept": "application/json"},
        )
        try:
            with wall_deadline(timeout):
                with self.opener.open(req, timeout=timeout) as response:
                    raw = response.read(LIMIT + 1)
                    if len(raw) > LIMIT:
                        raise Refused("body_limit")
                    return json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise Refused(f"http_{code}") from None
        except (error.URLError, OSError, ValueError, RecursionError):
            raise Refused("request_failed") from None


def cloud_client(path: Path, profile: str) -> Client:
    if profile != "cloud" or path != Path.home() / ".splunk/splunk-adm/credentials":
        raise Refused("target_selection")
    profiles, errors = parse_credentials(path)
    if errors or any(_profile_errors(name, cfg) for name, cfg in profiles.items()):
        raise Refused("profile_invalid")
    cfg = profiles["cloud"]
    uri = cfg.get("SPLUNK_URI") or cfg.get("SPLUNK_SEARCH_API_URI", "")
    if uri != f"https://{cfg.get('SPLUNK_CLOUD_STACK')}.splunkcloud.com:8089":
        raise Refused("target_mismatch")
    return Client(uri, cfg["SPLUNK_USER"], cfg["SPLUNK_PASS"])


def indexes(client: Client, macro_names: tuple[str, ...] = MACROS) -> list[str]:
    found = set()
    if not macro_names or any(name not in MACROS for name in macro_names):
        raise Refused("invalid_macro_selection")
    for name in macro_names:
        payload = client.call(
            "GET", f"/servicesNS/nobody/splunk_adm/admin/macros/{name}?output_mode=json"
        )
        entries = payload.get("entry", [])
        if len(entries) != 1 or entries[0].get("name") != name:
            raise Refused("macro_metadata_invalid")
        definition = entries[0].get("content", {}).get("definition", "")
        match = re.fullmatch(
            r'\s*index\s*=\s*(?:"([a-zA-Z0-9][a-zA-Z0-9_-]{0,127})"|([a-zA-Z0-9][a-zA-Z0-9_-]{0,127}))\s*',
            definition,
        )
        if not match:
            raise Refused("macro_definition_unsupported")
        value = match.group(1) or match.group(2)
        if value.lower() not in ("unconfigured_optional", "unconfigured_dns"):
            found.add(value)
    if not found:
        raise Refused("no_configured_indexes")
    return sorted(found)


def discover(client: Client, names: list[str], now: int | None = None) -> dict:
    if not names or any(
        not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", n) for n in names
    ):
        raise Refused("invalid_indexes")
    end = int(time.time()) if now is None else now
    query = (
        "| tstats count min(_time) AS first max(_time) AS last WHERE index IN("
        + ",".join('"' + n + '"' for n in sorted(set(names)))
        + ") BY index sourcetype"
    )
    deadline = time.monotonic() + 35
    sid = None
    output = {"status": "error", "cleanup": "not_started"}
    if signal.getitimer(signal.ITIMER_REAL)[0]:
        raise Refused("active_timer")

    def deadline_expired(_signum, _frame):
        raise Refused("deadline")

    previous_handler = signal.signal(signal.SIGALRM, deadline_expired)
    signal.setitimer(signal.ITIMER_REAL, 35)
    try:
        # A lost creation response can leave a job whose identifier is unknown.
        output["cleanup"] = "unconfirmed"
        created = client.call(
            "POST",
            "/services/search/jobs?output_mode=json",
            {
                "search": query,
                "earliest_time": str(end - 86400),
                "latest_time": str(end),
                "max_time": "20",
                "ttl": "60",
                "auto_cancel": "30",
                "exec_mode": "normal",
            },
            timeout=max(0.1, deadline - time.monotonic()),
        )
        sid = created.get("sid")
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", sid):
            sid = None
            raise Refused("invalid_job_id")
        path = "/services/search/jobs/" + parse.quote(sid, safe="")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused("deadline")
            job = client.call("GET", path + "?output_mode=json", timeout=remaining)
            entries = job.get("entry", [])
            if len(entries) != 1 or not isinstance(entries[0].get("content"), dict):
                raise Refused("job_metadata_invalid")
            info = entries[0]["content"]
            if info.get("messages") or job.get("messages"):
                raise Refused("job_messages")
            if info.get("dispatchState") in ("FAILED", "CANCELED", "FINALIZED"):
                raise Refused("job_incomplete")
            if info.get("isDone") in (True, 1, "1"):
                if (
                    info.get("dispatchState") != "DONE"
                    or int(info.get("resultCount", 0)) > 100
                ):
                    raise Refused("job_incomplete_or_capped")
                break
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refused("deadline")
        results = client.call(
            "GET", path + "/results?output_mode=json&count=100", timeout=remaining
        )
        rows = results.get("results")
        if (
            results.get("preview") not in (False, "0", 0)
            or results.get("messages")
            or not isinstance(rows, list)
            or len(rows) > 100
        ):
            raise Refused("results_incomplete_or_capped")
        families = {
            name: {"count": 0, "first": None, "last": None}
            for name in sorted(set(FAMILIES.values()))
        }
        unknown = 0
        for row in rows:
            if not isinstance(row, dict) or row.get("index") not in names:
                raise Refused("result_invalid")
            family = FAMILIES.get(row.get("sourcetype"))
            if not family:
                unknown += 1
                continue
            try:
                count, first, last = (
                    int(row["count"]),
                    float(row["first"]),
                    float(row["last"]),
                )
            except (KeyError, TypeError, ValueError, OverflowError):
                raise Refused("result_invalid") from None
            if count < 0 or not end - 86400 <= first <= last <= end:
                raise Refused("result_invalid")
            item = families[family]
            item["count"] += count
            item["first"] = (
                min(item["first"], first) if item["first"] is not None else first
            )
            item["last"] = max(item["last"], last) if item["last"] is not None else last
        output.update(
            status="ok",
            families=families,
            unknown_rows=unknown,
            window_seconds=86400,
            zero_counts_prove_absence=False,
        )
    except (Refused, TypeError, ValueError, OverflowError) as exc:
        output["reason"] = str(exc) if isinstance(exc, Refused) else "invalid_response"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if sid is not None:
            try:
                client.call(
                    "DELETE",
                    "/services/search/jobs/"
                    + parse.quote(sid, safe="")
                    + "?output_mode=json",
                    timeout=5,
                )
                output["cleanup"] = "ok"
            except Refused:
                output["cleanup"] = "failed"
                output["status"] = "error"
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--profile", required=True, choices=["cloud"])
    parser.add_argument("--run", required=True, action="store_true")
    args = parser.parse_args()
    try:
        client = cloud_client(args.credentials, args.profile)
        result = discover(client, indexes(client))
    except Refused as exc:
        result = {"status": "error", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
