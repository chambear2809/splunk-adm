"""Single-purpose worker: fixed Splunk management endpoints and bounded bodies."""

import http.client
import json
import re
import resource
import ssl
import sys
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

MAX_INPUT = 64 * 1024
MAX_BODY = 2 * 1024 * 1024
MAX_CA = 128 * 1024
_JOB = re.compile(
    r"/services/search/(?:v2/)?jobs/([A-Za-z0-9_.%:-]{1,765})(/results)?\Z"
)

_QUERY = re.compile(
    r'\| admqualified mode=graph service="([A-Za-z0-9][A-Za-z0-9._:/@-]{0,254})" '
    r'environment="([A-Za-z0-9][A-Za-z0-9._-]{0,127})" '
    r'cluster="([A-Za-z0-9][A-Za-z0-9._-]{0,252})" '
    r'namespace="([a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)" '
    r"start=(0|[1-9][0-9]{0,15}) as_of=(0|[1-9][0-9]{0,15})\Z"
)


def request(value, ca):
    if set(value) != {
        "token",
        "origin",
        "ca_length",
        "method",
        "path",
        "data",
        "timeout",
    }:
        raise ValueError()
    origin = urlsplit(value["origin"])
    if (
        origin.scheme != "https"
        or origin.hostname not in ("localhost", "127.0.0.1", "::1")
        or origin.username is not None
        or origin.password is not None
        or origin.path not in ("", "/")
        or origin.query
        or origin.fragment
    ):
        raise ValueError()
    token = value["token"]
    if (
        not isinstance(ca, bytes)
        or not 0 < len(ca) <= MAX_CA
        or value["ca_length"] != len(ca)
        or b"PRIVATE KEY" in ca.upper()
        or not isinstance(token, str)
        or not token
        or any(ord(c) < 33 or ord(c) > 126 for c in token)
    ):
        raise ValueError()
    method, path, data = value["method"], value["path"], value["data"]
    target = urlsplit(path)
    if target.scheme or target.netloc or target.fragment:
        raise ValueError()
    params = parse_qsl(target.query, strict_parsing=True)
    if len(params) != len(dict(params)):
        raise ValueError()
    query = dict(params)
    match = _JOB.fullmatch(target.path)
    permitted = (
        method == "GET"
        and target.path
        in ("/services/authentication/current-context", "/services/server/info")
        and not query
        or method == "POST"
        and target.path == "/servicesNS/nobody/splunk_adm/search/v2/jobs"
        and not query
        or match
        and method in ("GET", "DELETE")
        and (
            (
                match.group(2) is None
                and target.path.startswith("/services/search/jobs/")
                and not query
            )
            or (
                match.group(2) == "/results"
                and target.path.startswith("/services/search/v2/jobs/")
                and method == "GET"
                and query == {"count": "2000", "offset": "0"}
            )
        )
    )
    if not permitted:
        raise ValueError()
    if match:
        sid = unquote(match.group(1))
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", sid) or quote(
            sid, safe=""
        ) != match.group(1):
            raise ValueError()
    if method == "POST":
        allowed = {
            "search",
            "earliest_time",
            "latest_time",
            "exec_mode",
            "max_time",
            "auto_cancel",
            "ttl",
            "status_buckets",
        }
        if (
            not isinstance(data, dict)
            or set(data) - allowed
            or any(not isinstance(v, str) for v in data.values())
        ):
            raise ValueError()
        required = {
            "search",
            "earliest_time",
            "latest_time",
            "exec_mode",
            "max_time",
            "auto_cancel",
            "ttl",
            "status_buckets",
        }
        if not required <= set(data):
            raise ValueError()
        match_query = _QUERY.fullmatch(data["search"])
        if (
            match_query is None
            or data["earliest_time"] != match_query.group(5)
            or data["latest_time"] != match_query.group(6)
            or not 0 < int(match_query.group(6)) - int(match_query.group(5)) <= 300
            or {
                key: data[key]
                for key in (
                    "exec_mode",
                    "max_time",
                    "auto_cancel",
                    "ttl",
                    "status_buckets",
                )
            }
            != {
                "exec_mode": "normal",
                "max_time": "5",
                "auto_cancel": "10",
                "ttl": "30",
                "status_buckets": "0",
            }
        ):
            raise ValueError()
        body = urlencode(data).encode("utf-8")
    elif data is None:
        body = None
    else:
        raise ValueError()
    query["output_mode"] = "json"
    request_path = target.path + "?" + urlencode(query)
    cadata = ca.decode("ascii") if b"-----BEGIN" in ca else ca
    context = ssl.create_default_context(cadata=cadata)
    conn = http.client.HTTPSConnection(
        origin.hostname,
        origin.port or 8089,
        context=context,
        timeout=float(value["timeout"]),
    )
    try:
        authorization = (
            "Bearer "
            if token.startswith("eyJ") and token.count(".") == 2
            else "Splunk "
        ) + token
        headers = {
            "Authorization": authorization,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, request_path, body=body, headers=headers)
        response = conn.getresponse()
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError()
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError()
        return response.status, raw
    finally:
        conn.close()


def main():
    # Set limits after interpreter start; never use preexec_fn in the host.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    if sys.argv[1:] == ["--preflight"]:
        # Exercise imports and representative bounded allocation after limits,
        # without accepting a session token or contacting any peer.
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        bytearray(MAX_BODY + MAX_CA + MAX_INPUT)
        sys.stdout.buffer.write((200).to_bytes(4, "big") + b'{"ready":true}')
        sys.stdout.buffer.flush()
        return
    if sys.argv[1:]:
        raise ValueError()
    frame = sys.stdin.buffer.readline(MAX_INPUT + 1)
    if len(frame) > MAX_INPUT or not frame.endswith(b"\n"):
        raise ValueError()
    value = json.loads(frame)
    length = value.get("ca_length")
    if type(length) is not int or not 0 < length <= MAX_CA:
        raise ValueError()
    ca = sys.stdin.buffer.read(length)
    if len(ca) != length:
        raise ValueError()
    status, body = request(value, ca)
    sys.stdout.buffer.write(status.to_bytes(4, "big") + body)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(1)
