#!/usr/bin/env python3
"""Bounded current-point ACI snapshot modular input for the Cisco DC TA."""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import quote, urlencode, urlsplit

from atlas_aci import aci_snapshot as core

APP = "cisco_dc_networking_app_for_splunk"
CONF = "cisco_dc_networking_app_for_splunk_aci_account"
REALM = "__REST_CREDENTIAL__#cisco_dc_networking_app_for_splunk#configs/conf-cisco_dc_networking_app_for_splunk_aci_account"
SEP = "``splunk_cred_sep``"
END_MARK = SEP + SEP.join("SPLUNK") + SEP
MAX_RESPONSE = 16 * 1024 * 1024
MAX_LINE = 65536
MAX_OBJECTS = 10000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
TIMEOUT = 20
SAFE_FAILURE_CODES = frozenset(
    {
        "account_unavailable",
        "authority_mismatch",
        "credential_chunks_invalid",
        "deadline",
        "duplicate_headers",
        "duplicate_json_key",
        "event_size_limit",
        "headers_limit",
        "http_status",
        "http_unauthorized",
        "http_forbidden",
        "http_throttled",
        "http_server_error",
        "http_unavailable",
        "invalid_account",
        "invalid_apic_address",
        "invalid_chunk",
        "invalid_credential",
        "invalid_headers",
        "invalid_identity",
        "invalid_index",
        "invalid_json_number",
        "invalid_length",
        "invalid_origin",
        "invalid_pin",
        "invalid_poll_version",
        "invalid_request",
        "invalid_response",
        "login_failed",
        "object_count_limit",
        "output_size_limit",
        "pin_mismatch",
        "response_limit",
        "transport_failure",
        "unsupported_account",
        "apic_error",
        "capture_id_invalid",
        "capture_payload_cap_exceeded",
        "class_allowlist",
        "clock_regressed",
        "deadline_exceeded",
        "deadline_invalid",
        "dn_order_invalid",
        "duplicate_dn",
        "invalid_json_key",
        "limits_invalid",
        "missing_page",
        "monotonic_regressed",
        "noncanonical_data",
        "nonfinite_data",
        "page_cap_exceeded",
        "page_truncated",
        "passes_changed",
        "payload_cap_exceeded",
        "row_cap_exceeded",
        "row_class_mismatch",
        "row_count_mismatch",
        "row_dn_missing",
        "row_shape_invalid",
        "total_count_changed",
        "unsupported_data",
        "wall_clock_invalid",
        "monotonic_clock_invalid",
        "total_count_invalid",
        "total_count_negative",
    }
)


def failure_code(exc):
    if (
        type(exc) in (ValueError, core.SnapshotError)
        and len(exc.args) == 1
        and type(exc.args[0]) is str
        and exc.args[0] in SAFE_FAILURE_CODES
    ):
        return exc.args[0]
    return "unexpected_failure"


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("invalid_json_number")


def _numeric_origin(origin, *, loopback=False):
    try:
        p = urlsplit(origin)
        address = ipaddress.ip_address(p.hostname or "")
        port = p.port
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid_origin") from exc
    if (
        p.scheme != "https"
        or not port
        or p.username
        or p.password
        or p.query
        or p.fragment
        or p.path not in ("", "/")
        or getattr(address, "scope_id", None)
        or (loopback and not address.is_loopback)
    ):
        raise ValueError("invalid_origin")
    return str(address), port, p.netloc


def _pin(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise ValueError("invalid_pin")
    return value.lower()


async def open_stream(host, port, context, deadline):
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    target = (host, port, 0, 0) if address.version == 6 else (host, port)
    sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().sock_connect(sock, target),
            max(0, deadline - time.monotonic()),
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=context, server_hostname=host),
            max(0, deadline - time.monotonic()),
        )
        sock = None
        return reader, writer
    finally:
        if sock is not None:
            sock.close()


def request_json(
    origin,
    path,
    *,
    method="GET",
    body=None,
    authorization=None,
    cookie=None,
    pin=None,
    loopback_pin=False,
    deadline,
):
    """Use literal-address TLS only; check a configured DER pin before HTTP bytes."""
    host, port, host_header = _numeric_origin(
        origin, loopback=loopback_pin and pin is not None
    )
    if pin is not None:
        pin = _pin(pin)
    if (
        not path.startswith("/")
        or "\r" in path
        or "\n" in path
        or method not in ("GET", "POST")
    ):
        raise ValueError("invalid_request")
    for value, pattern in (
        (authorization, r"[A-Za-z0-9._~+/=^-]{1,8192}"),
        (cookie, r"[A-Za-z0-9._~+/=-]{1,8192}"),
    ):
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(pattern, value)
        ):
            raise ValueError("invalid_credential")
    request_deadline = min(deadline, time.monotonic() + TIMEOUT)

    async def run():
        context = ssl.create_default_context()
        if pin is not None:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        reader, writer = await open_stream(host, port, context, request_deadline)
        try:
            if pin is not None:
                peer = writer.get_extra_info("ssl_object")
                cert = peer.getpeercert(binary_form=True) if peer else None
                if not cert or not hmac.compare_digest(
                    hashlib.sha256(cert).hexdigest(), pin
                ):
                    raise ValueError("pin_mismatch")
            payload = _canonical(body) if body is not None else b""
            headers = [
                f"{method} {path} HTTP/1.1",
                f"Host: {host_header}",
                "Accept: application/json",
                "Connection: close",
            ]
            if authorization is not None:
                headers.append(f"Authorization: Splunk {authorization}")
            if cookie is not None:
                headers.append(f"Cookie: APIC-cookie={cookie}")
            if body is not None:
                headers.extend(
                    [
                        "Content-Type: application/json",
                        f"Content-Length: {len(payload)}",
                    ]
                )
            writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + payload)

            async def bounded(awaitable):
                remaining = request_deadline - time.monotonic()
                if remaining <= 0:
                    if hasattr(awaitable, "close"):
                        awaitable.close()
                    raise ValueError("deadline")
                return await asyncio.wait_for(awaitable, remaining)

            await bounded(writer.drain())
            line = await bounded(reader.readline())
            match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\r\n", line)
            if not match:
                raise ValueError("http_status")
            status = int(match.group(1))
            if status != 200:
                raise ValueError(
                    {
                        401: "http_unauthorized",
                        403: "http_forbidden",
                        429: "http_throttled",
                        500: "http_server_error",
                        502: "http_unavailable",
                        503: "http_unavailable",
                        504: "http_unavailable",
                    }.get(status, "http_status")
                )
            headers_in = {}
            header_size = len(line)
            while True:
                line = await bounded(reader.readline())
                header_size += len(line)
                if header_size > 65536:
                    raise ValueError("headers_limit")
                if line == b"\r\n":
                    break
                if b":" not in line or line.startswith((b" ", b"\t")):
                    raise ValueError("invalid_headers")
                key, value = line.split(b":", 1)
                key = key.decode("ascii").lower()
                if key in headers_in:
                    raise ValueError("duplicate_headers")
                headers_in[key] = value.decode("ascii").strip()
            if "transfer-encoding" in headers_in:
                if (
                    headers_in["transfer-encoding"].lower() != "chunked"
                    or "content-length" in headers_in
                ):
                    raise ValueError("invalid_headers")
                chunks, total = [], 0
                while True:
                    line = await bounded(reader.readline())
                    if not re.fullmatch(rb"[0-9a-fA-F]{1,8}(?:;[^\r\n]*)?\r\n", line):
                        raise ValueError("invalid_chunk")
                    size = int(line.split(b";", 1)[0].strip(), 16)
                    if size == 0:
                        if await bounded(reader.readline()) != b"\r\n":
                            raise ValueError("invalid_chunk")
                        break
                    total += size
                    if total > MAX_RESPONSE:
                        raise ValueError("response_limit")
                    chunk = await bounded(reader.readexactly(size + 2))
                    if not chunk.endswith(b"\r\n"):
                        raise ValueError("invalid_chunk")
                    chunks.append(chunk[:-2])
                payload = b"".join(chunks)
            else:
                try:
                    size = int(headers_in["content-length"])
                except (KeyError, ValueError) as exc:
                    raise ValueError("invalid_length") from exc
                if size < 0 or size > MAX_RESPONSE:
                    raise ValueError("response_limit")
                payload = await bounded(reader.readexactly(size))
            result = json.loads(
                payload,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            if not isinstance(result, dict):
                raise ValueError("invalid_response")
            return result
        finally:
            writer.close()
            try:
                await asyncio.wait_for(
                    writer.wait_closed(), max(0, request_deadline - time.monotonic())
                )
            except (asyncio.TimeoutError, OSError):
                pass

    try:
        return asyncio.run(run())
    except (asyncio.TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("transport_failure") from exc


def resolve_account(
    account, management_origin, session, management_pin, deadline, request=request_json
):
    if not isinstance(account, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,128}", account
    ):
        raise ValueError("invalid_account")
    base = f"/servicesNS/nobody/{APP}"
    options = {
        "authorization": session,
        "pin": management_pin,
        "loopback_pin": True,
        "deadline": deadline,
    }
    config = request(
        management_origin,
        f"{base}/configs/conf-{CONF}/{quote(account, safe='')}?output_mode=json",
        **options,
    )
    entries = config.get("entry")
    if (
        not isinstance(entries, list)
        or len(entries) != 1
        or not isinstance(entries[0].get("content"), dict)
    ):
        raise ValueError("account_unavailable")
    config = entries[0]["content"]
    if (
        config.get("apic_authentication_type") != "password_authentication"
        or str(config.get("apic_port")) != "443"
    ):
        raise ValueError("unsupported_account")
    host = config.get("apic_hostname")
    try:
        address = ipaddress.ip_address(host)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid_apic_address") from exc
    if getattr(address, "scope_id", None):
        raise ValueError("invalid_apic_address")
    username = config.get("apic_username")
    if not isinstance(username, str) or not username:
        raise ValueError("account_unavailable")
    response = request(
        management_origin,
        f"{base}/storage/passwords?count=0&output_mode=json",
        **options,
    )
    entries = response.get("entry")
    if not isinstance(entries, list):
        raise ValueError("account_unavailable")
    chunks = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), dict):
            raise ValueError("account_unavailable")
        item = entry["content"]
        if item.get("realm") != REALM:
            continue
        user = item.get("username", "")
        if not isinstance(user, str) or not user.startswith(account + SEP):
            continue
        suffix = user[len(account + SEP) :]
        if not re.fullmatch(r"[1-9][0-9]*", suffix):
            raise ValueError("credential_chunks_invalid")
        index = int(suffix)
        value = item.get("clear_password")
        if index in chunks or not isinstance(value, str) or index > 1000:
            raise ValueError("credential_chunks_invalid")
        chunks[index] = value
    if (
        not chunks
        or sorted(chunks) != list(range(1, len(chunks) + 1))
        or chunks[len(chunks)] != END_MARK
        or END_MARK in [chunks[i] for i in range(1, len(chunks))]
    ):
        raise ValueError("credential_chunks_invalid")
    try:
        secret = json.loads("".join(chunks[i] for i in range(1, len(chunks))))[
            "apic_password"
        ]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("account_unavailable") from exc
    if not isinstance(secret, str) or not secret:
        raise ValueError("account_unavailable")
    return str(address), username, secret


def capture_events(settings, management_origin, session, *, request=request_json):
    for name in ("authority", "fabric", "scope"):
        if not isinstance(settings.get(name), str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}", settings[name]
        ):
            raise ValueError("invalid_identity")
    if re.match(r"^(unknown|unmapped|reserved)(:|$)", settings["scope"], re.I):
        raise ValueError("invalid_identity")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", settings.get("index", "")):
        raise ValueError("invalid_index")
    version = settings.get("poll_version", "1")
    if version not in ("1", "2"):
        raise ValueError("invalid_poll_version")
    apic_pin = _pin(settings.get("apic_certificate_sha256"))
    deadline = time.monotonic() + 300
    host, username, password = resolve_account(
        settings["aci_account"],
        management_origin,
        session,
        settings.get("management_certificate_sha256"),
        deadline,
        request,
    )
    if settings["authority"] != host:
        raise ValueError("authority_mismatch")
    origin = f"https://[{host}]:443" if ":" in host else f"https://{host}:443"
    token = None
    try:
        response = request(
            origin,
            "/api/aaaLogin.json",
            method="POST",
            body={"aaaUser": {"attributes": {"name": username, "pwd": password}}},
            pin=apic_pin,
            deadline=deadline,
        )
        try:
            token = response["imdata"][0]["aaaLogin"]["attributes"]["token"]
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError("login_failed") from exc
        if not isinstance(token, str) or not re.fullmatch(
            r"[A-Za-z0-9._~+/=-]{1,8192}", token
        ):
            raise ValueError("login_failed")

        def get_page(cls, page, size):
            q = urlencode(
                {"page": page, "page-size": size, "order-by": cls + ".dn|asc"}
            )
            return request(
                origin,
                f"/api/node/class/{cls}.json?{q}",
                cookie=token,
                pin=apic_pin,
                deadline=deadline,
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("deadline")
        capture = core.capture(
            get_page,
            classes=core.CLASSES if version == "1" else core.CLASSES_V2,
            limits=core.CaptureLimits(page_size=500, deadline_seconds=remaining),
        )
        common = {
            "schema": f"application_atlas.aci_poll.v{version}",
            "schema_version": int(version),
            "capture_id": capture["capture_id"],
            "authority": settings["authority"],
            "fabric": settings["fabric"],
            "scope": settings["scope"],
            "capture_started_at": capture["capture_started_at"],
            "capture_completed_at": capture["capture_completed_at"],
            "consumer_quarantine": True,
        }
        rendered = []
        output_bytes = 0

        def append_event(event):
            nonlocal output_bytes
            line = _canonical(event)
            if len(line) >= MAX_LINE:
                raise ValueError("event_size_limit")
            output_bytes += len(line) + 1
            if output_bytes > MAX_OUTPUT_BYTES:
                raise ValueError("output_size_limit")
            rendered.append(line)

        for cls in capture["classes"]:
            for index, row in enumerate(capture["records"][cls]):
                if len(rendered) >= MAX_OBJECTS:
                    raise ValueError("object_count_limit")
                attrs = row[cls]["attributes"]
                window = capture["passes"][0][cls]["request_windows"][index // 500]
                append_event(
                    {
                        **common,
                        "record_type": "object",
                        "class": cls,
                        "dn": attrs["dn"],
                        "attributes": attrs,
                        "observation_started_at": window["started_at"],
                        "observation_completed_at": window["completed_at"],
                        "record_fingerprint": hashlib.sha256(
                            _canonical(row)
                        ).hexdigest(),
                    }
                )
        append_event(
            {
                **common,
                "record_type": "manifest",
                "complete": True,
                "classes": capture["classes"],
                "page_size": 500,
                "apic_address": host,
                "apic_certificate_sha256": apic_pin,
                "passes": capture["passes"],
                "capture_digest": capture["capture_digest"],
                "record_count": len(rendered),
            }
        )
        return rendered
    finally:
        if token is not None:
            try:
                request(
                    origin,
                    "/api/aaaLogout.json",
                    method="POST",
                    body={"aaaUser": {"attributes": {"name": username}}},
                    cookie=token,
                    pin=apic_pin,
                    deadline=deadline,
                )
            except Exception:
                pass


def main():
    import import_declare_test  # noqa: F401
    from splunklib import modularinput as smi

    class Input(smi.Script):
        def get_scheme(self):
            scheme = smi.Scheme("Atlas ACI snapshot")
            scheme.use_external_validation = False
            scheme.use_single_instance = False
            for name in (
                "aci_account",
                "authority",
                "fabric",
                "scope",
                "apic_certificate_sha256",
            ):
                scheme.add_argument(smi.Argument(name, required_on_create=True))
            scheme.add_argument(smi.Argument("management_certificate_sha256"))
            scheme.add_argument(smi.Argument("poll_version"))
            return scheme

        def stream_events(self, inputs, writer):
            try:
                for settings in inputs.inputs.values():
                    events = capture_events(
                        settings,
                        inputs.metadata["server_uri"],
                        inputs.metadata["session_key"],
                    )
                    for event in events:
                        writer.write_event(
                            smi.Event(
                                data=event.decode(),
                                source="atlas:aci_poll",
                                sourcetype=f"adm:aci_poll:v{settings.get('poll_version', '1')}",
                                index=settings["index"],
                                time=json.loads(event)["capture_completed_at"],
                            )
                        )
            except Exception as exc:
                writer.log(
                    smi.EventWriter.ERROR,
                    "Atlas ACI snapshot capture failed: " + failure_code(exc),
                )
                raise RuntimeError("Atlas ACI snapshot capture failed") from None

    return Input().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
