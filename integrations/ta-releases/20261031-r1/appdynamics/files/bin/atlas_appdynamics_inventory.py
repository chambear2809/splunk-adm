#!/usr/bin/env python3
"""Additive Splunk modular input for complete AppDynamics inventory captures."""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import socket
import ssl
import sys
from urllib.parse import quote, urlsplit
import time

from tools.export_appdynamics import collect_snapshot
from tools.import_appdynamics import (
    _asset_history_output,
    _validate_asset_history_manifest,
    _validate_bundle,
    render_appdynamics_ndjson,
)


MANAGEMENT_REQUEST_TIMEOUT_SECONDS = 15


def management_url(server_uri, path):
    """Build a bounded management URL from the modular input's server_uri."""
    parsed = urlsplit(server_uri)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_management_endpoint") from exc
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValueError("invalid_management_endpoint") from exc
    if getattr(address, "scope_id", None):
        raise ValueError("invalid_management_endpoint")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or not port
    ):
        raise ValueError("invalid_management_endpoint")
    return f"https://{parsed.netloc}/{path.lstrip('/')}"


async def open_management_stream(host, port, context, deadline):
    """Connect to a numeric splunkd address without using a DNS executor."""
    address = ipaddress.ip_address(host)
    if getattr(address, "scope_id", None):
        raise ValueError("invalid_management_endpoint")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sockaddr = (
        (str(address), port, 0, 0) if address.version == 6 else (str(address), port)
    )
    sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError
        await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout=remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=context, server_hostname=host),
            timeout=remaining,
        )
        sock = None
        return reader, writer
    finally:
        if sock is not None:
            sock.close()


def management_json(server_uri, session_key, path, management_certificate_sha256=None):
    """Read one JSON management endpoint using bounded, verified HTTPS."""
    parsed = urlsplit(management_url(server_uri, path))
    host = parsed.hostname
    if not host:
        raise ValueError("invalid_management_endpoint")
    pin = management_certificate_sha256
    if pin is not None:
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
            raise ValueError("invalid_management_certificate_pin")
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError("invalid_management_certificate_pin")
        pin = pin.lower()
    port = parsed.port or 443
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    deadline = time.monotonic() + MANAGEMENT_REQUEST_TIMEOUT_SECONDS

    async def read_response():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("management_request_timeout")
        context = ssl.create_default_context()
        if pin is not None:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        reader, writer = await open_management_stream(host, port, context, deadline)
        try:
            if pin is not None:
                peer = writer.get_extra_info("ssl_object")
                certificate = peer.getpeercert(binary_form=True) if peer else None
                if not certificate or not hmac.compare_digest(
                    hashlib.sha256(certificate).hexdigest(), pin
                ):
                    raise ValueError("management_certificate_pin_mismatch")
            host_header = parsed.netloc
            writer.write(
                (
                    f"GET {request_target} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"Authorization: Splunk {session_key}\r\n"
                    "Accept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            await asyncio.wait_for(
                writer.drain(), timeout=max(0, deadline - time.monotonic())
            )
            status_line = await asyncio.wait_for(
                reader.readline(), timeout=max(0, deadline - time.monotonic())
            )
            match_status = re.fullmatch(
                rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\r?\n", status_line
            )
            if not match_status or int(match_status.group(1)) != 200:
                # Redirects are intentionally not followed; the session key must
                # never be sent to a different authority.
                raise ValueError("management_request_failed")

            headers = {}
            header_bytes = len(status_line)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("management_request_timeout")
                line = await asyncio.wait_for(reader.readline(), timeout=remaining)
                header_bytes += len(line)
                if header_bytes > 65536:
                    raise ValueError("management_response_too_large")
                if line in (b"\r\n", b"\n"):
                    break
                if b":" not in line or line.startswith((b" ", b"\t")):
                    raise ValueError("invalid_management_response")
                name, value = line.split(b":", 1)
                key = name.decode("ascii", errors="strict").lower()
                value = value.decode("ascii", errors="strict").strip()
                if key in headers:
                    raise ValueError("invalid_management_response")
                headers[key] = value

            if "transfer-encoding" in headers:
                if (
                    headers["transfer-encoding"].lower() != "chunked"
                    or "content-length" in headers
                ):
                    raise ValueError("invalid_management_response")
                chunks = []
                total = 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("management_request_timeout")
                    size_line = await asyncio.wait_for(
                        reader.readline(), timeout=remaining
                    )
                    size_token = size_line.split(b";", 1)[0].strip()
                    if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size_token):
                        raise ValueError("invalid_management_response")
                    size = int(size_token, 16)
                    if size == 0:
                        trailer_bytes = 0
                        while True:
                            trailer = await asyncio.wait_for(
                                reader.readline(),
                                timeout=max(0, deadline - time.monotonic()),
                            )
                            trailer_bytes += len(trailer)
                            if trailer_bytes > 65536:
                                raise ValueError("management_response_too_large")
                            if trailer in (b"\r\n", b"\n"):
                                break
                            if b":" not in trailer:
                                raise ValueError("invalid_management_response")
                        break
                    total += size
                    if total > 2_000_000:
                        raise ValueError("management_response_too_large")
                    chunk = await asyncio.wait_for(
                        reader.readexactly(size + 2),
                        timeout=max(0, deadline - time.monotonic()),
                    )
                    if not chunk.endswith(b"\r\n"):
                        raise ValueError("invalid_management_response")
                    chunks.append(chunk[:-2])
                payload = b"".join(chunks)
            else:
                try:
                    content_length = int(headers["content-length"])
                except (KeyError, ValueError) as exc:
                    raise ValueError("invalid_management_response") from exc
                if content_length < 0 or content_length > 2_000_000:
                    raise ValueError("management_response_too_large")
                payload = await asyncio.wait_for(
                    reader.readexactly(content_length),
                    timeout=max(0, deadline - time.monotonic()),
                )
            try:
                decoded = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("invalid_management_response") from exc
            if not isinstance(decoded, dict):
                raise ValueError("invalid_management_response")
            return decoded
        finally:
            writer.close()
            try:
                await asyncio.wait_for(
                    writer.wait_closed(), timeout=max(0, deadline - time.monotonic())
                )
            except (asyncio.TimeoutError, OSError):
                pass

    try:
        return asyncio.run(read_response())
    except asyncio.TimeoutError as exc:
        raise ValueError("management_request_timeout") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("management_request_failed") from exc


def resolve_account(
    account_name,
    session_key,
    server_uri,
    request_json=None,
    management_certificate_sha256=None,
):
    """Read the same configured account and password storage used by the vendor TA."""
    request_json = request_json or management_json
    account_path = (
        "servicesNS/nobody/Splunk_TA_AppDynamics/configs/"
        "conf-splunk_ta_appdynamics_account/"
        f"{quote(account_name, safe='')}?output_mode=json"
    )

    def request(path):
        if management_certificate_sha256 is None:
            return request_json(server_uri, session_key, path)
        return request_json(
            server_uri,
            session_key,
            path,
            management_certificate_sha256=management_certificate_sha256,
        )

    account_response = request(account_path)
    entries = account_response.get("entry")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("account_credentials_unavailable")
    config = entries[0].get("content")
    if not isinstance(config, dict):
        raise ValueError("account_credentials_unavailable")
    if not isinstance(config.get("appd_controller_url"), str) or not isinstance(
        config.get("appd_client_name"), str
    ):
        raise ValueError("account_credentials_unavailable")
    password_path = (
        "servicesNS/nobody/Splunk_TA_AppDynamics/storage/passwords"
        "?count=0&output_mode=json"
    )
    password_response = request(password_path)
    matches = []
    for entry in password_response.get("entry", []):
        content = entry.get("content", {})
        if content.get("username", "").startswith(account_name + "``splunk_cred_sep``"):
            clear = content.get("clear_password")
            if clear:
                try:
                    parsed = json.loads(clear)
                except (TypeError, json.JSONDecodeError):
                    continue
                if parsed.get("appd_client_secret"):
                    matches.append(parsed["appd_client_secret"])
    if len(matches) != 1:
        raise ValueError("account_credentials_unavailable")
    return config["appd_controller_url"], config["appd_client_name"], matches[0]


def capture_events(settings, credentials):
    """Fully validate both captures before yielding any event to Splunk."""
    index = settings.get("index", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", index):
        raise ValueError("invalid_index")
    origin, client, secret = credentials
    bundle, manifest = collect_snapshot(
        controller_origin=origin,
        controller_authority=settings["authority"],
        scope=settings["scope"],
        api_client=client,
        account_name=settings["controller_account"],
        client_secret=secret,
    )
    bundle["asset_history_manifest"] = manifest
    records, root = _validate_bundle(bundle)
    _validate_asset_history_manifest(manifest, records, root)
    inventory = render_appdynamics_ndjson(records)
    assets, _, _ = _asset_history_output(manifest)
    events = []
    for payload in (inventory, assets):
        for line in payload.splitlines():
            event = json.loads(line)
            events.append({**event, "index": index})
    return events


def main():
    # The vendor TA supplies the modular-input SDK. Credentials are retrieved
    # directly from the bounded management transport, never logged or placed in
    # environment variables.
    import import_declare_test  # noqa: F401
    from splunklib import modularinput as smi

    class Input(smi.Script):
        def get_scheme(self):
            scheme = smi.Scheme("Atlas AppDynamics Inventory")
            scheme.description = "Collect bounded current AppDynamics inventory."
            scheme.use_external_validation = False
            scheme.use_single_instance = False
            for name in (
                "global_account",
                "controller_account",
                "authority",
                "scope",
            ):
                scheme.add_argument(smi.Argument(name, required_on_create=True))
            scheme.add_argument(smi.Argument("management_certificate_sha256"))
            return scheme

        def stream_events(self, inputs, writer):
            try:
                for settings in inputs.inputs.values():
                    credentials = resolve_account(
                        settings["global_account"],
                        inputs.metadata["session_key"],
                        inputs.metadata["server_uri"],
                        management_certificate_sha256=settings.get(
                            "management_certificate_sha256"
                        ),
                    )
                    events = capture_events(settings, credentials)
                    for event in events:
                        writer.write_event(
                            smi.Event(
                                data=json.dumps(
                                    event["event"],
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                source=event["source"],
                                sourcetype=event["sourcetype"],
                                index=event["index"],
                                time=event["time"],
                            )
                        )
            except Exception:
                # Neither exception strings nor tracebacks may reveal credentials.
                writer.log(
                    smi.EventWriter.ERROR, "Atlas AppDynamics inventory capture failed"
                )
                raise RuntimeError(
                    "Atlas AppDynamics inventory capture failed"
                ) from None

    return Input().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
