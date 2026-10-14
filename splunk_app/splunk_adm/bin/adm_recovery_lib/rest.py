"""Token-only, TLS-verified REST access using the vendored Splunk SDK."""

from __future__ import annotations

import json
import errno
import socket
import ssl
from urllib.error import URLError
from urllib.parse import parse_qsl, urlsplit

from splunklib import binding


class ApiError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Splunk REST HTTP {status}")


class TransportTimeout(RuntimeError):
    """The local management request exceeded its transport timeout."""


def is_transport_timeout(exc):
    """Recognize socket timeouts, including urllib's wrapped form."""
    if isinstance(exc, TransportTimeout):
        return True
    reason = exc.reason if isinstance(exc, URLError) else exc
    return isinstance(reason, (TimeoutError, socket.timeout)) or (
        isinstance(reason, OSError) and reason.errno == errno.ETIMEDOUT
    )


class Rest:
    def __init__(self, session_key, uri="https://localhost:8089", ca_file=None):
        endpoint = urlsplit(uri)
        if (
            endpoint.scheme != "https"
            or endpoint.username
            or endpoint.password
            or endpoint.path not in ("", "/")
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("management_uri must be an HTTPS origin")
        if endpoint.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError(
                "standalone recovery requires the local management endpoint"
            )
        if not session_key:
            raise ValueError("owner session_key is required")
        self.token = session_key
        self.host = endpoint.hostname
        self.port = endpoint.port or 8089
        self.context = ssl.create_default_context(cafile=ca_file or None)

    def request(self, method, path, data=None, json_body=False, timeout=30):
        client = binding.Context(
            host=self.host,
            port=self.port,
            scheme="https",
            token=self.token,
            autologin=False,
            retries=0,
            handler=binding.handler(timeout=timeout, verify=True, context=self.context),
        )
        parts = urlsplit(path)
        if parts.scheme or parts.netloc or not parts.path.startswith("/services"):
            raise ValueError("invalid local REST path")
        # Callers escape each path segment. Preserve that escaping through the
        # SDK; a plain string would encode '%' again (saved-search names fail).
        path_segment = binding.UrlEncoded(parts.path, skip_encode=True)
        params = dict(parse_qsl(parts.query))
        params["output_mode"] = "json"
        try:
            if method == "GET":
                response = client.get(path_segment, **params)
            elif method == "POST":
                headers = [("Content-Type", "application/json")] if json_body else []
                body = json.dumps(data).encode() if json_body else data or {}
                response = client.post(
                    path_segment, headers=headers, body=body, **params
                )
            elif method == "DELETE":
                response = client.delete(path_segment, **params)
            else:
                raise ValueError("unsupported REST method")
            with response.body as stream:
                raw = stream.read()
            if response.status >= 300:
                raise ApiError(response.status)
            return json.loads(raw) if raw else {}
        except binding.HTTPError as exc:
            # Do not log response bodies, auth headers, or the session token.
            raise ApiError(exc.status) from None
        except (TimeoutError, socket.timeout, URLError) as exc:
            if is_transport_timeout(exc):
                raise TransportTimeout() from None
            raise
