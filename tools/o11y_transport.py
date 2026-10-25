"""Verified, deadline-bounded SSE transport for the pinned SignalFlow SDK.

The SDK still decodes messages and end-of-channel controls. This adapter replaces
only its HTTP stream: no redirects, ambient proxies, unbounded response reads or
automatic stream reconnects. No network request is made by importing this file.
"""

from __future__ import annotations

import http.client
import json
import queue
import re
import socket
import ssl
import threading
import time
from typing import Any, Iterator
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CHUNK_BYTES = 65_536
_EVENTS = {
    "control-message",
    "message",
    "event",
    "metadata",
    "expired-tsid",
    "data",
    "error",
}
_CONTROLS = {
    "STREAM_START",
    "JOB_START",
    "JOB_PROGRESS",
    "CHANNEL_ABORT",
    "END_OF_CHANNEL",
}


class TransportError(RuntimeError):
    """Safe generic transport error; never contains headers, token or response."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class _ResponseStream:
    def __init__(
        self,
        url: str,
        body: bytes | None,
        token: str,
        timeout: int,
        context: ssl.SSLContext,
    ):
        self.url, self.body, self.token = url, body, token
        self.deadline = time.monotonic() + timeout
        self.context = context
        self.cancelled = threading.Event()
        self.events: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=4)
        self.socket: socket.socket | None = None
        self.connection: http.client.HTTPSConnection | None = None
        self.thread = threading.Thread(
            target=self._run, daemon=True, name="atlas-signalflow-sse"
        )
        self.thread.start()

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.cancelled.is_set():
            raise TransportError(
                "SignalFlow response deadline expired or capture was cancelled."
            )
        return remaining

    def _emit(self, kind: str, payload: bytes | None = None) -> None:
        while not self.cancelled.is_set():
            try:
                self.events.put((kind, payload), timeout=min(0.05, self.remaining()))
                return
            except queue.Full:
                continue

    def _next(self) -> tuple[str, bytes | None]:
        try:
            kind, payload = self.events.get(timeout=self.remaining())
            self.remaining()
            if kind == "error":
                raise TransportError(
                    "SignalFlow HTTPS request failed; no complete capture was published."
                )
            return kind, payload
        except (queue.Empty, TransportError):
            self.close()
            raise TransportError(
                "SignalFlow HTTPS stream failed or exceeded its deadline."
            ) from None

    def wait_headers(self) -> None:
        if self._next()[0] != "headers":
            self.close()
            raise TransportError("SignalFlow returned an invalid response stream.")

    def __iter__(self) -> Iterator[bytes]:
        while True:
            kind, payload = self._next()
            if kind == "data" and payload is not None:
                yield payload
            else:
                # SDK Computation otherwise reconnects automatically after EOF.
                # A normal EOC is consumed by the SDK before another read here.
                self.close()
                raise TransportError(
                    "SignalFlow stream ended without a verified completion."
                )

    def close(self) -> None:
        self.cancelled.set()
        current = self.socket
        if current is not None:
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current.close()
            except OSError:
                pass
        if threading.current_thread() is not self.thread:
            self.thread.join(timeout=0.1)

    def _run(self) -> None:
        session = self

        class Connection(http.client.HTTPSConnection):
            def connect(self) -> None:
                session.remaining()
                # Separate TCP connection and TLS handshake so cancellation can
                # interrupt either socket before any authentication is sent.
                http.client.HTTPConnection.connect(self)
                session.socket = self.sock
                session.remaining()
                self.sock = session.context.wrap_socket(
                    self.sock, server_hostname=self.host, do_handshake_on_connect=False
                )
                session.socket = self.sock
                self.sock.settimeout(session.remaining())
                self.sock.do_handshake()
                session.remaining()

            def send(self, data: Any) -> None:
                session.remaining()
                super().send(data)
                session.remaining()

        def connection(host: str, **kwargs: Any) -> Connection:
            kwargs["timeout"] = session.remaining()
            kwargs["context"] = session.context
            result = Connection(host, **kwargs)
            session.connection = result
            return result

        class Handler(HTTPSHandler):
            def https_open(self, request: Request) -> Any:
                return self.do_open(connection, request)

        response = None
        try:
            request = Request(
                self.url,
                data=self.body,
                method="POST",
                headers={
                    "X-SF-Token": self.token,
                    "Content-Type": "text/plain",
                    "Accept": "text/event-stream",
                    "Accept-Encoding": "identity",
                },
            )
            opener = build_opener(ProxyHandler({}), _NoRedirect(), Handler())
            response = opener.open(request, timeout=self.remaining())
            if (
                response.status != 200
                or response.headers.get("Content-Type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
                != "text/event-stream"
                or response.headers.get("Content-Encoding", "identity").strip().lower()
                not in {"", "identity"}
            ):
                raise TransportError("SignalFlow returned an unsupported response.")
            length = response.headers.get("Content-Length")
            if length is not None and (
                not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES
            ):
                raise TransportError("SignalFlow response exceeds its byte cap.")
            self._emit("headers")
            total = 0
            while True:
                self.remaining()
                chunk = response.read1(CHUNK_BYTES)
                if not chunk:
                    self._emit("end")
                    break
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise TransportError("SignalFlow response exceeds its byte cap.")
                self._emit("data", chunk)
        except HTTPError as error:
            error.close()
            try:
                self._emit("error")
            except TransportError:
                pass
        except Exception:
            try:
                self._emit("error")
            except TransportError:
                pass
        finally:
            if response is not None:
                response.close()
            if self.connection is not None:
                self.connection.close()


def make_client(
    token: str, realm: str, timeout_seconds: int, ca_bundle: str | None = None
) -> Any:
    """Construct one historical-capture SDK client with verified bounded SSE."""
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 8192
        or any(ord(char) < 32 or ord(char) == 127 for char in token)
    ):
        raise TransportError("Invalid server-side SignalFlow credential.")
    if (
        not isinstance(realm, str)
        or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", realm)
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 300
    ):
        raise TransportError("Invalid SignalFlow realm or timeout.")
    context = ssl.create_default_context(cafile=ca_bundle)
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise TransportError(
            "SignalFlow requires certificate and hostname verification."
        )
    from signalfx.signalflow import SignalFlowClient
    from signalfx.signalflow.sse import SSETransport
    import sseclient

    endpoint = f"https://stream.{realm}.observability.splunkcloud.com"

    class Events:
        def __init__(self, response: _ResponseStream):
            self.response = response

        def events(self) -> Iterator[Any]:
            for event in sseclient.SSEClient(self.response).events():
                if event.event not in _EVENTS:
                    raise TransportError("Unsupported SignalFlow event type.")
                if event.event == "control-message":
                    try:
                        payload = json.loads(event.data)
                    except (ValueError, RecursionError):
                        raise TransportError(
                            "Invalid SignalFlow control message."
                        ) from None
                    if (
                        not isinstance(payload, dict)
                        or payload.get("event") not in _CONTROLS
                    ):
                        # Prevent the SDK's unknown-control logger printing data.
                        raise TransportError("Unsupported SignalFlow control message.")
                yield event

        def close(self) -> None:
            self.response.close()

    class VerifiedSSETransport(SSETransport):
        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self._streams: list[_ResponseStream] = []
            self._started = False

        def _post(self, url: str, fields: Any = None, body: Any = None) -> Events:
            target, origin = urlsplit(url), urlsplit(endpoint)
            if (
                target.scheme != origin.scheme
                or target.netloc != origin.netloc
                or target.username
                or target.password
                or target.fragment
                or target.path != "/v2/signalflow/execute"
                or target.query
                or self._started
            ):
                raise TransportError(
                    "SignalFlow capture endpoint or replay is unsupported."
                )
            self._started = True
            if fields:
                url += "?" + urlencode(
                    {
                        key: str(value).lower() if isinstance(value, bool) else value
                        for key, value in fields.items()
                    }
                )
            content = body.encode("utf-8") if isinstance(body, str) else body
            stream = _ResponseStream(url, content, token, timeout_seconds, context)
            self._streams.append(stream)
            stream.wait_headers()
            return Events(stream)

        def close(self) -> None:
            for stream in self._streams:
                stream.close()
            super().close()

    return SignalFlowClient(
        token=token,
        endpoint=endpoint,
        timeout=timeout_seconds,
        transport=VerifiedSSETransport,
        compress=False,
    )
