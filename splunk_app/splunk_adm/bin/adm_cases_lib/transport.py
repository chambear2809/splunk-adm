"""Supervise fixed local management requests without exposing session credentials."""

import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

MAX_INPUT = 64 * 1024
MAX_BODY = 2 * 1024 * 1024
MAX_CA = 128 * 1024


def _read_ca(path):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in (0, os.getuid())
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > MAX_CA
        ):
            raise ValueError()
        chunks = bytearray()
        while len(chunks) <= MAX_CA:
            data = os.read(descriptor, min(65536, MAX_CA + 1 - len(chunks)))
            if not data:
                break
            chunks.extend(data)
        after = os.fstat(descriptor)
        if (
            not chunks
            or len(chunks) > MAX_CA
            or (
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
                before.st_mode,
                before.st_uid,
                before.st_gid,
                before.st_nlink,
            )
            != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_nlink,
            )
            or b"PRIVATE KEY" in bytes(chunks).upper()
        ):
            raise ValueError()
        ca = bytes(chunks)
        cadata = ca.decode("ascii") if b"-----BEGIN" in ca else ca
        ssl.create_default_context(cadata=cadata)
        return ca
    finally:
        os.close(descriptor)


class TransportError(RuntimeError):
    """Generic failure; a POST may have reached the server when uncertain."""

    def __init__(self, status=None, uncertain=False):
        super().__init__("management request unavailable")
        self.status = status
        self.uncertain = uncertain


def _worker_environment():
    # Splunk's embedded Linux Python needs its own public shared libraries.
    # Do not inherit caller-controlled loader paths or the surrounding env.
    environment = {"LANG": "C.UTF-8"}
    home = os.environ.get("SPLUNK_HOME")
    if sys.platform == "linux" and home:
        try:
            root = Path(home)
            if not root.is_absolute():
                raise ValueError()
            root = root.resolve(strict=True)
            if Path(sys.executable).resolve(strict=True).parent == root / "bin":
                library = root / "lib"
                info = library.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid not in (0, os.getuid())
                    or stat.S_IMODE(info.st_mode) & 0o022
                ):
                    raise ValueError()
                environment["LD_LIBRARY_PATH"] = str(library)
        except (OSError, ValueError):
            raise TransportError() from None
    return environment


class SupervisedTransport:
    def __init__(self, token, origin, ca_file, *, _worker_path=None):
        try:
            endpoint = urlsplit(origin)
            port = endpoint.port
            if (
                endpoint.scheme != "https"
                or endpoint.hostname not in ("localhost", "127.0.0.1", "::1")
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.path not in ("", "/")
                or endpoint.query
                or endpoint.fragment
                or (port is not None and not 1 <= port <= 65535)
                or not isinstance(token, str)
                or not token
                or len(token) > 16384
                or any(ord(c) < 33 or ord(c) > 126 for c in token)
            ):
                raise ValueError()
            ca = _read_ca(ca_file)
            host = (
                f"[{endpoint.hostname}]"
                if endpoint.hostname == "::1"
                else endpoint.hostname
            )
            canonical_origin = f"https://{host}:{port or 8089}"
        except (OSError, TypeError, ValueError, UnicodeError, ssl.SSLError):
            raise TransportError() from None
        self.token, self.origin, self.ca_bytes = token, canonical_origin, ca
        self.trust_digest = hashlib.sha256(
            canonical_origin.encode("ascii") + b"\0" + ca
        ).hexdigest()
        self.worker = _worker_path or str(
            Path(__file__).with_name("transport_worker.py")
        )

    def __call__(self, method, path, data, timeout):
        if (
            method not in ("GET", "POST", "DELETE")
            or not isinstance(path, str)
            or len(path) > 4096
            or (data is not None and not isinstance(data, dict))
            or (
                isinstance(data, dict)
                and (
                    len(data) > 32
                    or any(
                        not isinstance(key, str)
                        or not isinstance(value, str)
                        or len(key) > 256
                        or len(value) > MAX_INPUT
                        for key, value in data.items()
                    )
                )
            )
            or type(timeout) not in (int, float)
            or not 0 < timeout <= 30
        ):
            raise TransportError()
        try:
            payload = (
                json.dumps(
                    {
                        "token": self.token,
                        "origin": self.origin,
                        "ca_length": len(self.ca_bytes),
                        "method": method,
                        "path": path,
                        "data": data,
                        "timeout": timeout,
                    },
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise TransportError() from None
        if len(payload) > MAX_INPUT:
            raise TransportError()
        payload += self.ca_bytes
        return self._exchange(payload, timeout, method=method)

    def preflight(self):
        return self._exchange(b"", 3, method="GET", preflight=True) == {"ready": True}

    def _exchange(self, payload, timeout, *, method, preflight=False):
        deadline = time.monotonic() + timeout
        process = None
        output = bytearray()
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", self.worker]
                + (["--preflight"] if preflight else []),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_worker_environment(),
                close_fds=True,
            )
            uncertain = method == "POST"
            if time.monotonic() >= deadline:
                raise TransportError(uncertain=uncertain)
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin, selectors.EVENT_WRITE)
                selector.register(process.stdout, selectors.EVENT_READ)
                sent = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TransportError(uncertain=uncertain)
                    events = selector.select(remaining)
                    if not events:
                        raise TransportError(uncertain=uncertain)
                    for key, _ in events:
                        if key.fileobj is process.stdin:
                            try:
                                count = os.write(process.stdin.fileno(), payload[sent:])
                            except BlockingIOError:
                                continue
                            sent += count
                            if sent == len(payload):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                        else:
                            try:
                                chunk = os.read(process.stdout.fileno(), 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(process.stdout)
                                process.stdout.close()
                            else:
                                output.extend(chunk)
                                if len(output) > MAX_BODY + 4:
                                    raise TransportError(uncertain=uncertain)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(uncertain=uncertain)
            if process.wait(timeout=remaining) != 0 or len(output) < 4:
                raise TransportError(uncertain=uncertain)
            status = int.from_bytes(output[:4], "big")
            if not 200 <= status < 300:
                raise TransportError(
                    status=status if 100 <= status <= 599 else None, uncertain=uncertain
                )
            result = (
                {} if method == "DELETE" and not output[4:] else json.loads(output[4:])
            )
            if not isinstance(result, dict) or time.monotonic() >= deadline:
                raise TransportError(uncertain=uncertain)
            return result
        except TransportError:
            raise
        except (
            OSError,
            ValueError,
            TypeError,
            subprocess.SubprocessError,
            RecursionError,
        ):
            raise TransportError(
                uncertain=method == "POST" and process is not None
            ) from None
        finally:
            if process is not None:
                for pipe in (process.stdin, process.stdout):
                    if pipe and not pipe.closed:
                        pipe.close()
                if process.poll() is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                process.wait()
