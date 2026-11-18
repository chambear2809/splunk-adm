"""One caller request per fresh session; fixed app code, no command input."""

import json
import os
from pathlib import Path
import resource
import signal
import sys
import threading
import time

MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
WATCHDOG_SECONDS = 42.0


def terminate_group():
    os.killpg(os.getpid(), signal.SIGKILL)


def main(*, _watchdog_seconds=WATCHDOG_SECONDS):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if sys.argv[1:] or os.getpgrp() != os.getpid() or os.getsid(0) != os.getpid():
        raise RuntimeError("isolated request session required")
    watchdog = threading.Timer(_watchdog_seconds, terminate_group)
    watchdog.daemon = True
    watchdog.start()
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if not 0 < len(raw) <= MAX_INPUT:
        raise ValueError("invalid request frame")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("invalid request frame")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from adm_cases_lib.splunk_host import SplunkHost, handle

    token = request.get("session", {}).get("authtoken")
    status, payload, headers = handle(request, SplunkHost(token))
    response = json.dumps(
        {"status": status, "payload": payload, "headers": headers},
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if not 0 < len(response) <= MAX_OUTPUT:
        raise ValueError("response too large")
    sys.stdout.buffer.write(len(response).to_bytes(4, "big") + response)
    sys.stdout.buffer.flush()
    # Keep the leader (and its watchdog) alive until the parent retires the group.
    # This also pins its PGID if the parent dies immediately after receiving data.
    while True:
        time.sleep(WATCHDOG_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        if os.getpgrp() == os.getpid() and os.getsid(0) == os.getpid():
            terminate_group()
        sys.exit(1)
