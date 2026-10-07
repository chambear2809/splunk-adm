"""Stdlib-only client for the local Splunk validation lab (localhost only)."""

from __future__ import annotations

import base64
import json
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECRETS = HERE / ".lab-secrets"
MGMT = "https://127.0.0.1:8089"
HEC = "https://127.0.0.1:8088"
APP = "splunk_adm"
MAX_BATCH_BYTES = 5 * 1024 * 1024

# The lab container uses a self-signed certificate and is bound to 127.0.0.1.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class LabError(RuntimeError):
    pass


def init_secrets() -> None:
    if SECRETS.exists():
        return
    password = "Adm-" + secrets.token_urlsafe(18)
    SECRETS.write_text(
        f"SPLUNK_PASSWORD={password}\nHEC_TOKEN={uuid.uuid4()}\n", encoding="utf-8"
    )
    SECRETS.chmod(0o600)


def read_secrets() -> dict[str, str]:
    if not SECRETS.exists():
        raise LabError(f"missing {SECRETS}; run lab.sh up first")
    pairs = (
        line.split("=", 1)
        for line in SECRETS.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    return {k: v for k, v in pairs}


def _open(req: urllib.request.Request, timeout: float = 120):
    try:
        return urllib.request.urlopen(req, context=_CTX, timeout=timeout)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:2000]
        raise LabError(f"HTTP {e.code} {req.full_url}: {body}") from e


def _mgmt(method: str, path: str, data: dict | None = None, timeout: float = 120):
    s = read_secrets()
    auth = base64.b64encode(f"admin:{s['SPLUNK_PASSWORD']}".encode()).decode()
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    req = urllib.request.Request(
        MGMT + path,
        data=body,
        method=method,
        headers={"Authorization": f"Basic {auth}"},
    )
    return _open(req, timeout)


def _json(method: str, path: str, data: dict | None = None) -> dict:
    sep = "&" if "?" in path else "?"
    with _mgmt(method, f"{path}{sep}output_mode=json", data) as r:
        return json.loads(r.read())


def wait_ready(timeout: float = 900) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            _json("GET", "/services/server/info")
            return
        except (LabError, OSError) as e:
            last = e
            time.sleep(5)
    raise LabError(f"splunkd not ready after {timeout}s: {last}")


def restart() -> None:
    try:
        _mgmt("POST", "/services/server/control/restart")
    except (LabError, OSError):
        pass
    time.sleep(15)
    wait_ready()


def _hec_post(body: bytes, query: str = "") -> dict:
    token = read_secrets()["HEC_TOKEN"]
    req = urllib.request.Request(
        f"{HEC}/services/collector/event{query}",
        data=body,
        method="POST",
        headers={"Authorization": f"Splunk {token}"},
    )
    with _open(req) as r:
        out = json.loads(r.read())
    if out.get("code") != 0:
        raise LabError(f"HEC rejected batch: {out}")
    return out


def load(paths, query: str = "") -> int:
    """Send HEC envelope NDJSON files to /services/collector/event in batches."""
    count, batch, size = 0, [], 0
    for path in paths:
        for n, line in enumerate(
            Path(path).read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as e:
                raise LabError(f"{path}:{n}: invalid JSON: {e}") from e
            data = line.encode()
            if batch and size + len(data) > MAX_BATCH_BYTES:
                _hec_post(b"\n".join(batch), query)
                batch, size = [], 0
            batch.append(data)
            size += len(data) + 1
            count += 1
    if batch:
        _hec_post(b"\n".join(batch), query)
    return count


def _query(spl: str) -> str:
    s = spl.strip()
    return s if s.startswith("|") or s.startswith("search ") else f"search {s}"


def _time_args(earliest, latest) -> dict:
    out = {}
    if earliest is not None:
        out["earliest_time"] = earliest
    if latest is not None:
        out["latest_time"] = latest
    return out


def _raise_messages(messages, context: str) -> None:
    errors = [
        m.get("text", "")
        for m in messages or []
        if m.get("type", "").upper() in ("FATAL", "ERROR")
    ]
    if errors:
        raise LabError(f"{context}: " + " | ".join(errors))


def _wait_job(sid: str, timeout: float = 600) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        entry = _json("GET", f"/services/search/v2/jobs/{sid}")["entry"][0]
        content = entry["content"]
        if content.get("dispatchState") == "FAILED":
            _raise_messages(content.get("messages"), f"job {sid} failed")
            raise LabError(f"job {sid} failed: {content.get('messages')}")
        if content.get("isDone"):
            _raise_messages(content.get("messages"), f"job {sid}")
            return content
        time.sleep(1)
    raise LabError(f"job {sid} did not finish in {timeout}s")


def _results(sid: str) -> list[dict]:
    out = _json("GET", f"/services/search/v2/jobs/{sid}/results?count=0")
    _raise_messages(out.get("messages"), f"job {sid} results")
    return out.get("results", [])


def search(spl: str, earliest=None, latest=None, app: str = APP) -> list[dict]:
    """Run a blocking search in the app's namespace and return all result rows."""
    data = {
        "search": _query(spl),
        "exec_mode": "blocking",
        **_time_args(earliest, latest),
    }
    with _mgmt(
        "POST", f"/servicesNS/admin/{app}/search/v2/jobs?output_mode=json", data, 900
    ) as r:
        sid = json.loads(r.read())["sid"]
    _wait_job(sid)
    return _results(sid)


def run_saved_search(name, earliest=None, latest=None, args=None, app: str = APP):
    """Dispatch a saved search and return its rows; args fill `$args.<name>$`."""
    data = {
        **{f"dispatch.{k}": v for k, v in _time_args(earliest, latest).items()},
        **{f"args.{k}": v for k, v in (args or {}).items()},
        "trigger_actions": "1",
    }
    path = (
        f"/servicesNS/nobody/{app}/saved/searches/"
        f"{urllib.parse.quote(name, safe='')}/dispatch?output_mode=json"
    )
    with _mgmt("POST", path, data) as r:
        sid = json.loads(r.read())["sid"]
    _wait_job(sid)
    return _results(sid)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "init-secrets":
            init_secrets()
        elif cmd == "wait":
            wait_ready()
        elif cmd == "restart":
            restart()
        elif cmd == "load":
            print(f"sent {load(rest)} events")
        elif cmd == "search":
            spl, *times = rest
            rows = search(spl, *(times + [None, None])[:2])
            print(json.dumps(rows, indent=2))
        elif cmd == "saved":
            name, *times = rest
            rows = run_saved_search(name, *(times + [None, None])[:2])
            print(json.dumps(rows, indent=2))
        else:
            print(f"unknown command {cmd}", file=sys.stderr)
            return 2
    except LabError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
