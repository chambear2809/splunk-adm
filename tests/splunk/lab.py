"""Stdlib-only client for the local Splunk validation lab (localhost only)."""

from __future__ import annotations

import base64
import functools
import io
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import lab_tls

HERE = Path(__file__).resolve().parent
SECRETS = Path(
    os.environ.get(
        "ADM_LAB_SECRETS",
        str(
            HERE
            / (
                ".lab-secrets"
                + (
                    "-" + os.environ["ADM_LAB_NAME"]
                    if os.environ.get("ADM_LAB_NAME")
                    else ""
                )
            )
        ),
    )
)
MGMT = f"https://127.0.0.1:{int(os.environ.get('ADM_LAB_MGMT_PORT', '8089'))}"
HEC = f"https://127.0.0.1:{int(os.environ.get('ADM_LAB_HEC_PORT', '8088'))}"
WEB = f"https://127.0.0.1:{int(os.environ.get('ADM_LAB_WEB_PORT', '8000'))}"
IMAGE = "splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4"
APP = "splunk_adm"
MAX_BATCH_BYTES = 5 * 1024 * 1024
TASK_CPU_NANOS = 4_000_000_000
TASK_MEMORY_BYTES = 8 * 1024**3
TASK_PIDS_LIMIT = 1024
TASK_LOG_CONFIG = {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "2"}}


class LabError(RuntimeError):
    pass


def task_identity() -> tuple[str, str] | None:
    task = os.environ.get("ADM_LAB_TASK")
    if not task:
        return None
    name = os.environ.get("ADM_LAB_NAME", "")
    if (
        not re.fullmatch(r"[a-z0-9-]+", task)
        or not re.fullmatch(r"adm-[a-z0-9-]+", name)
        or name == "adm-splunk-lab"
    ):
        raise LabError("invalid task lab identity")
    return task, name


def local_docker_endpoint() -> str:
    """Pin task operations to a local daemon before creating any resource."""
    context = os.environ.get("DOCKER_CONTEXT")
    endpoint = os.environ.get("DOCKER_HOST") if not context else None
    if not endpoint:
        command = ["docker", "context", "inspect"]
        if context:
            command.append(context)
        command.extend(["--format", "{{.Endpoints.docker.Host}}"])
        endpoint = subprocess.check_output(command, text=True, timeout=30).strip()
    if not endpoint.startswith("unix:///"):
        raise LabError("task labs require a local Docker Unix socket")
    os.environ.pop("DOCKER_CONTEXT", None)
    os.environ["DOCKER_HOST"] = endpoint
    return endpoint


def _verify_resource_limits(host: dict) -> None:
    if (
        host.get("NanoCpus") != TASK_CPU_NANOS
        or host.get("Memory") != TASK_MEMORY_BYTES
        or host.get("MemorySwap") != TASK_MEMORY_BYTES
        or host.get("PidsLimit") != TASK_PIDS_LIMIT
        or host.get("LogConfig") != TASK_LOG_CONFIG
    ):
        raise LabError("refusing task lab with mismatched resource limits")


def verify_target(
    *, expected_id: str | None = None, registering=False, require_limits: bool = True
) -> None:
    """Task labs refuse operations against an unowned or misrouted container."""
    identity = task_identity()
    if identity is None:
        return
    task, name = identity
    local_docker_endpoint()
    result = subprocess.run(
        ["docker", "inspect", name],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    target = json.loads(result.stdout)[0]
    if registering:
        if expected_id is None or not re.fullmatch(r"[a-f0-9]{64}", expected_id):
            raise LabError("a newly created container ID is required")
    else:
        recorded = lab_tls.read_container(SECRETS, identity)
        if expected_id is not None and expected_id != recorded:
            raise LabError("task container identity differs from the recorded ID")
        expected_id = recorded
    if target.get("Id") != expected_id:
        raise LabError("refusing a replaced task container")
    config = target.get("Config", {})
    if config.get("Image") != IMAGE or (config.get("Healthcheck") or {}).get(
        "Test"
    ) != ["NONE"]:
        raise LabError(
            "task lab requires the pinned image and disabled image healthcheck"
        )
    labels = target.get("Config", {}).get("Labels") or {}
    if (
        labels.get("org.splunk-adm.task") != task
        or labels.get("org.splunk-adm.lab") != name
    ):
        raise LabError("refusing unowned task lab")
    host = target.get("HostConfig", {})
    if require_limits:
        _verify_resource_limits(host)
    if host.get("NetworkMode") != name + "-net":
        raise LabError("refusing task lab with mismatched network")
    expected_mounts = {
        "/opt/splunk/etc": name + "-etc",
        "/opt/splunk/var": name + "-var",
    }
    mounts = {item.get("Destination"): item for item in target.get("Mounts", [])}
    for destination, volume in expected_mounts.items():
        if (
            mounts.get(destination, {}).get("Name") != volume
            or mounts[destination].get("Type") != "volume"
        ):
            raise LabError("refusing task lab with mismatched volumes")
    bindings = host.get("PortBindings", {})
    for internal, variable, default in (
        ("8000/tcp", "ADM_LAB_WEB_PORT", "8000"),
        ("8089/tcp", "ADM_LAB_MGMT_PORT", "8089"),
        ("8088/tcp", "ADM_LAB_HEC_PORT", "8088"),
    ):
        if bindings.get(internal) != [
            {"HostIp": "127.0.0.1", "HostPort": os.environ.get(variable, default)}
        ]:
            raise LabError("refusing task lab with mismatched loopback ports")


def verify_cleanup_target() -> None:
    """Verify every normal guard while allowing legacy missing resource caps."""
    verify_target(require_limits=False)


def task_resources(remove: bool = False) -> None:
    """Create or remove only resources bearing the task and lab labels."""
    identity = task_identity()
    if identity is None:
        return
    task, name = identity
    local_docker_endpoint()
    for kind, suffix in (("network", "net"), ("volume", "etc"), ("volume", "var")):
        resource = f"{name}-{suffix}"
        inventory = subprocess.run(
            ["docker", kind, "ls", "--format", "{{.Name}}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        if resource in inventory.stdout.splitlines():
            result = subprocess.run(
                ["docker", kind, "inspect", resource],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            labels = json.loads(result.stdout)[0].get("Labels") or {}
            if (
                labels.get("org.splunk-adm.task") != task
                or labels.get("org.splunk-adm.lab") != name
            ):
                raise LabError("refusing unowned task resource")
            if remove:
                subprocess.run(
                    ["docker", kind, "rm", resource],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    timeout=30,
                )
        elif not remove:
            subprocess.run(
                [
                    "docker",
                    kind,
                    "create",
                    "--label",
                    f"org.splunk-adm.task={task}",
                    "--label",
                    f"org.splunk-adm.lab={name}",
                    resource,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )


def init_secrets() -> None:
    lab_tls.tls_directory(SECRETS)
    if os.path.lexists(SECRETS):
        read_secrets()
        return
    password = "Adm-" + secrets.token_urlsafe(18)
    descriptor = os.open(
        SECRETS,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(f"SPLUNK_PASSWORD={password}\nHEC_TOKEN={uuid.uuid4()}\n")


def read_secrets() -> dict[str, str]:
    lab_tls.tls_directory(SECRETS)
    try:
        descriptor = os.open(SECRETS, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise LabError("unsafe lab credential file")
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise LabError("invalid lab credential file")
        data = raw.decode("utf-8")
        pairs = [line.split("=", 1) for line in data.splitlines()]
        if (
            len(data) > 65536
            or len(pairs) != 2
            or any(len(pair) != 2 or not pair[1] for pair in pairs)
            or {pair[0] for pair in pairs} != {"SPLUNK_PASSWORD", "HEC_TOKEN"}
        ):
            raise LabError("invalid lab credential file")
        return dict(pairs)
    except (OSError, UnicodeDecodeError) as exc:
        raise LabError("lab credentials are missing or unsafe") from exc


@functools.lru_cache(maxsize=1)
def _context():
    return lab_tls.tls_context(SECRETS, identity=task_identity())


def __getattr__(name):
    # Preserve endpoint test compatibility without constructing trust during
    # pre-container initialization or reading private keys into diagnostics.
    if name == "_CTX":
        return _context()
    raise AttributeError(name)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LabError("lab HTTP redirects are prohibited")


def urlopen(req: urllib.request.Request, timeout: float = 120):
    try:
        target = urllib.parse.urlsplit(req.full_url)
        port = target.port
    except ValueError as exc:
        raise LabError("lab requests require an exact loopback HTTPS target") from exc
    if (
        target.scheme != "https"
        or target.hostname != "127.0.0.1"
        or target.username is not None
        or target.password is not None
        or target.fragment
        or port
        not in {
            urllib.parse.urlsplit(MGMT).port,
            urllib.parse.urlsplit(HEC).port,
            *(
                [urllib.parse.urlsplit(WEB).port]
                if task_identity() is not None
                and os.environ.get("ADM_LAB_WEB_TLS") == "1"
                else []
            ),
        }
    ):
        raise LabError("lab requests require an exact loopback HTTPS target")
    verify_target()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=_context()),
    )
    return opener.open(req, timeout=timeout)


def init_tls():
    identity = task_identity()
    if identity is None:
        raise LabError("new disposable labs require an explicit task identity")
    return lab_tls.prepare_tls(SECRETS, *identity)


def remember_container(container_id):
    identity = task_identity()
    if identity is None:
        raise LabError("new disposable labs require an explicit task identity")
    verify_target(expected_id=container_id, registering=True)
    lab_tls.remember_container(SECRETS, identity, container_id)


def start_container():
    identity = task_identity()
    if identity is None:
        raise LabError("startup requires an explicit task identity")
    verify_target()
    container_id = lab_tls.read_container(SECRETS, identity)
    target = json.loads(
        subprocess.check_output(
            ["docker", "inspect", container_id], text=True, timeout=30
        )
    )[0]
    status = target.get("State", {}).get("Status")
    if status == "created":
        # A previous copy may have failed after the ID was recorded. Never
        # start that peer until the complete fixed TLS set has been restaged.
        stage_tls()
    elif status not in ("running", "exited"):
        raise LabError("task container is not in a startable state")
    verify_target(expected_id=container_id)
    subprocess.run(
        ["docker", "start", container_id],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )


def stage_tls():
    """Stage fixed TLS files before starting the recorded disposable peer."""
    verify_target()
    identity = task_identity()
    if identity is None:
        raise LabError("TLS staging requires an explicit task identity")
    container_id = lab_tls.read_container(SECRETS, identity)
    target = json.loads(
        subprocess.check_output(
            ["docker", "inspect", container_id], text=True, timeout=30
        )
    )[0]
    if target.get("State", {}).get("Status") != "created":
        raise LabError("TLS staging is permitted only before initial startup")
    directory = Path(str(SECRETS) + ".tls")
    # Context construction validates the public CA and protected task directory.
    lab_tls.tls_context(SECRETS, identity=identity)
    prefix = "/opt/splunk/etc/auth/adm_lab_tls/"
    files = {
        "etc/auth/adm_lab_tls/server.pem": lab_tls.server_bundle(SECRETS, identity),
        "etc/auth/adm_lab_tls/ca.pem": (directory / "ca.pem").read_bytes(),
        "etc/system/local/server.conf": (
            f"[general]\nserverName = {identity[1]}\n\n[sslConfig]\n"
            f"serverCert = {prefix}server.pem\nsslRootCAPath = {prefix}ca.pem\n"
            "sslPassword =\ncliVerifyServerName = true\n"
        ).encode(),
        "etc/system/local/inputs.conf": (
            f"[http]\nenableSSL = 1\nserverCert = {prefix}server.pem\nsslPassword =\n"
        ).encode(),
    }
    if os.environ.get("ADM_LAB_WEB_TLS") == "1":
        files["etc/system/local/web.conf"] = (
            "[settings]\nenableSplunkWebSSL = true\n"
            f"privKeyPath = {prefix}server.pem\nserverCert = {prefix}server.pem\n"
        ).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as output:
        parents = sorted(
            {
                str(parent)
                for name in files
                for parent in Path(name).parents
                if str(parent) != "."
            },
            key=lambda name: (len(Path(name).parts), name),
        )
        for name in parents:
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, 0o755
            member.uid = member.gid = 41812
            output.addfile(member)
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.uid = member.gid = 41812
            member.uname = member.gname = "splunk"
            member.mode, member.size = 0o600, len(data)
            output.addfile(member, io.BytesIO(data))
    verify_target(expected_id=container_id)
    subprocess.run(
        ["docker", "cp", "-", container_id + ":/opt/splunk"],
        input=archive.getvalue(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )


def _open(req: urllib.request.Request, timeout: float = 120):
    try:
        return urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        with e:
            body = e.read().decode("utf-8", "replace")[:2000]
        raise LabError(f"HTTP {e.code} {req.full_url}: {body}") from e


def _mgmt(method: str, path: str, data: dict | None = None, timeout: float = 120):
    verify_target()
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


def wait_bootstrap(timeout: float = 900) -> None:
    """Wait for the pinned image's state marker without invoking its curl check."""
    identity = task_identity()
    if identity is None:
        raise LabError("bootstrap readiness requires an explicit task identity")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        verify_target()
        container_id = lab_tls.read_container(SECRETS, identity)
        target = json.loads(
            subprocess.check_output(
                ["docker", "inspect", container_id], text=True, timeout=30
            )
        )[0]
        if target.get("State", {}).get("Status") != "running":
            raise LabError("task container stopped during bootstrap")
        state = subprocess.run(
            [
                "docker",
                "exec",
                container_id,
                "cat",
                "/opt/container_artifact/splunk-container.state",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if state.returncode == 0 and state.stdout.strip() in (b"running", b"started"):
            return
        time.sleep(5)
    raise LabError("task container bootstrap did not complete")


def wait_ready(timeout: float = 900) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            _json("GET", "/services/server/info")
            return
        except (LabError, OSError) as e:
            if isinstance(getattr(e, "reason", e), ssl.SSLCertVerificationError):
                raise LabError("task TLS certificate verification failed") from None
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
    verify_target()
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
        if cmd == "local-docker-endpoint":
            print(local_docker_endpoint())
        elif cmd == "verify-target":
            verify_target()
        elif cmd == "verify-cleanup-target":
            verify_cleanup_target()
        elif cmd == "init-resources":
            task_resources()
        elif cmd == "remove-resources":
            task_resources(remove=True)
        elif cmd == "init-tls":
            init_tls()
        elif cmd == "remember-container":
            if len(rest) != 1:
                raise LabError("a newly created container ID is required")
            remember_container(rest[0])
        elif cmd == "start-container":
            start_container()
        elif cmd == "stage-tls":
            stage_tls()
        elif cmd == "purge-tls":
            identity = task_identity()
            if identity is None:
                raise LabError("TLS purge requires an explicit task identity")
            lab_tls.cleanup_tls(SECRETS, *identity)
        elif cmd == "init-secrets":
            init_secrets()
        elif cmd == "wait-bootstrap":
            wait_bootstrap()
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
    except (LabError, lab_tls.LabTLSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
