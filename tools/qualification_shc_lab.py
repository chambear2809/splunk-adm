#!/usr/bin/env python3
"""Coordinator-operated disposable SHC lifecycle; never operates on name alone.

Import from a reviewed external driver and hold ``with lab.locked():`` across
prepare, install, every check/failure investigation, and cleanup. There is no
independently mutating CLI that drops the lock between lifecycle phases.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import configparser
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import time
import uuid

from qualification_shc import (
    MEMBERS,
    ROLES,
    TASK_RE,
    Refused,
    canonical,
    protected_file,
    require,
)

IMAGE = "splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4"
LABEL = "com.splunk-adm.qualification.task"
SPLUNK = "/opt/splunk/bin/splunk"
SPLUNK_UID = 41812
DIAGNOSTICS = ContextVar("qualification_diagnostics", default=None)

# Static code executed by the pinned container's trusted bundled interpreter.
# Credentials enter only via stdin. PTY output is never returned or persisted.
LOGIN_PTY_HELPER = r"""
import errno
import json
import os
import pty
import re
import selectors
import signal
import sys
import termios
import time

def login_pty(username, password, argv=("/opt/splunk/bin/splunk", "login"), timeout=60):
    result = {"status": "helper_error", "exit_code": None, "username_prompt": False,
              "password_prompt": False, "child_reaped": False}
    if (not isinstance(username, str) or not isinstance(password, str)
        or not username or not password or len(username.encode()) > 128
        or len(password.encode()) > 1024 or any(c in username + password for c in "\r\n\x00")
        or not 0 < timeout <= 60):
        result["status"] = "invalid_input"
        return result
    child, master, reaped, terminal = None, None, False, None
    deadline = time.monotonic() + timeout
    def echo_off(fd):
        attrs = termios.tcgetattr(fd)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    def send(value):
        echo_off(master)
        pending = (value + "\n").encode()
        while pending:
            if time.monotonic() >= deadline:
                raise TimeoutError
            try:
                pending = pending[os.write(master, pending):]
            except BlockingIOError:
                time.sleep(.005)
    try:
        child, master = pty.fork()
        if child == 0:
            try:
                echo_off(0)
                os.execv(argv[0], list(argv))
            except BaseException:
                os._exit(127)
        os.set_blocking(master, False)
        echo_off(master)
        transcript, total = b"", 0
        with selectors.DefaultSelector() as selector:
            selector.register(master, selectors.EVENT_READ)
            while True:
                found, status = os.waitpid(child, os.WNOHANG)
                if found == child:
                    reaped = True
                    result["exit_code"] = os.waitstatus_to_exitcode(status)
                    if result["exit_code"] != 0:
                        terminal = "rejected"
                    elif result["username_prompt"] != result["password_prompt"]:
                        terminal = "incomplete_prompt"
                    else:
                        # Zero prompts is valid for a successful cached login.
                        terminal = "completed"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    terminal = "timeout"
                    break
                if not selector.select(min(.1, remaining)):
                    continue
                try:
                    chunk = os.read(master, 4096)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        time.sleep(min(.005, remaining))
                        continue
                    raise
                if not chunk:
                    time.sleep(min(.005, remaining))
                    continue
                total += len(chunk)
                if total > 65536:
                    terminal = "output_limit"
                    break
                transcript = (transcript + chunk)[-4096:]
                if re.search(rb"(?:^|[\r\n])(?:Splunk\s+)?username\s*:\s*$", transcript, re.I):
                    if result["username_prompt"] or result["password_prompt"]:
                        terminal = "unexpected_prompt"
                        break
                    send(username)
                    result["username_prompt"] = True
                    transcript = b""
                elif re.search(rb"(?:^|[\r\n])password\s*:\s*$", transcript, re.I):
                    if not result["username_prompt"] or result["password_prompt"]:
                        terminal = "unexpected_prompt"
                        break
                    send(password)
                    result["password_prompt"] = True
                    transcript = b""
    except TimeoutError:
        terminal = "timeout"
    except BaseException:
        terminal = "helper_error"
    finally:
        if child not in (None, 0) and not reaped:
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                _, status = os.waitpid(child, 0)
                result["exit_code"] = os.waitstatus_to_exitcode(status)
                reaped = True
            except ChildProcessError:
                reaped = True
        if master is not None:
            os.close(master)
        result["child_reaped"] = reaped
    result["status"] = terminal or "helper_error"
    return result

if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"username", "password"}:
            raise ValueError
        result = login_pty(value["username"], value["password"])
    except BaseException:
        result = {"status": "invalid_input", "exit_code": None, "username_prompt": False,
                  "password_prompt": False, "child_reaped": False}
    print(json.dumps(result, sort_keys=True), flush=True)
"""


class OwnedContainerStopped(Refused):
    """A requested startup stopped before authenticated readiness was reached."""


def command(args, *, data=None, timeout=300):
    """Never emit command output: docker/Splunk can echo credentials or config."""
    started = time.monotonic()
    try:
        result = subprocess.run(
            args, input=data, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        _command_failure(
            args, "timeout", error.stdout or b"", error.stderr or b"", started
        )
    except OSError:
        _command_failure(args, "launch_error", b"", b"", started)
    if result.returncode:
        _command_failure(args, result.returncode, result.stdout, result.stderr, started)
    return result.stdout


def _command_failure(args, status, stdout, stderr, started):
    # These file/stdin-based commands never put secrets in argv. Even protected
    # diagnostics retain only metadata/hashes, never subprocess input or output.
    categories = [
        label
        for label in (
            "permission denied",
            "no such file",
            "unknown command",
            "connection refused",
            "invalid configuration",
            "certificate verify failed",
            "not initialized",
            "not ready",
            "timed out",
            "authentication failed",
            "address already in use",
        )
        if label in (stdout + stderr).decode("utf-8", "replace").lower()
    ]
    record = {
        "utc": datetime.now(timezone.utc).isoformat(),
        "argv": args,
        "status": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "categories": categories,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    directory = DIAGNOSTICS.get()
    suffix = ""
    if directory and directory.is_dir():
        path = directory / ("subprocess-failure-" + uuid.uuid4().hex + ".json")
        private_write(path, canonical(record) + b"\n")
        suffix = "; diagnostic=" + str(path)
    operation = " ".join(str(word) for word in args[:2])
    raise Refused(
        f"{operation} failed status={status}; categories={','.join(categories) or 'unclassified'}{suffix}"
    )


def private_write(path: Path, content: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def safe_extract(archive: Path, destination: Path):
    """Accept one splunk_adm root and regular files/directories, without links."""
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(bool(members), "empty candidate archive")
        for member in members:
            path = Path(member.name)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and path.parts[0] == "splunk_adm"
                and (member.isfile() or member.isdir()),
                "unsafe candidate archive member",
            )
        # Validation above deliberately disallows symlinks and hardlinks.
        source.extractall(destination, members=members, filter="data")


def file_hashes(directory: Path):
    return {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


class Lab:
    def __init__(
        self,
        directory: Path,
        task: str,
        *,
        port_base=22000,
        lock_file=Path("/tmp/adm-qualification-host.lock"),
    ):
        require(bool(TASK_RE.fullmatch(task)), "invalid qualification task")
        require(20000 <= port_base <= 65000, "SHC ports must be disjoint high ports")
        self.directory = Path(directory).absolute()
        require(not self.directory.is_symlink(), "task directory cannot be a symlink")
        self.task, self.port_base = task, port_base
        self.lock_file, self._lock = Path(lock_file), None
        self.state = {
            "task": task,
            "image": IMAGE,
            "created": {},
            "network": None,
            "directory": str(self.directory),
        }

    @contextmanager
    def locked(self):
        require(self._lock is None, "lifecycle lock already held")
        fd = os.open(self.lock_file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        token = None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock = fd
            token = DIAGNOSTICS.set(self.directory / "evidence")
            yield self
        finally:
            if token is not None:
                DIAGNOSTICS.reset(token)
            self._lock = None
            os.close(fd)

    def _owned(self):
        require(self._lock is not None, "hold exclusive host lock for entire lifecycle")

    def save(self):
        self._owned()
        path = self.directory / "state.json"
        temporary = self.directory / (".state-" + uuid.uuid4().hex)
        private_write(temporary, canonical(self.state) + b"\n")
        os.replace(temporary, path)

    def inventory(self):
        """Read-only whitelisted inventory; never include docker Env or mounts."""
        ids = command(["docker", "ps", "-aq"]).decode().split()
        rows = []
        for identity in ids:
            value = json.loads(command(["docker", "inspect", identity]))[0]
            rows.append(
                {
                    "id": value["Id"],
                    "name": value["Name"].lstrip("/"),
                    "status": value["State"]["Status"],
                    "task": value["Config"].get("Labels", {}).get(LABEL),
                }
            )
        return rows

    def prepare(self, source_root: Path, archive: Path, *, source_sha: str):
        self._owned()
        source_root, archive = Path(source_root).resolve(), Path(archive).resolve()
        require(
            not self.directory.resolve().is_relative_to(source_root),
            "private lab material must live outside repository",
        )
        require(not self.directory.exists(), "new task directory already exists")
        self.directory.mkdir(mode=0o700, parents=False)
        (self.directory / "evidence").mkdir(mode=0o700)
        self.state["preflight_containers"] = self.inventory()
        self.state["source_sha"] = source_sha
        self.state["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.state["test_hashes"] = {
            path: hashlib.sha256((source_root / path).read_bytes()).hexdigest()
            for path in (
                "tests/splunk/test_distributed_interfaces.py",
                "tools/qualification_shc.py",
                "tools/qualification_shc_lab.py",
            )
        }
        staged_archive = self.directory / "candidate.tar.gz"
        shutil.copyfile(archive, staged_archive)
        staged_archive.chmod(0o600)
        stage = self.directory / "stage"
        stage.mkdir(mode=0o700)
        safe_extract(staged_archive, stage)
        self.state["candidate_files"] = file_hashes(stage / "splunk_adm")
        self.state["account_files"] = {}
        for account in ("admin", "viewer"):
            path = self.directory / (account + ".json")
            private_write(
                path,
                canonical(
                    {
                        "username": account
                        if account == "admin"
                        else "adm_qualification_viewer",
                        "password": "Adm-" + secrets.token_urlsafe(24),
                    }
                ),
            )
            self.state["account_files"][account] = str(path)
        admin = json.loads((self.directory / "admin.json").read_text())
        private_write(
            self.directory / "docker.env",
            ("SPLUNK_PASSWORD=" + admin["password"] + "\n").encode(),
        )
        private_write(self.directory / "shc.secret", secrets.token_urlsafe(32).encode())
        private_write(self.directory / "hec.secret", str(uuid.uuid4()).encode())
        self._pki()
        for index, role in enumerate(ROLES):
            self.state["created"][role] = {
                "name": f"{self.task}-{role}",
                "url": f"https://localhost:{self.port_base + index * 10 + 9}",
                "id": None,
            }
        self.save()

    def _pki(self):
        self._owned()
        pki = self.directory / "pki"
        pki.mkdir(mode=0o700)
        ca = pki / "ca.pem"
        command(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3",
                "-subj",
                "/CN=" + self.task + "-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                str(pki / "ca.key"),
                "-out",
                str(ca),
            ]
        )
        ca.chmod(0o600)
        (pki / "ca.key").chmod(0o600)
        self.state["ca_file"] = str(ca)
        for role in ROLES:
            key, csr, cert = (
                pki / (role + extension) for extension in (".key", ".csr", ".crt")
            )
            extensions = pki / (role + ".ext")
            private_write(
                extensions,
                (
                    "subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:"
                    + self.task
                    + "-"
                    + role
                    + "\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=critical,CA:FALSE\n"
                    + "keyUsage=critical,digitalSignature,keyEncipherment\n"
                ).encode(),
            )
            command(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=" + self.task + "-" + role,
                    "-keyout",
                    str(key),
                    "-out",
                    str(csr),
                ]
            )
            command(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-CA",
                    str(ca),
                    "-CAkey",
                    str(pki / "ca.key"),
                    "-CAcreateserial",
                    "-days",
                    "3",
                    "-extfile",
                    str(extensions),
                    "-out",
                    str(cert),
                ]
            )
            key.chmod(0o600)
            private_write(pki / (role + ".pem"), key.read_bytes() + cert.read_bytes())

    def create(self):
        self._owned()
        require(
            all(not item["id"] for item in self.state["created"].values()),
            "create must run once; inspect partial state before continuing",
        )
        network_name = self.task + "-net"
        identity = (
            command(
                [
                    "docker",
                    "network",
                    "create",
                    "--label",
                    LABEL + "=" + self.task,
                    network_name,
                ]
            )
            .decode()
            .strip()
        )
        self.state["network"] = {"name": network_name, "id": identity}
        self.save()
        for index, role in enumerate(ROLES):
            item = self.state["created"][role]
            memory, cpus = ("2g", "1") if role == "deployer" else ("4g", "2")
            args = [
                "docker",
                "create",
                "--name",
                item["name"],
                "--hostname",
                item["name"],
                "--label",
                LABEL + "=" + self.task,
                "--network",
                network_name,
                "--platform",
                "linux/amd64",
                "--memory",
                memory,
                "--cpus",
                cpus,
                "--env-file",
                str(self.directory / "docker.env"),
                "-e",
                "SPLUNK_START_ARGS=--accept-license",
                "-e",
                "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com",
            ]
            for offset, internal in ((0, 8000), (8, 8088), (9, 8089)):
                args += [
                    "-p",
                    f"127.0.0.1:{self.port_base + index * 10 + offset}:{internal}",
                ]
            item["id"] = command([*args, IMAGE]).decode().strip()
            self.save()  # Register each ID before any later action can fail.
            self._copy_config(role)

    def _inspect_owned(self, role):
        item = self.state["created"][role]
        require(bool(item["id"]), "container ID not recorded")
        value = json.loads(command(["docker", "inspect", item["id"]]))[0]
        require(
            value["Id"] == item["id"]
            and value["Name"] == "/" + item["name"]
            and value["Config"].get("Labels", {}).get(LABEL) == self.task,
            "container ID/name/task label mismatch",
        )
        return value

    def identity(self, role):
        return self._inspect_owned(role)["Id"]

    def container_status(self, role):
        value = self._inspect_owned(role)
        state = value["State"]
        return {
            "role": role,
            "id": value["Id"],
            "name": value["Name"].lstrip("/"),
            "status": state["Status"],
            "running": state.get("Running"),
            "exit_code": state.get("ExitCode"),
            "health": state.get("Health", {}).get("Status"),
        }

    def copy_files(self, role, files):
        self._owned()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as output:
            parents = sorted(
                {
                    str(parent)
                    for target in files
                    for parent in Path(target).parents
                    if str(parent) != "."
                },
                key=lambda value: (len(Path(value).parts), value),
            )
            for parent in parents:
                info = tarfile.TarInfo(parent)
                info.type = tarfile.DIRTYPE
                info.uid = info.gid = SPLUNK_UID
                # The pinned image starts Ansible as UID 999, which must traverse
                # native installation paths owned by Splunk UID 41812. Secret
                # leaves remain 0600; tightening shared ancestors breaks facts.
                info.mode = 0o755
                output.addfile(info)
            for target, content in files.items():
                require(
                    not Path(target).is_absolute() and ".." not in Path(target).parts,
                    "unsafe container target",
                )
                data, mode = content if isinstance(content, tuple) else (content, 0o600)
                info = tarfile.TarInfo(target)
                info.uid = info.gid = SPLUNK_UID
                info.uname = info.gname = "splunk"
                info.mode, info.size = mode, len(data)
                output.addfile(info, io.BytesIO(data))
        command(
            ["docker", "cp", "-a", "-", self.identity(role) + ":/opt/splunk"],
            data=archive.getvalue(),
        )

    def _copy_config(self, role):
        secret = (self.directory / "shc.secret").read_text()
        name = self.state["created"][role]["name"]
        conf = (
            f"[general]\nserverName = {name}\n\n[sslConfig]\n"
            "serverCert = /opt/splunk/etc/auth/adm_qualification/server.pem\n"
            "sslRootCAPath = /opt/splunk/etc/auth/adm_qualification/ca.pem\nsslPassword =\n"
            "cliVerifyServerName = true\n"
        )
        if role in MEMBERS or role == "deployer":
            conf += "\n[shclustering]\npass4SymmKey = " + secret + "\n"
            conf += "shcluster_label = " + self.task + "\n"
            if role in MEMBERS:
                conf += (
                    f"disabled = false\nmgmt_uri = https://{name}:8089\n"
                    "replication_factor = 3\n"
                    f"conf_deploy_fetch_url = https://{self.task}-deployer:8089\n"
                    "\n[replication_port://9887]\ndisabled = 0\n"
                )
        self.copy_files(
            role,
            {
                "etc/system/local/server.conf": conf.encode(),
                "etc/auth/adm_qualification/server.pem": (
                    self.directory / "pki" / (role + ".pem")
                ).read_bytes(),
                "etc/auth/adm_qualification/ca.pem": (
                    self.directory / "pki/ca.pem"
                ).read_bytes(),
            },
        )

    def start(self, role):
        self._owned()
        command(["docker", "start", self.identity(role)])

    def login(self, role):
        self._owned()
        admin = json.loads(protected_file(self.directory / "admin.json").read_text())
        value = command(
            [
                "docker",
                "exec",
                "-i",
                "-u",
                "splunk",
                self.identity(role),
                "/opt/splunk/bin/python3.13",
                "-c",
                LOGIN_PTY_HELPER,
            ],
            data=canonical(
                {"username": admin["username"], "password": admin["password"]}
            ),
            timeout=70,
        )
        try:
            result = json.loads(value)
        except (TypeError, ValueError):
            raise Refused("CLI PTY helper returned invalid metadata") from None
        allowed = {
            "status",
            "exit_code",
            "username_prompt",
            "password_prompt",
            "child_reaped",
        }
        require(
            isinstance(result, dict)
            and set(result) == allowed
            and result["status"]
            in {
                "completed",
                "rejected",
                "incomplete_prompt",
                "unexpected_prompt",
                "timeout",
                "output_limit",
                "helper_error",
                "invalid_input",
            }
            and (result["exit_code"] is None or type(result["exit_code"]) is int)
            and all(
                type(result[key]) is bool
                for key in ("username_prompt", "password_prompt", "child_reaped")
            ),
            "CLI PTY helper returned unexpected metadata",
        )
        evidence = {"role": role, **result}
        directory = self.directory / "evidence"
        require(directory.is_dir(), "owned evidence directory is missing")
        private_write(
            directory / ("cli-login-" + uuid.uuid4().hex + ".json"),
            canonical(evidence) + b"\n",
        )
        self.state.setdefault("cli_login_evidence", []).append(evidence)
        self.save()
        require(
            result["status"] == "completed"
            and result["exit_code"] == 0
            and result["child_reaped"] is True,
            "bounded interactive CLI login failed; inspect sanitized login metadata",
        )
        return result

    def cli(self, role, arguments, *, timeout=900):
        self._owned()
        require(
            not any(word in ("-auth", "--password", "-secret") for word in arguments),
            "secrets must never be supplied on CLI argv",
        )
        return command(
            ["docker", "exec", "-u", "splunk", self.identity(role), SPLUNK, *arguments],
            timeout=timeout,
        )

    def bootstrap(self):
        self._owned()
        self.login("sh1")
        self.cli(
            "sh1",
            [
                "bootstrap",
                "shcluster-captain",
                "-servers_list",
                ",".join(f"https://{self.task}-{role}:8089" for role in MEMBERS),
                "-answer-yes",
            ],
        )

    def install_candidate(self, role="deployer"):
        """The exact archive is staged; local qualified_shc override is separate."""
        self._owned()
        base = "etc/shcluster/apps" if role == "deployer" else "etc/apps"
        app = self.directory / "stage/splunk_adm"
        self.copy_files(
            role,
            {
                base + "/splunk_adm/" + str(path.relative_to(app)): path.read_bytes()
                if not path.stat().st_mode & 0o111
                else (path.read_bytes(), 0o700)
                for path in app.rglob("*")
                if path.is_file()
            },
        )

    def install_support(self, source_root: Path, addon_roots: list[Path]):
        """Before first start: curated vendor config and lab-only index/HEC setup.

        Vendor inputs and scripts are never copied or executed. Supply reviewed
        extracted add-on roots explicitly; their copied bytes are manifested.
        """
        self._owned()
        support = {}
        confs = (
            "app",
            "props",
            "transforms",
            "eventtypes",
            "tags",
            "fields",
            "macros",
            "collections",
            "ipfixmap",
        )
        for root in map(Path, addon_roots):
            require(root.is_dir() and root.name != "splunk_adm", "invalid add-on root")
            for conf in confs:
                path = root / "default" / (conf + ".conf")
                if path.is_file():
                    support[root.name + "/default/" + path.name] = path.read_bytes()
            for folder, patterns in (
                ("lookups", ("*.csv", "*.csv.gz")),
                ("metadata", ("*.meta",)),
            ):
                for pattern in patterns:
                    for path in (root / folder).glob(pattern):
                        require(
                            not path.is_symlink(), "add-on data cannot be symlinked"
                        )
                        support[root.name + "/" + folder + "/" + path.name] = (
                            path.read_bytes()
                        )
        self.state["support_files"] = {
            key: hashlib.sha256(value).hexdigest()
            for key, value in sorted(support.items())
        }
        for role in ("deployer", "idx"):
            base = "etc/shcluster/apps/" if role == "deployer" else "etc/apps/"
            self.copy_files(role, {base + key: value for key, value in support.items()})
        indexes = (
            Path(source_root) / "tests/splunk/lab_app/default/indexes.conf"
        ).read_bytes()
        inputs = (
            Path(source_root) / "tests/splunk/lab_app/default/inputs.conf.template"
        ).read_text()
        inputs = inputs.replace(
            "@HEC_TOKEN@", (self.directory / "hec.secret").read_text()
        )
        inputs = inputs.replace(
            "[http]\n",
            "[http]\n"
            "serverCert = /opt/splunk/etc/auth/adm_qualification/server.pem\nsslPassword =\n",
        )
        inputs += "\n[splunktcp://9997]\ndisabled = 0\n"
        self.copy_files(
            "idx",
            {
                "etc/apps/adm_qualification/default/app.conf": b"[install]\nstate = enabled\n",
                "etc/apps/adm_qualification/default/indexes.conf": b"[default]\nfrozenTimePeriodInSecs = 2592000\n\n"
                + indexes,
                "etc/apps/adm_qualification/default/inputs.conf": inputs.encode(),
            },
        )
        outputs = (
            "[tcpout]\ndefaultGroup = adm_qualification\n"
            "\n[tcpout:adm_qualification]\nserver = " + self.task + "-idx:9997\n"
        )
        for role in MEMBERS:
            self.copy_files(role, {"etc/system/local/outputs.conf": outputs.encode()})
        self.save()

    def opt_in_settings(self):
        """Task-local override distributed by deployer; package bytes stay exact."""
        self._owned()
        self.copy_files(
            "deployer",
            {
                "etc/shcluster/apps/splunk_adm/local/adm_settings.conf": b"[persistence]\nwrite_mode = qualified_shc\nplatform = enterprise\n"
            },
        )
        self.state["settings_override"] = {
            "write_mode": "qualified_shc",
            "platform": "enterprise",
        }
        self.save()

    def apply_bundle(self):
        self._owned()
        self.login("deployer")
        # Enterprise 10.6.0.5 does not expose `validate shcluster-bundle`.
        self.cli(
            "deployer",
            [
                "apply",
                "shcluster-bundle",
                "-target",
                f"https://{self.task}-sh1:8089",
                "-answer-yes",
            ],
            timeout=1200,
        )

    def verify_candidate(self):
        """Hash all installed archive files; permit only generated app checksum."""
        result = {}
        for role in MEMBERS:
            files = {}
            for name, expected in self.state["candidate_files"].items():
                data = command(
                    [
                        "docker",
                        "exec",
                        "-u",
                        "splunk",
                        self.identity(role),
                        "cat",
                        "/opt/splunk/etc/apps/splunk_adm/" + name,
                    ]
                )
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected:
                    require(
                        name == "default/app.conf", "installed archive file differs"
                    )
                    baseline = configparser.RawConfigParser()
                    baseline.read(self.directory / "stage/splunk_adm/default/app.conf")
                    installed = configparser.RawConfigParser()
                    installed.read_string(data.decode())
                    require(
                        set(baseline.sections()) == set(installed.sections()),
                        "installed app.conf sections differ",
                    )
                    for section in baseline.sections():
                        declared = dict(baseline[section])
                        observed = dict(installed[section])
                        if section == "install" and "checksum" not in declared:
                            observed.pop("checksum", None)
                        require(
                            declared == observed, "installed app.conf settings differ"
                        )
                    files[name] = {"sha256": actual, "generated_checksum_only": True}
                else:
                    files[name] = {"sha256": actual, "byte_exact": True}
            result[role] = files
        return result

    def cleanup(self):
        """Validate the entire removal set before removing any task resource."""
        self._owned()
        identities = [
            self.identity(role) for role in ROLES if self.state["created"][role]["id"]
        ]
        network = self.state.get("network")
        if network:
            value = json.loads(
                command(["docker", "network", "inspect", network["id"]])
            )[0]
            require(
                value["Id"] == network["id"]
                and value["Name"] == network["name"]
                and value.get("Labels", {}).get(LABEL) == self.task,
                "network ID/name/task label mismatch",
            )
            require(
                set(value.get("Containers", {})).issubset(identities),
                "task network has an unowned attachment",
            )
        for identity in identities:
            command(["docker", "rm", "-f", "-v", identity])
        if network:
            command(["docker", "network", "rm", network["id"]])
        # Keep package/evidence/state for root export. Secrets remain private until
        # root verifies exported hashes and explicitly disposes this directory.
        self.state["cleanup"] = {
            "removed_ids": identities,
            "network_removed": network["id"] if network else None,
        }
        self.save()
