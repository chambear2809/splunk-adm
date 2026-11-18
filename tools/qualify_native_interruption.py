"""Native interruption qualification primitives; no fixture runs on import.

See docs/CASE_NATIVE_INTERRUPTION.md. This is not an autonomous remote runner.
"""

import hashlib
import json
import os
import re
from pathlib import Path
import signal
import stat

WORKER = b"/opt/splunk/etc/apps/splunk_adm/bin/adm_cases_lib/request_worker.py"


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def journal_dispatch(directory, *, principal, method, path, key, body):
    """Publish the exact operation before dispatch; fail closed on unsafe storage."""
    directory = Path(directory)
    info = directory.lstat()
    _require(
        stat.S_ISDIR(info.st_mode)
        and directory.is_absolute()
        and directory.resolve() == directory
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "unsafe journal directory",
    )
    _require(
        all(isinstance(v, str) and v for v in (principal, method, path, key))
        and isinstance(body, bytes)
        and len(body) <= 128000,
        "invalid operation identity",
    )
    # JSON encodes bytes losslessly rather than decoding and re-encoding the body.
    import base64

    record = {
        "state": "dispatching",
        "principal": principal,
        "method": method,
        "path": path,
        "key": key,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    payload = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    fd = os.open(
        directory / "dispatch.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # A partial file is evidence of an incomplete publication; never reuse it.
        raise
    dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    _sync_dir(directory.parent)
    return record


def process_identity(pid):
    """Read a Linux process identity including the kernel start-time cookie."""
    _require(type(pid) is int and pid > 1, "invalid pid")
    root = Path("/proc") / str(pid)
    uid = root.stat().st_uid
    raw = (root / "stat").read_text()
    # comm is parenthesized and can contain spaces or closing parentheses.
    suffix = raw[raw.rfind(")") + 2 :].split()
    _require(len(suffix) >= 20, "invalid process stat")
    argv = (root / "cmdline").read_bytes()
    _require(len(argv) <= 16384, "oversized process command")
    return {
        "pid": pid,
        "uid": uid,
        "state": suffix[0],
        "ppid": int(suffix[1]),
        "pgid": int(suffix[2]),
        "session": int(suffix[3]),
        "start_time": int(suffix[19]),
        "argv": argv.split(b"\0")[:-1],
    }


def _pidfd_functions():
    """Use Python pidfd APIs or exported libc functions; never guess syscalls."""
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        return (
            lambda pid: os.pidfd_open(pid, 0),
            lambda fd, sig: signal.pidfd_send_signal(fd, sig),
        )
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        open_fn = libc.pidfd_open
        send_fn = libc.pidfd_send_signal
    except AttributeError as exc:
        raise RuntimeError("pidfd unavailable") from exc
    open_fn.argtypes = [ctypes.c_int, ctypes.c_uint]
    open_fn.restype = ctypes.c_int
    send_fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    send_fn.restype = ctypes.c_int

    def opened(pid):
        result = open_fn(pid, 0)
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return result

    def sent(fd, sig):
        if send_fn(fd, sig, None, 0) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    return opened, sent


def pidfd_preflight():
    """Verify kernel pidfd open/send-zero support against this process only."""
    open_pidfd, send_pidfd = _pidfd_functions()
    fd = open_pidfd(os.getpid())
    try:
        send_pidfd(fd, 0)
    finally:
        os.close(fd)
    return {
        "pidfd_open": True,
        "pidfd_signal_zero": True,
        "implementation": "python"
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
        else "libc",
    }


def interrupt_owned_worker(marker, expected, *, read_identity=process_identity):
    """Kill only a verified worker using a Linux pidfd; never signal its group.

    expected is captured independently before signaling and includes uid, worker
    start time, parent pid/start time/independently approved argv digest and child start time. The marker itself is
    read and authenticated by the caller via the existing native hook observer.
    """
    _require(set(marker) == {"phase", "pid", "pgid", "child_pid"}, "invalid marker")
    _require(marker["phase"] in {"precommit", "postcommit"}, "invalid phase")
    _require(marker["pid"] == marker["pgid"], "worker is not group leader")
    worker = read_identity(marker["pid"])
    parent = read_identity(worker["ppid"])
    child = read_identity(marker["child_pid"])
    _require(
        worker["uid"] == expected["uid"] == parent["uid"] == child["uid"]
        and worker["state"] not in {"Z", "X"}
        and worker["start_time"] == expected["worker_start"]
        and worker["ppid"] == expected["parent_pid"]
        and parent["start_time"] == expected["parent_start"]
        and hashlib.sha256(b"\0".join(parent["argv"]) + b"\0").hexdigest()
        == expected["parent_argv_sha256"]
        and child["start_time"] == expected["child_start"]
        and child["ppid"] == worker["pid"]
        and worker["pgid"] == worker["session"] == worker["pid"]
        and child["pgid"] == child["session"] == worker["pid"]
        and len(worker["argv"]) == 3
        and worker["argv"][1:] == [b"-I", WORKER],
        "worker ownership or identity unproven",
    )
    open_pidfd, send_pidfd = _pidfd_functions()
    fd = open_pidfd(worker["pid"])
    try:
        # Opening a pidfd after /proc inspection does not itself close the PID
        # reuse race: recheck all three identities after obtaining the handle.
        _require(read_identity(worker["pid"]) == worker, "worker identity changed")
        _require(read_identity(parent["pid"]) == parent, "parent identity changed")
        _require(read_identity(child["pid"]) == child, "child identity changed")
        send_pidfd(fd, signal.SIGKILL)
    finally:
        os.close(fd)


def validate_evidence(value):
    """Fail closed unless each independent observation is explicitly true."""
    required = {
        "original_operation_durable_before_dispatch",
        "worker_killed",
        "worker_and_descendant_retired",
        "precommit_zero_receipts",
        "precommit_zero_new_captures",
        "postcommit_one_receipt",
        "postcommit_one_new_capture",
        "same_operation_retry_converged",
        "capture_identity_preserved",
        "source_jobs_terminal_and_absent",
        "revoked_read_export_retry_redacted",
        "restored_access_and_retry",
        "hook_source_and_cache_restored",
        "owned_resources_cleanup_verified",
        "uninjected_capture_after_restoration",
    }
    _require(isinstance(value, dict) and set(value) == required, "incomplete evidence")
    _require(all(v is True for v in value.values()), "failed or uncertain evidence")
    return True


# Hashes of the reviewed repository test-only primitives. The transformed hook
# differs only in its private control directory, and its own hash is recorded by
# the platform transaction helper.
NATIVE_HELPER_SHA256 = (
    "a938437224ac1db5129de00396e8c3ec27d0d5d745763f4217836d1f4118fd84"
)
HOOK_SHA256 = "ff2b2c2d2e32e705748b8bf4665e776af12590460bf092a6580581449b85b8b0"
NATIVE_ROOT = Path("/opt/splunk/var/atlas-interruption-20261118")
_OLD_CONTROL = b"/tmp/adm-cases-requests-20261118"
_KEY = re.compile(r"atlas_intr_[0-9a-f]{32}\Z")


def transformed_hook(source):
    _require(hashlib.sha256(source).hexdigest() == HOOK_SHA256, "hook hash mismatch")
    _require(source.count(_OLD_CONTROL) == 1, "unexpected hook source")
    return source.replace(_OLD_CONTROL, os.fsencode(NATIVE_ROOT / "control"))


def _load_helper(source):
    import types

    _require(
        hashlib.sha256(source).hexdigest() == NATIVE_HELPER_SHA256,
        "native transaction helper hash mismatch",
    )
    module = types.ModuleType("atlas_reviewed_native_hook")
    exec(compile(source, "<reviewed-native-hook>", "exec"), module.__dict__)
    module.STAGED = NATIVE_ROOT / "stage"
    module.CONTROL = NATIVE_ROOT / "control"
    module.HOOK_BACKUP = NATIVE_ROOT / "backup"
    module.HOOK_TRANSACTION = module.HOOK_BACKUP / "transaction.json"
    module.HOOK_SOURCE = module.STAGED / "case_request_fault_hook.py"
    return module


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare_native_hook(helper_source, hook_source):
    """Root-only one-shot staging; a preexisting task directory is a hard stop."""
    import platform
    import pwd

    _require(os.getuid() == 0 and platform.system() == "Linux", "root Linux required")
    _require(os.environ.get("SPLUNK_HOME") == "/opt/splunk", "wrong Splunk home")
    module = _load_helper(helper_source)
    payload = transformed_hook(hook_source)
    # A parent symlink or alternate Splunk installation is not an owned target.
    parent = NATIVE_ROOT.parent
    _require(parent.resolve() == parent and parent.is_dir(), "unsafe native parent")
    splunk = pwd.getpwnam("splunk")
    NATIVE_ROOT.mkdir(mode=0o711)
    os.chmod(NATIVE_ROOT, 0o711)
    _sync_dir(parent)
    for name in ("stage", "control"):
        path = NATIVE_ROOT / name
        path.mkdir(mode=0o700)
        os.chown(path, splunk.pw_uid, splunk.pw_gid)
        os.chmod(path, 0o700)
    _sync_dir(NATIVE_ROOT)
    fd = os.open(
        module.HOOK_SOURCE,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fchown(stream.fileno(), splunk.pw_uid, splunk.pw_gid)
        os.fchmod(stream.fileno(), 0o600)
        os.fsync(stream.fileno())
    _sync_dir(module.STAGED)
    return hashlib.sha256(payload).hexdigest()


def _validate_native_directory():
    import pwd

    uid = pwd.getpwnam("splunk").pw_uid
    for path, owner, mode in (
        (NATIVE_ROOT, 0, 0o711),
        (NATIVE_ROOT / "stage", uid, 0o700),
        (NATIVE_ROOT / "control", uid, 0o700),
    ):
        info = path.lstat()
        _require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == owner
            and stat.S_IMODE(info.st_mode) == mode
            and path.resolve() == path,
            "unsafe task directory",
        )


def native_hook_action(helper_source, hook_source, action, *, mode=None, key=None):
    """Invoke the pinned transaction/control code under its required OS user."""
    import platform
    import pwd

    _require(platform.system() == "Linux", "Linux required")
    _require(os.environ.get("SPLUNK_HOME") == "/opt/splunk", "wrong Splunk home")
    _validate_native_directory()
    module = _load_helper(helper_source)
    payload = transformed_hook(hook_source)
    digest = hashlib.sha256(payload).hexdigest()
    if action in {"install", "restore"}:
        _require(os.getuid() == 0, "root required")
        return (
            module.hook_install(digest)
            if action == "install"
            else module.hook_remove(digest)
        )
    _require(os.getuid() == pwd.getpwnam("splunk").pw_uid, "Splunk user required")
    if action == "arm":
        _require(mode in {"precommit", "postcommit"}, "invalid checkpoint")
        _require(isinstance(key, str) and _KEY.fullmatch(key), "invalid fixture key")
        return module.set_fault(mode, key, mode)
    if action == "disable":
        return module.set_fault("off", "", "precommit")
    if action == "observe":
        _require(mode in {"precommit", "postcommit"}, "invalid checkpoint")
        return module.observe(mode)
    raise RuntimeError("unknown native hook action")


def _check_jobs(state):
    jobs = state["new_jobs"]
    _require(isinstance(jobs, list) and len(jobs) >= 2, "source jobs unproven")
    sids = set()
    for job in jobs:
        _require(
            isinstance(job, dict)
            and set(job) == {"sid", "state", "native_absent"}
            and isinstance(job["sid"], str)
            and job["sid"]
            and job["state"] == "deleted"
            and job["native_absent"] is True,
            "source job retirement unproven",
        )
        _require(job["sid"] not in sids, "duplicate source job")
        sids.add(job["sid"])


def run_capture_phase(mode, operation, journal_directory, io, *, timeout=30):
    """Run one capture checkpoint using the caller's authenticated native I/O.

    ``io`` supplies arm, dispatch, observe, interrupt, wait_retired, inspect,
    disable, retry and check_access callbacks. Each callback receives the exact
    operation object except observe/arm (mode and operation), interrupt (marker),
    and wait_retired (marker). Dispatch and retry must use the operation's bytes
    and principal unchanged. inspect returns the independent database/API
    observation described in CASE_NATIVE_INTERRUPTION.md. This function never
    creates credentials, grants or sources; the surrounding reviewed fixture owns
    them and installs/restores the hook in a separate finally block.
    """
    import threading
    import time

    _require(mode in {"precommit", "postcommit"}, "invalid checkpoint")
    _require(
        isinstance(operation, dict)
        and set(operation) == {"principal", "method", "path", "key", "body"}
        and operation["method"] == "POST"
        and operation["path"].endswith("/captures")
        and isinstance(operation["key"], str)
        and _KEY.fullmatch(operation["key"]),
        "invalid capture operation",
    )
    journal_dispatch(journal_directory, **operation)
    baseline = io.inspect(operation)
    _require(
        baseline["receipt_count"] == 0 and type(baseline["capture_count"]) is int,
        "operation is not fresh",
    )
    result = []

    def request():
        try:
            io.dispatch(operation)
            result.append("response")
        except Exception:
            result.append("unknown")

    thread = None
    armed = False
    try:
        # Even an uncertain arm must be followed by a disable attempt.
        armed = True
        io.arm(mode, operation)
        thread = threading.Thread(target=request, daemon=True)
        thread.start()
        deadline = time.monotonic() + timeout
        marker = None
        while time.monotonic() < deadline:
            observed = io.observe(mode, operation)
            if observed.get("marker_present"):
                marker = observed["marker"]
                break
            if not thread.is_alive():
                raise RuntimeError("request returned before checkpoint")
            time.sleep(0.05)
        _require(
            marker is not None and marker.get("phase") == mode, "checkpoint missing"
        )
        at_checkpoint = io.inspect(operation)
        expected_count = 0 if mode == "precommit" else 1
        _require(
            at_checkpoint["receipt_count"] == expected_count
            and at_checkpoint["capture_count"]
            == baseline["capture_count"] + expected_count,
            "checkpoint commit cardinality mismatch",
        )
        _check_jobs(at_checkpoint)
        io.interrupt(marker)
        retirement = io.wait_retired(marker)
        _require(
            retirement
            == {"worker_absent": True, "group_absent": True, "child_absent": True},
            "worker retirement unproven",
        )
        thread.join(timeout=10)
        _require(not thread.is_alive(), "dispatch did not settle")
        io.disable(operation)
        armed = False
        io.retry(operation)
        after = io.inspect(operation)
        _require(
            after["receipt_count"] == 1
            and after["capture_count"] == baseline["capture_count"] + 1
            and isinstance(after["receipt_digest"], str)
            and bool(after["receipt_digest"])
            and isinstance(after["capture_id"], str)
            and bool(after["capture_id"]),
            "exact retry did not converge",
        )
        _check_jobs(after)
        if mode == "postcommit":
            _require(
                at_checkpoint["receipt_digest"] == after["receipt_digest"]
                and at_checkpoint["capture_id"] == after["capture_id"],
                "committed identity changed",
            )
        access = io.check_access(operation, after["capture_id"])
        _require(
            access
            == {
                "revoked_read_redacted": True,
                "revoked_export_redacted": True,
                "revoked_exact_retry_redacted": True,
                "changed_config_read_redacted": True,
                "changed_config_export_redacted": True,
                "changed_config_exact_retry_redacted": True,
                "restored_read": True,
                "restored_exact_retry": True,
            },
            "recovery access checks failed",
        )
        return {
            "mode": mode,
            "dispatch_outcome": result[0],
            "checkpoint": at_checkpoint,
            "retirement": retirement,
            "after_retry": after,
            "access": access,
        }
    finally:
        import sys

        primary = sys.exc_info()[1]
        failures = []
        if armed:
            try:
                io.disable(operation)
            except BaseException as exc:
                failures.append("disable:" + type(exc).__name__)
        if thread is not None and thread.is_alive():
            thread.join(timeout=50)
            if thread.is_alive():
                failures.append("dispatch_still_running")
        if failures:
            message = "phase cleanup uncertain: " + ", ".join(failures)
            if primary is None:
                raise RuntimeError(message)
            primary.add_note(message)


def interrupt_checkpoint(helper_source, hook_source, mode, key, expected):
    """Authenticate the private control and marker before worker-only signaling."""
    import pwd

    _require(os.getuid() == pwd.getpwnam("splunk").pw_uid, "Splunk user required")
    _validate_native_directory()
    module = _load_helper(helper_source)
    transformed_hook(hook_source)
    _require(mode in {"precommit", "postcommit"}, "invalid checkpoint")
    _require(isinstance(key, str) and _KEY.fullmatch(key), "invalid fixture key")
    module.request_id(key)
    raw = module._read_regular(
        module.CONTROL / "fault.json", owner=os.getuid(), mode=0o600, maximum=4096
    )
    _require(
        json.loads(raw.decode("ascii"))
        == {"mode": mode, "request_id": key, "generation": mode},
        "checkpoint control changed",
    )
    observed = module.observe(mode)
    _require(observed.get("marker_present") is True, "checkpoint marker missing")
    marker = observed["marker"]
    interrupt_owned_worker(marker, expected)
    return marker


def installed_native_hook(install, disable, restore, journal):
    """Return a context manager that independently attempts disable and restore."""
    from contextlib import contextmanager

    @contextmanager
    def preserved():
        primary = None
        try:
            install()
            yield
        except BaseException as exc:
            primary = exc
            raise
        finally:
            outcomes = {}
            failures = []
            for name, action in (("disable", disable), ("restore", restore)):
                try:
                    result = action()
                    if name == "restore":
                        _require(
                            isinstance(result, dict)
                            and all(
                                result.get(k) is True
                                for k in (
                                    "hook_removed",
                                    "hook_restored",
                                    "cache_restored",
                                )
                            )
                            and result.get("fixture_hook_active") is False,
                            "hook restoration unproven",
                        )
                    outcomes[name] = "acknowledged"
                except BaseException as exc:
                    failures.append(name)
                    outcomes[name] = "failed_or_uncertain:" + type(exc).__name__
            try:
                journal({"state": "hook_cleanup", "outcomes": outcomes})
            except BaseException:
                failures.append("journal")
            if failures:
                message = "hook cleanup failed or uncertain: " + ", ".join(failures)
                if primary is None:
                    raise RuntimeError(message)
                primary.add_note(message)

    return preserved()
