"""Guarded building blocks for a native, synthetic service-restart exercise.

The surrounding fixture owns the authenticated I/O, process observations and
recovery journal. No service operation occurs on import.
"""

import re
import subprocess
import time

RESTART_COMMAND = ("sudo", "-n", "/opt/splunk/bin/splunk", "restart")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_identity(value):
    require(isinstance(value, dict), "missing service identity")
    require(
        set(value)
        == {"unit", "active", "main_pid", "main_start", "invocation", "cgroup"}
        and isinstance(value["unit"], str)
        and re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", value["unit"])
        and value["active"] is True
        and type(value["main_pid"]) is int
        and value["main_pid"] > 1
        and type(value["main_start"]) is int
        and value["main_start"] > 0
        and isinstance(value["invocation"], str)
        and re.fullmatch(r"[0-9a-f]{32}", value["invocation"])
        and isinstance(value["cgroup"], str)
        and value["cgroup"].startswith("/")
        and value["cgroup"] != "/",
        "invalid or inactive service identity",
    )


def execute_restart(*, popen=subprocess.Popen, timeout=120, on_launch=None):
    """Launch the fixed supported CLI; never kill it on timeout or uncertainty."""
    process = popen(
        RESTART_COMMAND,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    require(
        type(process.pid) is int and process.pid > 1, "invalid restart command identity"
    )
    if on_launch is not None:
        on_launch(process.pid)
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "restart command still running; service state uncertain"
        ) from exc
    require(status == 0, "restart command failed; service state uncertain")
    return {"command_pid": process.pid, "exit_status": status}


def within_service_cgroup(path, unit_cgroup):
    return isinstance(path, str) and (
        path == unit_cgroup or path.startswith(unit_cgroup + "/")
    )


def restart_at_checkpoint(io, mode, marker):
    """Restart once around an authenticated live worker checkpoint.

    ``io`` is the task-owned integration: service_identity(),
    checkpoint_identity(marker), journal(record), assert_checkpoint_live(marker,
    checkpoint), launch_restart(), wait_ready(old), and old_process_absent(old).
    All evidence callbacks must fail on uncertainty. The callback which launches
    the command must use execute_restart; it must not retry, kill, or force-start
    after an uncertain result. The journal must be durable before launch.
    """
    require(mode in {"precommit", "postcommit"}, "invalid checkpoint")
    require(
        isinstance(marker, dict)
        and set(marker) == {"phase", "pid", "pgid", "child_pid"}
        and marker["phase"] == mode
        and all(
            type(marker[k]) is int and marker[k] > 1
            for k in ("pid", "pgid", "child_pid")
        )
        and marker["pid"] == marker["pgid"],
        "invalid checkpoint marker",
    )
    old = io.service_identity()
    validate_identity(old)
    checkpoint = io.checkpoint_identity(marker)
    require(
        isinstance(checkpoint, dict)
        and checkpoint.get("worker_pid") == marker["pid"]
        and checkpoint.get("child_pid") == marker["child_pid"]
        and within_service_cgroup(checkpoint.get("worker_cgroup"), old["cgroup"])
        and within_service_cgroup(checkpoint.get("parent_cgroup"), old["cgroup"])
        and within_service_cgroup(checkpoint.get("child_cgroup"), old["cgroup"])
        and checkpoint.get("identities_verified") is True,
        "checkpoint ownership or service membership unproven",
    )
    io.journal(
        {
            "state": "service_restart_intent",
            "mode": mode,
            "old_service": old,
            "checkpoint": checkpoint,
            "intent_monotonic_ns": time.monotonic_ns(),
        }
    )
    require(
        io.assert_checkpoint_live(marker, checkpoint) is True,
        "checkpoint changed before restart",
    )
    require(io.service_identity() == old, "service changed before restart")
    command = io.launch_restart()
    require(
        isinstance(command, dict)
        and command.get("exit_status") == 0
        and command.get("worker_live_on_launch") is True
        and type(command.get("command_pid")) is int
        and command["command_pid"] > 1,
        "restart acknowledgement missing",
    )
    new = io.wait_ready(old)
    validate_identity(new)
    require(
        new["unit"] == old["unit"]
        and new["cgroup"] == old["cgroup"]
        and new["invocation"] != old["invocation"]
        and (new["main_pid"], new["main_start"]) != (old["main_pid"], old["main_start"])
        and io.old_process_absent(old) is True,
        "service restart identity unproven",
    )
    io.journal(
        {
            "state": "service_restart_verified",
            "mode": mode,
            "old_service": old,
            "new_service": new,
            "command_pid": command["command_pid"],
        }
    )
    return {
        "old_service": old,
        "new_service": new,
        "checkpoint": checkpoint,
        "command": command,
    }
