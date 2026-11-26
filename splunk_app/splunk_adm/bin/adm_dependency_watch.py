#!/usr/bin/env python3
"""Disabled one-window watch action; session credentials enter through stdin only."""

import json
import re
import sys
import time

from adm_baselines_lib.splunk_host import SplunkHost
from adm_log_lib import log_outcome

HANDLER = "adm_dependency_watch"

MAX_INPUT_BYTES = 64 * 1024


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _text(value, maximum):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or not value.isprintable()
    ):
        raise ValueError("invalid field")
    return value


def _constant(_):
    raise ValueError("nonfinite number")


def _timestamp(value):
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,11}", value):
        value = int(value)
    if type(value) is not int:
        raise ValueError("invalid timestamp")
    return value


def main(*, stdin=None, stdout=None, configuration=None, host_factory=SplunkHost):
    """No saved search is shipped; the installed Splunk envelope is unqualified."""
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    configuration = configuration or SplunkHost._execution_configuration
    started = time.monotonic()

    def emit(state, error=None):
        # Never log the payload, credential, source reference or protected results.
        stdout.write(json.dumps({"status": state}, separators=(",", ":")) + "\n")
        outcome = {"committed": "ok", "disabled": "refused"}.get(state)
        if state == "invalid_request":
            outcome = "refused"
        log_outcome(
            HANDLER,
            started=started,
            outcome=outcome or "failed",
            code=state,
            error=error,
            exit_code=0 if state == "committed" else 1,
        )

    dispatched = False
    try:
        if configuration() != {"enabled": True}:
            emit("disabled")
            return 1
        raw = stdin.read(MAX_INPUT_BYTES + 1)
        if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
            raise ValueError("invalid action input")
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
        required = {"app", "session_key", "result"}
        optional = {
            "configuration",
            "owner",
            "search_name",
            "sid",
            "results_file",
            "results_link",
            "server_uri",
            "server_host",
        }
        if (
            not isinstance(payload, dict)
            or not required <= set(payload)
            or set(payload) - required - optional
        ):
            raise ValueError("invalid action envelope")
        if payload["app"] != "splunk_adm":
            raise ValueError("wrong namespace")
        token = _text(payload["session_key"], 16384)
        result = payload["result"]
        if not isinstance(result, dict) or set(result) != {
            "binding_id",
            "start",
            "end",
            "request_id",
        }:
            raise ValueError("invalid action selection")
        binding_id = _text(result["binding_id"], 64)
        request_id = _text(result["request_id"], 128)
        start, end = _timestamp(result["start"]), _timestamp(result["end"])
        if not 0 <= start < end <= 253402300799 or end - start > 300:
            raise ValueError("invalid action window")
        host = host_factory(token)
        executor = host.watch_executor()
        dispatched = True
        receipt = executor.execute(
            binding_id,
            {"start": start, "end": end},
            request_id,
        )
        # A generic acknowledgement supplies no owner-context evidence to viewers.
        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"id", "revision", "resultWithheld"}
            or receipt["resultWithheld"] is not True
            or type(receipt["revision"]) is not int
            or receipt["revision"] < 1
        ):
            emit("uncertain")
            return 1
        emit("committed")
        return 0
    except ValueError as exc:
        emit("unavailable_or_uncertain" if dispatched else "invalid_request", exc)
        return 1
    except Exception as exc:
        # After dispatch an exception may mean commit-before-response loss. Keep
        # the stable request identity; the executor journal owns reconciliation.
        emit("unavailable_or_uncertain", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
