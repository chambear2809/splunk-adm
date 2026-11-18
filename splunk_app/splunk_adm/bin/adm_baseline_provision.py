#!/usr/bin/env python3
"""Explicit owner/admin provisioning; credentials are accepted only on stdin."""

import json
import sys

from adm_baselines_lib.splunk_host import SplunkHost

MAX_INPUT = 65536


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def main(*, stdin=None, stdout=None, host_factory=SplunkHost):
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        raw = stdin.read(MAX_INPUT + 1)
        if not isinstance(raw, bytes) or len(raw) > MAX_INPUT:
            raise ValueError("invalid input")
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("invalid number")
            ),
        )
        if not isinstance(data, dict):
            raise ValueError("invalid input")
        operation = data.get("operation", "create")
        fields = {
            "create": {
                "session_key",
                "baseline_id",
                "watch_id",
                "selection",
                "request_id",
            },
            "enable": {"session_key", "binding_id", "expected_revision", "request_id"},
            "disable": {"session_key", "binding_id", "expected_revision", "request_id"},
            "inspect": {"session_key", "binding_id"},
            "find_created": {"session_key", "request_id"},
            "receipt": {"session_key", "binding_id", "request_id"},
        }
        if operation not in fields or set(data) - {"operation"} != fields[operation]:
            raise ValueError("invalid input")
        token = data["session_key"]
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 16384
            or not token.isprintable()
        ):
            raise ValueError("invalid session")
        if operation != "inspect":
            request_id = data["request_id"]
            if (
                not isinstance(request_id, str)
                or not request_id
                or len(request_id) > 128
                or not request_id.isprintable()
                or request_id.strip() != request_id
            ):
                raise ValueError("invalid request")
        host = host_factory(token)
        if operation == "create":
            binding = host.watch_executor().create_binding(
                data["baseline_id"],
                data["watch_id"],
                data["selection"],
                request_id=request_id,
            )
            result = {key: binding[key] for key in ("id", "revision", "enabled")}
        elif operation == "inspect":
            result = host.watch_manager().inspect(data["binding_id"])
        elif operation == "find_created":
            result = host.watch_manager().find_created(request_id)
        elif operation == "receipt":
            result = host.watch_manager().receipt(data["binding_id"], request_id)
        else:
            if (
                type(data["expected_revision"]) is not int
                or data["expected_revision"] < 1
            ):
                raise ValueError("invalid revision")
            manager = (
                host.watch_executor() if operation == "enable" else host.watch_manager()
            )
            result = manager.set_enabled(
                data["binding_id"],
                data["expected_revision"],
                operation == "enable",
                request_id=request_id,
            )
        stdout.write(
            json.dumps({"status": "ok", **result}, separators=(",", ":")) + "\n"
        )
        return 0
    except Exception:
        stdout.write('{"status":"unavailable_or_uncertain"}\n')
        return 1


if __name__ == "__main__":
    sys.exit(main())
