"""Command-line wiring for the legacy Cisco migration entrypoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any
from .common import (
    JOURNAL_DEFAULT,
    MigrationError,
    ROOT,
    Refused,
)
from .journal import Journal


def _api_from_stdin(uri: str, ca_file: str | None):
    if not sys.stdin.isatty():
        token = sys.stdin.readline().strip()
    else:
        import getpass

        token = getpass.getpass("Splunk session key: ")
    if not token or "\n" in token or "\r" in token:
        raise Refused("session key must be supplied via stdin")
    bin_root = ROOT / "splunk_app" / "splunk_adm" / "bin"
    sys.path.insert(0, str(bin_root))
    sys.path.insert(0, str(bin_root / "lib"))
    from adm_recovery_lib.rest import Rest

    return Rest(token, uri=uri, ca_file=ca_file)


def _read_scenario(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        info = path.lstat()
        if (
            not path.is_file()
            or path.is_symlink()
            or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise Refused(
                "scenario must be an owner-only regular JSON file under 64 KiB"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except Refused:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise Refused("validation scenario is unreadable or invalid JSON") from None
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise Refused(
            "validation scenario must map string field names to string values"
        )
    return value


def main(
    argv: list[str] | None = None, *, api_factory, migration_class, description
) -> int:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--journal", type=Path, default=JOURNAL_DEFAULT)
    parser.add_argument("--management-uri", default="https://localhost:8089")
    parser.add_argument("--ca-file")
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare")
    prepare.add_argument(
        "--start", required=True, type=int, help="inclusive UTC epoch, 5-minute aligned"
    )
    prepare.add_argument(
        "--end", required=True, type=int, help="exclusive UTC epoch, 5-minute aligned"
    )
    actions.add_parser("backfill")
    reconcile = actions.add_parser("reconcile")
    reconcile.add_argument(
        "--sid", required=True, help="operator-discovered SID for an ambiguous dispatch"
    )
    validate = actions.add_parser("validate")
    validate.add_argument(
        "--scenario", type=Path, help="owner-only deployment validation scenario JSON"
    )
    actions.add_parser("cutover")
    actions.add_parser("rollback")
    actions.add_parser("status")
    args = parser.parse_args(argv)
    try:
        journal = Journal(args.journal)
        if args.action == "status":
            print(
                json.dumps(
                    journal.read() or {"status": "uninitialized"},
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        api = api_factory(args.management_uri, args.ca_file)
        migration = migration_class(api, journal)
        with migration.operation_locked():
            if args.action == "prepare":
                result = migration.prepare(args.start, args.end)
            elif args.action == "backfill":
                result = migration.backfill()
            elif args.action == "reconcile":
                result = migration.reconcile(args.sid)
            elif args.action == "validate":
                result = migration.validate(_read_scenario(args.scenario))
            elif args.action == "cutover":
                result = migration.cutover()
            elif args.action == "rollback":
                result = migration.rollback()
            else:
                result = journal.read() or {"status": "uninitialized"}
    except MigrationError as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True))
        return 2
    except OSError as exc:
        reason = f"local file or TLS setup failed: {exc.strerror or type(exc).__name__}"
        print(json.dumps({"status": "refused", "reason": reason}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0
