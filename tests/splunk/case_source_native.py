"""Read-only exact fixture capture receipt and search ledger inspection."""

from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

ROOT = Path("/opt/splunk/var/lib/splunk/splunk_adm_investigations")


def read_db(name):
    path = ROOT / name
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise RuntimeError("unsafe database")
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)


def main():
    if (
        os.environ.get("ADM_CASE_SOURCE_NATIVE_TASK") != "cases-source-20261118"
        or os.getuid() == 0
    ):
        raise RuntimeError("wrong task")
    value = json.load(sys.stdin)
    if (
        set(value) != {"principal", "request_id"}
        or not re.fullmatch(r"atlas_ev_[0-9a-f]{10}a", value["principal"])
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value["request_id"])
    ):
        raise RuntimeError("invalid identity")
    with closing(read_db("cases.sqlite")) as db:
        rows = db.execute(
            "SELECT action, case_id, digest, result FROM requests WHERE principal=? AND request_id=?",
            (value["principal"], value["request_id"]),
        ).fetchall()
    try:
        ledger = read_db("capture_jobs.sqlite")
    except FileNotFoundError:
        jobs = []
    else:
        with closing(ledger) as db:
            jobs = db.execute(
                "SELECT sid, server_sid, state FROM jobs WHERE principal=? ORDER BY seq",
                (value["principal"],),
            ).fetchall()
    return {
        "requests": [
            {
                "action": row[0],
                "case_id": row[1],
                "digest": row[2],
                "result": json.loads(row[3]),
            }
            for row in rows
        ],
        "jobs": [
            {"sid": row[0], "server_sid": row[1], "state": row[2]} for row in jobs
        ],
    }


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__}))
        sys.exit(1)
