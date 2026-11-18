"""Synthetic native filesystem/ledger fixture, never a production entry point."""

import configparser
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid

sys.path[:0] = [str(Path(__file__).parent), "/opt/splunk/etc/apps/splunk_adm/bin"]
from adm_cases_lib.store import CaseStore  # noqa: E402
from adm_cases_lib.job_ledger import JobLedger, QuotaExceeded  # noqa: E402
from case_recovery_snapshot import inspect_database, schema_descriptor  # noqa: E402

TASKS = {
    "cases-recovery-source-20261117",
    "cases-recovery-occupied-20261117",
    "cases-recovery-target-20261117",
}
ROOT = Path("/opt/splunk/var/lib/splunk/splunk_adm_investigations")
NAMES = ("cases.sqlite", "capture_jobs.sqlite")


def require(condition):
    if not condition:
        raise RuntimeError("native recovery fixture condition failed")


def flags():
    content = subprocess.check_output(
        [
            "/opt/splunk/bin/splunk",
            "btool",
            "adm_investigations",
            "list",
            "persistence",
            "--app=splunk_adm",
        ],
        timeout=30,
        text=True,
    )
    config = configparser.ConfigParser()
    config.read_string(content)
    require(config.get("persistence", "mode") == "disabled")
    require(config.get("persistence", "capture_mode") == "disabled")


def metadata(path, mode):
    info = path.lstat()
    require(not path.is_symlink() and info.st_uid == os.getuid())
    require(stat.S_IMODE(info.st_mode) == mode)
    if mode == 0o600:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    else:
        require(stat.S_ISDIR(info.st_mode))
    return {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode,
        "links": info.st_nlink,
    }


def schemas():
    with tempfile.TemporaryDirectory(prefix="adm-recovery-reference-") as temp:
        root = Path(temp)
        CaseStore(root / "cases.sqlite", lambda *_: False)
        os.chmod(root / "cases.sqlite", 0o600)
        JobLedger(root / "capture_jobs.sqlite")
        return {name: schema_descriptor(root / name) for name in NAMES}


def describe(principal, expected):
    metadata(ROOT, 0o700)
    allowed = set(NAMES) | {n + s for n in NAMES for s in ("-wal", "-shm")}
    require({p.name for p in ROOT.iterdir()} <= allowed)
    file_meta = {p.name: metadata(p, 0o600) for p in ROOT.iterdir()}
    # Read-only schema proof precedes the ledger constructor, which can migrate.
    databases = {name: inspect_database(ROOT / name, expected[name]) for name in NAMES}
    ledger = JobLedger(ROOT / "capture_jobs.sqlite", clock=lambda: 100000)
    rows = ledger.outstanding(principal)
    require(len(rows) == 3)
    require(
        {r["state"] for r in rows}
        == {"creating", "creation_unknown", "cleanup_unknown"}
    )
    try:
        ledger.reserve(
            principal,
            "adm-capture-" + uuid.uuid4().hex,
            "c" * 64,
            1,
            301,
            "a" * 32,
            transport_hash="d" * 64,
        )
    except QuotaExceeded:
        charged = True
    else:
        raise RuntimeError("unresolved job capacity was released")
    require(ledger.outstanding(principal) == rows)
    return {
        "schemas": expected,
        "databases": databases,
        "files": file_meta,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "ledger": rows,
        "quota_still_charged": charged,
        "native_jobs_dispatched": False,
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.system(),
        "machine": platform.machine(),
        "persistence_and_capture_disabled": True,
    }


def main():
    task = os.environ.get("ADM_RECOVERY_NATIVE_TASK")
    require(task in TASKS and os.getuid() != 0)
    require(ROOT.resolve() == ROOT and ROOT.parent.resolve() == ROOT.parent)
    flags()
    data = json.load(sys.stdin)
    action = data["action"]
    if action == "identity":
        require(not os.path.lexists(ROOT))
        return {"uid": os.getuid(), "gid": os.getgid(), "schemas": schemas()}
    if action == "occupied":
        require(task == "cases-recovery-occupied-20261117")
        ROOT.mkdir(mode=0o700)
        fd = os.open(
            ROOT / "refuse-overwrite-marker",
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"owned negative recovery target\n")
            stream.flush()
            os.fsync(stream.fileno())
        return {"uid": os.getuid(), "gid": os.getgid(), "marker_created": True}
    principal = data["principal"]
    require(re.fullmatch(r"atlas_case_[0-9a-f]{10}a", principal) is not None)
    expected = schemas()
    if action == "prepare":
        require(task == "cases-recovery-source-20261117")
        require(not os.path.lexists(ROOT / "capture_jobs.sqlite"))
        ledger = JobLedger(ROOT / "capture_jobs.sqlite", clock=lambda: 100)
        ids = ["adm-capture-" + uuid.uuid4().hex for _ in range(3)]
        owner = uuid.uuid4().hex
        for ident in ids:
            ledger.reserve(
                principal, ident, "c" * 64, 1, 301, owner, transport_hash="d" * 64
            )
        ledger.transition(
            principal, ids[0], owner, "creation_unknown", expected_revision=1
        )
        ledger.bind_created(
            principal, ids[1], owner, "1700000000.1", expected_revision=1
        )
        ledger.transition(
            principal, ids[1], owner, "cleanup_unknown", expected_revision=2
        )
    else:
        require(action == "inspect" and data["schemas"] == expected)
    return describe(principal, expected)


if __name__ == "__main__":
    print(json.dumps(main(), sort_keys=True))
