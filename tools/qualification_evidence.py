#!/usr/bin/env python3
"""Create a small, integrity-checked packet for offline/install qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

SCHEMA = 1
MANIFEST = "manifest.json"
MAX_FILE = 512 * 1024 * 1024
MAX_REPORT = 16 * 1024 * 1024
MAX_RUNTIME_RESPONSE = 64 * 1024
CHECKS = frozenset(
    {
        "release",
        "atlas_bundle",
        "appinspect",
        "lab_lifecycle",
        "splunk_integration",
        "native_runtime",
    }
)
PACKAGE_ROLES = {
    "main": re.compile(r"^splunk_adm-\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\.tar\.gz$"),
    "atlas_bundle": re.compile(
        r"^application-atlas-integrations-\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\.tar\.gz$"
    ),
}
STAGES = frozenset({"offline", "installed"})


class EvidenceError(RuntimeError):
    pass


def _sha(path: Path, limit: int = MAX_FILE) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"unsafe or missing file: {path.name}")
    if path.stat().st_size > limit:
        raise EvidenceError(f"file exceeds bound: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=".manifest.", delete=False
    ) as out:
        tmp = Path(out.name)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    checksum = path.with_name(path.name + ".sha256")
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=".checksum.", mode="w", delete=False
    ) as out:
        check_tmp = Path(out.name)
        out.write(hashlib.sha256(data).hexdigest() + "  " + path.name + "\n")
        out.flush()
        os.fsync(out.fileno())
    os.chmod(check_tmp, 0o600)
    os.replace(check_tmp, checksum)


def _load(directory: Path) -> dict[str, Any]:
    path = directory / MANIFEST
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
        raise EvidenceError("manifest is missing")
    checksum = path.with_name(path.name + ".sha256")
    if (
        not checksum.is_file()
        or checksum.is_symlink()
        or checksum.stat().st_size > 4096
    ):
        raise EvidenceError("manifest checksum is missing")
    line = checksum.read_text(encoding="utf-8").strip()
    if (
        not re.fullmatch(r"[0-9a-fA-F]{64}  manifest\.json", line)
        or line.split()[0].casefold() != _sha(path).casefold()
    ):
        raise EvidenceError("manifest checksum mismatch")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError("manifest must be an object")
    if (
        value.get("schemaVersion") != SCHEMA
        or value.get("stage") not in STAGES
        or value.get("status") not in {"incomplete", "failed", "complete"}
    ):
        raise EvidenceError("manifest schema or lifecycle status is invalid")
    if not isinstance(value.get("packages"), list) or not isinstance(
        value.get("checks"), list
    ):
        raise EvidenceError("manifest package/check records are invalid")
    return value


def _write(directory: Path, manifest: dict[str, Any]) -> None:
    _atomic_json(directory / MANIFEST, manifest)


def _manifest_sha(directory: Path) -> str:
    return _sha(directory / MANIFEST, 2 * 1024 * 1024)


def _read_sidecar(path: Path, expected: str) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        raise EvidenceError("invalid checksum sidecar")
    if path.read_text(encoding="utf-8").strip() != expected:
        raise EvidenceError("checksum sidecar mismatch")


def _valid_runtime(runtime: Any) -> bool:
    if not isinstance(runtime, dict):
        return False
    version = runtime.get("version")
    build = runtime.get("build")
    product = runtime.get("product_type")
    return (
        isinstance(version, str)
        and re.fullmatch(r"\d+(?:\.\d+){2,4}", version) is not None
        and isinstance(build, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", build) is not None
        and build.casefold() not in {"unknown", "unavailable", "none", "null", "build"}
        and isinstance(product, str)
        and product == "enterprise"
    )


def _verify_packet(
    directory: Path, stage: str | None = None, root: Path | None = None
) -> dict[str, Any]:
    manifest = _load(directory)
    if manifest.get("schemaVersion") != SCHEMA or manifest.get("status") != "complete":
        raise EvidenceError("packet is not a complete supported manifest")
    actual_stage = manifest.get("stage")
    if actual_stage not in STAGES or (stage and actual_stage != stage):
        raise EvidenceError("packet stage mismatch")
    required = (
        {"release", "atlas_bundle", "appinspect"}
        if actual_stage == "offline"
        else {"release", "lab_lifecycle", "splunk_integration"}
    )
    checks = {}
    for item in manifest.get("checks", []):
        if (
            not isinstance(item, dict)
            or item.get("name") not in CHECKS
            or item.get("name") in checks
        ):
            raise EvidenceError("unknown or duplicate check record")
        if item.get("status") != "passed" or item.get("exitcode") != 0:
            raise EvidenceError("packet contains a non-passing check")
        checks[item["name"]] = item
    if any(
        checks.get(name, {}).get("status") != "passed"
        or checks.get(name, {}).get("exitcode") != 0
        for name in required
    ):
        raise EvidenceError("required qualification check is absent or not passed")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > 2:
        raise EvidenceError("invalid package records")
    if (
        sum(
            package.get("role") == "main" and package.get("required") is True
            for package in packages
        )
        != 1
    ):
        raise EvidenceError("application package role is invalid")
    for package in packages:
        snapshot_name = package.get("snapshot")
        checksum_name = package.get("snapshot_checksum")
        if not isinstance(snapshot_name, str) or not isinstance(checksum_name, str):
            raise EvidenceError("invalid snapshot record")
        snapshot_raw = directory / snapshot_name
        checksum_raw = directory / checksum_name
        if snapshot_raw.is_symlink() or checksum_raw.is_symlink():
            raise EvidenceError("snapshot symlink is not allowed")
        snapshot = snapshot_raw.resolve()
        checksum = checksum_raw.resolve()
        if (
            directory.resolve() not in snapshot.parents
            or directory.resolve() not in checksum.parents
        ):
            raise EvidenceError("snapshot escapes packet directory")
        if snapshot.name != package.get("basename") or _sha(snapshot) != package.get(
            "sha256"
        ):
            raise EvidenceError("snapshot checksum mismatch")
        _read_sidecar(checksum, f"{package['sha256']}  {snapshot.name}")
    if actual_stage == "offline":
        summary = manifest.get("outcomes", {}).get("appinspect")
        if (
            not isinstance(summary, dict)
            or summary.get("valid") is not True
            or not isinstance(summary.get("counts"), dict)
            or not summary.get("sha256")
            or not re.fullmatch(r"[0-9a-f]{64}", str(summary.get("sha256")))
            or not any(
                int(value or 0)
                for key, value in summary["counts"].items()
                if key
                in {
                    "success",
                    "warning",
                    "not_applicable",
                    "skipped",
                    "future_failure",
                    "error",
                    "failure",
                }
            )
            or any(
                int(summary["counts"].get(key, 0) or 0) for key in ("error", "failure")
            )
        ):
            raise EvidenceError("AppInspect summary is missing or invalid")
    if actual_stage == "installed":
        parent = manifest.get("parent_packet")
        if (
            not isinstance(parent, dict)
            or parent.get("stage") != "offline"
            or not re.fullmatch(r"[0-9a-f]{64}", str(parent.get("manifest_sha256", "")))
            or not isinstance(parent.get("packages"), dict)
        ):
            raise EvidenceError("installed packet parent provenance is missing")
        if parent.get("source_commit") != manifest.get("source", {}).get("commit"):
            raise EvidenceError("installed packet parent source differs")
        if parent.get("packages") != {p.get("role"): p.get("sha256") for p in packages}:
            raise EvidenceError("installed packet parent packages differ")
        runtime = manifest.get("runtime", {}).get("splunk", {})
        if manifest.get("outcomes", {}).get(
            "lab_runtime"
        ) != "available" or not _valid_runtime(runtime):
            raise EvidenceError("native runtime evidence is missing")
    if root is not None:
        current = _source_fingerprint(root)
        source = manifest.get("source", {})
        if any(
            source.get(key) != current.get(key) for key in ("sha256", "commit", "tree")
        ):
            raise EvidenceError("source identity changed")
    return manifest


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError("git source identity unavailable") from exc


def _source_fingerprint(root: Path) -> dict[str, Any]:
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError("git source fingerprint unavailable") from exc
    names = raw.decode().split("\0") if raw else []
    prefixes = (
        "frontend/",
        "config/",
        "splunk_app/",
        "tools/",
        "tests/",
        ".github/",
        "docs/",
        "fixtures/",
        "integrations/",
        "research/",
    )
    selected = [
        n
        for n in names
        if n.startswith(prefixes)
        or n
        in {
            "package.json",
            "package-lock.json",
            "Makefile",
            "pyproject.toml",
            "vite.config.ts",
            "vite.splunk.config.ts",
            "tsconfig.json",
            "tsconfig.browser.json",
            ".eslintrc.json",
            "eslint.config.mjs",
            "playwright.config.ts",
            "research/package-manifest.json",
        }
    ]
    digest = hashlib.sha256()
    records = []
    for name in sorted(set(selected)):
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"source path is missing or symlinked: {name}")
        value = _sha(path)
        digest.update(name.encode() + b"\0" + value.encode() + b"\n")
        records.append({"path": name, "sha256": value})
    return {
        "sha256": digest.hexdigest(),
        "files": records,
        "commit": _git(root, "rev-parse", "HEAD"),
        "tree": _git(root, "rev-parse", "HEAD^{tree}"),
        "dirty": bool(_git(root, "status", "--porcelain")),
    }


def _version(command: str) -> str:
    path = shutil.which(command)
    if not path:
        return "unavailable"
    try:
        result = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        return (result.stdout or result.stderr).strip()[:120] or "unavailable"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def _runtime_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "node": _version("node"),
        "npm": _version("npm"),
        "appinspect": _version("splunk-appinspect"),
    }


def _package(root: Path, directory: Path, value: str, required: bool) -> dict[str, Any]:
    source = Path(value)
    if source.is_absolute() or ".." in source.parts:
        raise EvidenceError("package must be a root-relative path")
    path = root / source
    role = next(
        (
            name
            for name, pattern in PACKAGE_ROLES.items()
            if pattern.fullmatch(path.name)
        ),
        None,
    )
    if (
        role is None
        or (required and role != "main")
        or (not required and role != "atlas_bundle")
    ):
        raise EvidenceError(f"unsupported package basename: {path.name}")
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE:
        raise EvidenceError(f"invalid package: {value}")
    sidecar = path.with_name(path.name + ".sha256")
    if not sidecar.is_file() or sidecar.is_symlink() or sidecar.stat().st_size > 4096:
        raise EvidenceError(f"checksum sidecar missing: {path.name}")
    line = sidecar.read_text(encoding="utf-8").strip().splitlines()
    if len(line) != 1 or not re.fullmatch(
        r"[0-9a-fA-F]{64}  " + re.escape(path.name), line[0]
    ):
        raise EvidenceError(f"checksum sidecar does not name {path.name}")
    digest = _sha(path)
    if digest.casefold() != line[0].split()[0].casefold():
        raise EvidenceError(f"checksum mismatch: {path.name}")
    snapshot = directory / "artifacts" / path.name
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(snapshot.parent, 0o700)
    shutil.copyfile(path, snapshot)
    os.chmod(snapshot, 0o600)
    snapshot_sidecar = snapshot.with_name(snapshot.name + ".sha256")
    snapshot_sidecar.write_text(f"{digest}  {snapshot.name}\n", encoding="utf-8")
    os.chmod(snapshot_sidecar, 0o600)
    return {
        "path": source.as_posix(),
        "basename": path.name,
        "sha256": digest,
        "size": path.stat().st_size,
        "required": required,
        "role": role,
        "snapshot": snapshot.relative_to(directory).as_posix(),
        "snapshot_checksum": snapshot_sidecar.relative_to(directory).as_posix(),
    }


def start(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    if directory.exists():
        raise EvidenceError("qualification directory already exists")
    if args.stage not in STAGES:
        raise EvidenceError("unknown qualification stage")
    directory.mkdir(parents=True, mode=0o700)
    root = Path(args.root).resolve()
    parent_path = getattr(args, "parent_packet", None)
    if args.stage == "installed" and not parent_path:
        raise EvidenceError("installed qualification requires --parent-packet")
    if args.stage == "offline" and parent_path:
        raise EvidenceError("offline qualification cannot have a parent packet")
    parent = _verify_packet(Path(parent_path), "offline", root) if parent_path else None
    packages = [
        _package(root, directory, value, i == 0) for i, value in enumerate(args.package)
    ]
    if len(packages) > 2 or len({p["basename"] for p in packages}) != len(packages):
        raise EvidenceError("at most two unique packages are allowed")
    if sum(p["role"] == "main" for p in packages) != 1:
        raise EvidenceError("application package is required")
    if parent:
        parent_hashes = {p.get("role"): p.get("sha256") for p in parent["packages"]}
        current_hashes = {p.get("role"): p.get("sha256") for p in packages}
        if current_hashes != parent_hashes:
            raise EvidenceError("installed package differs from offline packet")
    manifest = {
        "schemaVersion": SCHEMA,
        "status": "incomplete",
        "stage": args.stage,
        "limits": {"runtime": False, "cloud": False, "production": False},
        "source": _source_fingerprint(root),
        "packages": packages,
        "runtime": _runtime_versions(),
        "checks": [],
        "outcomes": {},
    }
    run_meta = {
        key: os.environ[key]
        for key in (
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_SHA",
            "GITHUB_REPOSITORY",
            "GITHUB_EVENT_NAME",
        )
        if os.environ.get(key)
    }
    if run_meta:
        if run_meta.get("GITHUB_SHA") and run_meta["GITHUB_SHA"] != manifest[
            "source"
        ].get("commit"):
            raise EvidenceError("GITHUB_SHA does not match source commit")
        manifest["ci"] = run_meta
    if parent:
        manifest["parent_packet"] = {
            "manifest_sha256": _manifest_sha(Path(parent_path)),
            "stage": "offline",
            "source_commit": parent["source"].get("commit"),
            "packages": {p["role"]: p["sha256"] for p in parent["packages"]},
            "ci": parent.get("ci", {}),
        }
    _write(directory, manifest)
    return 0


def run_check(args: argparse.Namespace) -> int:
    if args.check not in CHECKS:
        raise EvidenceError("unknown check name")
    manifest = _load(Path(args.directory))
    if any(item.get("name") == args.check for item in manifest.get("checks", [])):
        raise EvidenceError(f"duplicate check: {args.check}")
    command = list(args.command or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise EvidenceError("run requires a command after --")
    if args.check == "splunk_integration":
        package = next(
            (
                p
                for p in manifest.get("packages", [])
                if p.get("basename", "").startswith("splunk_adm-")
            ),
            None,
        )
        env_package = os.environ.get("ADM_LAB_PACKAGE")
        if (
            not package
            or not env_package
            or _sha(Path(env_package)) != package.get("sha256")
            or os.environ.get("ADM_LAB") != "1"
        ):
            raise EvidenceError(
                "splunk_integration requires ADM_LAB=1 and the captured package"
            )
    manifest = _load(Path(args.directory))
    started = time.time()
    manifest.setdefault("checks", []).append(
        {"name": args.check, "status": "running", "started": started}
    )
    _write(Path(args.directory), manifest)
    try:
        result = subprocess.run(command, cwd=args.root, check=False)
    except KeyboardInterrupt:
        return 130
    except OSError:
        result = None
    finished = time.time()
    manifest = _load(Path(args.directory))
    record = next(
        item
        for item in manifest["checks"]
        if item.get("name") == args.check and item.get("status") == "running"
    )
    record.update(
        {
            "status": "passed"
            if result is not None and result.returncode == 0
            else "failed",
            "exitcode": result.returncode if result is not None else None,
            "finished": finished,
            "duration": finished - started,
        }
    )
    _write(Path(args.directory), manifest)
    return result.returncode if result is not None else 1


def _appinspect_summary(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_REPORT:
        raise EvidenceError("AppInspect report exceeds 16 MiB")
    from tools.check_appinspect import KNOWN_RESULTS, check_report

    failures = check_report(path)
    report = json.loads(path.read_text(encoding="utf-8"))
    counts = {name: 0 for name in sorted(KNOWN_RESULTS)}
    for item in report.get("reports", []) if isinstance(report, dict) else report:
        for group in item.get("groups", []) if isinstance(item, dict) else []:
            for check in group.get("checks", []) if isinstance(group, dict) else []:
                result = check.get("result") if isinstance(check, dict) else None
                if isinstance(result, str) and result.casefold() in counts:
                    counts[result.casefold()] += 1
    return {"counts": counts, "sha256": _sha(path, MAX_REPORT), "valid": not failures}


def finish(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    manifest = _load(directory)
    root = Path(args.root).resolve()
    problems = []
    try:
        current_source = _source_fingerprint(root)
        recorded_source = manifest.get("source", {})
        if any(
            recorded_source.get(key) != current_source.get(key)
            for key in ("sha256", "commit", "tree")
        ):
            problems.append("source_changed")
    except (OSError, EvidenceError):
        problems.append("source_unavailable")
    for package in manifest.get("packages", []):
        try:
            if (
                not isinstance(package.get("path"), str)
                or Path(package["path"]).is_absolute()
                or ".." in Path(package["path"]).parts
            ):
                raise EvidenceError("package path escapes root")
            source = root / package["path"]
            snapshot = directory / package["snapshot"]
            snapshot_checksum = directory / package["snapshot_checksum"]
            if _sha(source) != package["sha256"] or _sha(snapshot) != package["sha256"]:
                problems.append("package_changed")
            _read_sidecar(snapshot_checksum, f"{package['sha256']}  {snapshot.name}")
        except (OSError, KeyError, EvidenceError):
            problems.append("package_unavailable")
    checks = {}
    for item in manifest.get("checks", []):
        if (
            not isinstance(item, dict)
            or item.get("name") not in CHECKS
            or item.get("name") in checks
        ):
            problems.append("check_record_invalid")
            continue
        checks[item["name"]] = item
        if item.get("status") == "running":
            problems.append(f"check_{item['name']}_incomplete")
        elif item.get("status") != "passed" or item.get("exitcode") != 0:
            problems.append(f"check_{item['name']}_failed")
    if not manifest.get("packages"):
        problems.append("packages_missing")
    required = set(args.require)
    required.update(
        {"release", "atlas_bundle", "appinspect"}
        if manifest.get("stage") == "offline"
        else {"release", "lab_lifecycle", "splunk_integration"}
    )
    for name in required:
        status = checks.get(name, {}).get("status")
        if status != "passed":
            problems.append(
                f"check_{name}_{'incomplete' if status in (None, 'running') else 'failed'}"
            )
    if not checks:
        problems.append("checks_missing")
    if manifest.get("stage") == "installed":
        parent = manifest.get("parent_packet", {})
        if (
            not isinstance(parent, dict)
            or parent.get("stage") != "offline"
            or not re.fullmatch(r"[0-9a-f]{64}", str(parent.get("manifest_sha256", "")))
            or parent.get("source_commit") != manifest.get("source", {}).get("commit")
            or parent.get("packages")
            != {p.get("role"): p.get("sha256") for p in manifest.get("packages", [])}
        ):
            problems.append("parent_packet_invalid")
        runtime = manifest.get("runtime", {}).get("splunk", {})
        if manifest.get("outcomes", {}).get(
            "lab_runtime"
        ) != "available" or not _valid_runtime(runtime):
            problems.append("runtime_missing")
    report = args.appinspect_report
    if manifest.get("stage") == "offline" and not report:
        problems.append("appinspect_report_missing")
    if report:
        try:
            manifest["outcomes"]["appinspect"] = _appinspect_summary(Path(report))
            if not manifest["outcomes"]["appinspect"]["valid"]:
                problems.append("appinspect_failed")
        except (OSError, ValueError, EvidenceError):
            problems.append("appinspect_invalid")
    manifest["runtime_versions"] = _runtime_versions()
    incomplete_only = problems and all(
        p == "checks_missing"
        or p.endswith("_incomplete")
        or p in {"appinspect_report_missing"}
        for p in problems
    )
    manifest["status"] = (
        "complete" if not problems else ("incomplete" if incomplete_only else "failed")
    )
    manifest["finish"] = {"problems": problems, "finished": time.time()}
    _write(directory, manifest)
    return 0 if not problems else 1


def lab_runtime(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    manifest = _load(directory)
    try:
        from tests.splunk import lab

        with lab._mgmt("GET", "/services/server/info?output_mode=json") as response:
            body = response.read(MAX_RUNTIME_RESPONSE + 1)
        if len(body) > MAX_RUNTIME_RESPONSE:
            raise EvidenceError("runtime response exceeds bound")
        value = json.loads(body.decode("utf-8"))
        entries = value.get("entry")
        content = (
            entries[0].get("content")
            if isinstance(entries, list)
            and len(entries) == 1
            and isinstance(entries[0], dict)
            else None
        )
        if not isinstance(content, dict):
            raise EvidenceError("invalid runtime response")
        safe = {}
        for key in ("version", "build", "product_type"):
            item = content.get(key)
            if (
                not isinstance(item, str)
                or not item.strip()
                or len(item) > 120
                or not re.fullmatch(r"[A-Za-z0-9_. -]+", item)
            ):
                raise EvidenceError("invalid runtime field")
            safe[key] = item
        if not _valid_runtime(safe):
            raise EvidenceError("unsupported runtime identity")
        manifest.setdefault("runtime", {})["splunk"] = safe
        manifest.setdefault("outcomes", {})["lab_runtime"] = "available"
    except Exception:
        manifest.setdefault("runtime", {})["splunk"] = {"status": "unavailable"}
        manifest.setdefault("outcomes", {})["lab_runtime"] = "unavailable"
        _write(directory, manifest)
        return 1
    _write(directory, manifest)
    return 0


def verify(args: argparse.Namespace) -> int:
    _verify_packet(Path(args.directory), args.stage, Path(args.root).resolve())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    sub = parser.add_subparsers(dest="action", required=True)
    begin = sub.add_parser("start")
    begin.add_argument("--directory", required=True)
    begin.add_argument("--stage", required=True)
    begin.add_argument("--package", action="append", required=True)
    begin.add_argument("--parent-packet")
    run = sub.add_parser("run")
    run.add_argument("--directory", required=True)
    run.add_argument("--check", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    end = sub.add_parser("finish")
    end.add_argument("--directory", required=True)
    end.add_argument("--require", action="append", default=[])
    end.add_argument("--appinspect-report")
    runtime = sub.add_parser("lab-runtime")
    runtime.add_argument("--directory", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--directory", required=True)
    verify_parser.add_argument("--stage")
    args = parser.parse_args()
    try:
        return {
            "start": start,
            "run": run_check,
            "finish": finish,
            "lab-runtime": lab_runtime,
            "verify": verify,
        }[args.action](args)
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"qualification evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
