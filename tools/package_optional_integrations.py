#!/usr/bin/env python3
"""Package explicitly selected external tooling separately from the Splunk app."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


PATHS = (
    "LICENSE",
    "NOTICE",
    "tools/export_o11y_health.py",
    "tools/capture_o11y_health.py",
    "tools/o11y_transport.py",
    "tools/export_o11y_detector_events.py",
    "tools/hec_delivery.py",
    "tools/export_appdynamics.py",
    "tools/import_appdynamics.py",
    "tools/import_asset_history.py",
    "tools/requirements-o11y.txt",
    "tools/validate_processor_contract.py",
    "integrations/processors/v1",
    "fixtures/processors",
    "docs/processors",
    "docs/operators/o11y-health.md",
    "docs/operators/o11y-detector-events.md",
    "docs/operators/appdynamics-evidence.md",
    "docs/operators/ingest-processors.md",
    "docs/OPTIONAL_INTEGRATIONS_PLAN.md",
    "docs/OPTIONAL_INTEGRATIONS_QUALIFICATION.md",
    "docs/O11Y_HEALTH_DESIGN.md",
    "docs/APPDYNAMICS_EVIDENCE_DESIGN.md",
)
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 512


def selected_files(root: Path, paths: tuple[str, ...] = PATHS) -> dict[str, bytes]:
    """Fail closed on missing artifacts, links, development files and secrets."""
    root = root.resolve()
    files: dict[str, bytes] = {}
    total = 0
    for relative in paths:
        path = root / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("Unsafe integration package path")
        if not path.exists() or any(
            parent.is_symlink()
            for parent in (path, *path.parents)
            if parent.is_relative_to(root)
        ):
            raise ValueError(f"Missing or linked integration artifact: {relative}")
        candidates = [path, *sorted(path.rglob("*"))] if path.is_dir() else [path]
        for candidate in candidates:
            name = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                raise ValueError(f"Linked integration artifact: {name}")
            if candidate.is_dir():
                continue
            if (
                not candidate.is_file()
                or any(
                    part.startswith(".")
                    or part.lower()
                    in {"credentials", "secrets", "node_modules", "__pycache__"}
                    for part in candidate.relative_to(root).parts
                )
                or candidate.suffix in {".pyc", ".pyo", ".pem", ".key"}
            ):
                raise ValueError(f"Unsafe integration artifact: {name}")
            if candidate.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"Oversized integration artifact: {name}")
            data = candidate.read_bytes()
            if len(data) > MAX_FILE_BYTES:
                raise ValueError(f"Oversized integration artifact: {name}")
            if name not in files:
                files[name] = data
                total += len(data)
            if len(files) > MAX_FILES or total > MAX_TOTAL_BYTES:
                raise ValueError("Integration package exceeds its file/byte budget")
    if not files:
        raise ValueError("Empty integration package")
    return files


def render_archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(f"application-atlas-integrations/{name}")
                entry.size = len(data)
                entry.mode = 0o644
                archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    dist = args.dist or root / "dist"
    version = json.loads((root / "package.json").read_text())["version"]
    if (
        not isinstance(version, str)
        or not all(part.isdecimal() for part in version.split("."))
        or len(version.split(".")) != 3
    ):
        raise ValueError("Invalid package version")
    content = render_archive(selected_files(root))
    dist.mkdir(parents=True, exist_ok=True)
    target = dist / f"application-atlas-integrations-{version}.tar.gz"
    checksum = Path(f"{target}.sha256")
    if target.is_symlink() or checksum.is_symlink():
        raise ValueError("Refusing linked package output")
    target.write_bytes(content)
    checksum.write_text(f"{hashlib.sha256(content).hexdigest()}  {target.name}\n")
    print(f"Created {target.name} ({len(content)} bytes); external runtimes only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
