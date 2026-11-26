#!/usr/bin/env python3
"""Build offline configuration evidence and generation HEC files.

This command accepts a local normalized JSON export and writes local HEC
NDJSON plus an immutable generation manifest. It does not connect to Splunk,
vendor systems, or arbitrary URLs.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.change_correlation.contracts import (
    MAX_INPUT_BYTES,
    ContractError,
    parse_json_document,
)
from tools.change_correlation.export import render_generation_hec, render_manifest_json
from tools.change_correlation.history import build_generation


class OutputExists(Exception):
    pass


def _atomic_write(path: Path, content: bytes, *, overwrite: bool = False) -> None:
    """Publish ``content`` at ``path`` atomically.

    Without ``overwrite`` the publish is a hard link, which fails instead of
    replacing a file that appeared after any earlier existence check.
    """
    if not path.parent.is_dir():
        raise OSError("Output directory does not exist.")
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temp_path, path)
        else:
            try:
                os.link(temp_path, path)
            except FileExistsError as exc:
                raise OutputExists() from exc
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def _backup(path: Path) -> Path | None:
    """Hard-link an existing output aside so a failed pair can restore it."""
    if not path.exists():
        return None
    for _attempt in range(8):
        backup = path.with_name(f".{path.name}.{secrets.token_hex(8)}.previous")
        try:
            os.link(path, backup)
        except FileExistsError:
            continue
        return backup
    raise OSError("Could not reserve a backup name.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize local configuration evidence and render HEC NDJSON offline."
    )
    parser.add_argument(
        "input", type=Path, help="Local versioned JSON collection document"
    )
    parser.add_argument(
        "--output-hec", required=True, type=Path, help="HEC NDJSON output path"
    )
    parser.add_argument(
        "--output-manifest",
        required=True,
        type=Path,
        help="Immutable generation manifest output path",
    )
    parser.add_argument(
        "--index",
        required=True,
        help="Administrator-selected literal Splunk index for all HEC events",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Replace existing output files instead of refusing. Both modes use "
            "hard links (no-clobber publishing, or the rollback backup of the "
            "previous HEC file), so the output directory must support them."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    input_path = args.input.resolve()
    hec_path = args.output_hec.resolve()
    manifest_path = args.output_manifest.resolve()
    if hec_path == manifest_path or input_path in {hec_path, manifest_path}:
        print(
            "output_conflict: Input and output paths must be distinct.", file=sys.stderr
        )
        return 2
    if not args.overwrite and (hec_path.exists() or manifest_path.exists()):
        print(
            "output_exists: Output files already exist; pass --overwrite to replace them.",
            file=sys.stderr,
        )
        return 2
    try:
        with input_path.open("rb") as source:
            # Bound the read itself, including a file that grows after stat().
            collections = parse_json_document(source.read(MAX_INPUT_BYTES + 1))
        generation = build_generation(collections)
        hec_content = render_generation_hec(generation, index=args.index).encode(
            "utf-8"
        )
        manifest_content = render_manifest_json(generation).encode("utf-8")
        backup = _backup(hec_path) if args.overwrite else None
        try:
            _atomic_write(hec_path, hec_content, overwrite=args.overwrite)
            published = os.stat(hec_path).st_ino
            try:
                _atomic_write(manifest_path, manifest_content, overwrite=args.overwrite)
            except BaseException:
                # Never leave a new HEC file paired with a stale or absent manifest.
                with contextlib.suppress(OSError):
                    if os.stat(hec_path).st_ino == published:
                        if backup is not None:
                            os.replace(backup, hec_path)
                        else:
                            hec_path.unlink()
                raise
        finally:
            if backup is not None:
                with contextlib.suppress(OSError):
                    backup.unlink()
    except OutputExists:
        print(
            "output_exists: Output files already exist; pass --overwrite to replace them.",
            file=sys.stderr,
        )
        return 2
    except ContractError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        # Avoid printing exception strings that may contain input or payload data.
        print("io_error: Could not read input or write output files.", file=sys.stderr)
        return 2
    print(
        f"Wrote offline HEC and manifest for generation {generation['manifest']['generation_id']} "
        f"({generation['manifest']['row_count']} rows)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
