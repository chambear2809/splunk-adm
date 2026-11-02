#!/usr/bin/env python3
"""Build the Atlas receiver into a pinned official Splunk collector source tree.

The source tree must be an isolated, clean checkout; downloaded build scripts
are never invoked. This builds an Atlas artifact, not an official vendor binary.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "370a0a68ebf661de554e9b9f28077959dc6033d8"
FACTORIES_SHA = "a9efa6a0fa0776c4ca2f9b753ebb17101b79060a59794b6f5da6604aa5a799f0"
MODULE = "github.com/atlascisco/splunk-adm/integrations/otel_atlas_receiver"
VERSION = "0.164.0-atlas-device-evidence-r1"


def build(source, output):
    source, output = source.resolve(), output.resolve()
    report_path = output.with_name(output.name + ".json")
    if output.exists() or report_path.exists():
        raise ValueError("output already exists")
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=source, text=True
    )
    factory_path = source / "internal/components/components.go"
    if (
        head != COMMIT
        or dirty
        or hashlib.sha256(factory_path.read_bytes()).hexdigest() != FACTORIES_SHA
    ):
        raise ValueError("expected clean pinned vendor source")
    receiver = ROOT / "integrations/otel_atlas_receiver"
    files = sorted(p for p in receiver.rglob("*") if p.is_file())
    if not files or any(p.is_symlink() for p in receiver.rglob("*")):
        raise ValueError("invalid receiver source")
    source_hashes = {
        str(p.relative_to(receiver)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in files
    }
    shutil.copytree(receiver, source / "atlas_receiver")
    original = factory_path.read_text()
    marker = '\t"github.com/signalfx/splunk-otel-collector/baseline"'
    end = "\treturn b.Build()"
    if original.count(marker) != 1 or original.count(end) != 1:
        raise ValueError("vendor registration changed")
    modified = original.replace(marker, marker + f'\n\tatlasreceiver "{MODULE}"')
    modified = modified.replace(
        end, "\tb.AddReceivers(atlasreceiver.NewFactory())\n\n" + end
    )
    factory_path.write_text(modified)
    subprocess.run(["gofmt", "-w", str(factory_path)], check=True)
    subprocess.run(
        [
            "go",
            "mod",
            "edit",
            f"-require={MODULE}@v0.0.0",
            f"-replace={MODULE}=./atlas_receiver",
        ],
        cwd=source,
        check=True,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    environment = {**os.environ, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    subprocess.run(
        [
            "go",
            "build",
            "-p",
            "6",
            "-mod=mod",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags",
            f"-s -w -X github.com/signalfx/splunk-otel-collector/internal/version.Version={VERSION}",
            "-o",
            str(output),
            "./cmd/otelcol",
        ],
        cwd=source,
        env=environment,
        check=True,
    )
    report = {
        "vendor_version": "0.164.0",
        "vendor_commit": COMMIT,
        "atlas_version": VERSION,
        "platform": "linux/amd64",
        "artifact_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "artifact_bytes": output.stat().st_size,
        "receiver_source_sha256": source_hashes,
        "factory_source_sha256": hashlib.sha256(factory_path.read_bytes()).hexdigest(),
        "go_mod_sha256": hashlib.sha256((source / "go.mod").read_bytes()).hexdigest(),
        "go_sum_sha256": hashlib.sha256((source / "go.sum").read_bytes()).hexdigest(),
        "qualification": "built_not_deployed",
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: report[k]
                for k in ("atlas_version", "artifact_sha256", "artifact_bytes")
            }
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.source, args.output)


if __name__ == "__main__":
    main()
