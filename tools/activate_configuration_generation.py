#!/usr/bin/env python3
"""Verify complete configuration history before activating an owned local lab.

No credentials are accepted as arguments. Production activation is intentionally
not implemented by this qualification helper. An offline readback can be checked
without producing an activation event.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import importlib.util
import json
import math
import os
import re
import sys
import time
from pathlib import Path

if __package__:
    from .change_correlation.contracts import canonical_json, sha256_hex
    from .change_correlation.history import row_record_id
else:
    from change_correlation.contracts import canonical_json, sha256_hex
    from change_correlation.history import row_record_id

ROOT = Path(__file__).resolve().parents[1]
MAX_ROWS = 10_000
MAX_BYTES = 50 * 1024 * 1024
CHANGE_TYPE = "adm:configuration_change:v1"
MANIFEST_TYPE = "adm:configuration_change_manifest:v1"
ACTIVATION_TYPE = "adm:configuration_change_activation:v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
INDEX = re.compile(r"[a-z][a-z0-9_-]{0,79}\Z")


class ActivationError(ValueError):
    """A closed failure without source payload contents."""


def read_json(path: Path):
    with path.open("rb") as source:
        content = source.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ActivationError("input exceeds the qualification byte limit")
    return json.loads(content)


def finite_epoch(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 253402300799
    ):
        raise ActivationError("invalid qualification time bound")
    return value


def verify_readback(manifest: dict, indexed_rows: list[dict]) -> list[dict]:
    """Exact duplicate ingests are harmless; content conflicts are fatal."""
    if not isinstance(manifest, dict):
        raise ActivationError("invalid generation manifest")
    generation_id = manifest.get("generation_id")
    if not isinstance(generation_id, str) or not HEX.fullmatch(generation_id):
        raise ActivationError("invalid generation identity")
    body = {k: v for k, v in manifest.items() if k != "generation_id"}
    if sha256_hex(body) != generation_id:
        raise ActivationError("generation manifest hash mismatch")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("record_type") != "generation_manifest"
        or manifest.get("algorithm_version") != "configuration-history-v1"
        or manifest.get("canonicalization") != "bounded-decimal-json-v1"
        or manifest.get("row_order") != "record_id-asc-v1"
        or manifest.get("record_id_hash_excludes") != ["record_id", "generation_id"]
        or manifest.get("row_hash_excludes") != ["generation_id"]
        or type(manifest.get("row_count")) is not int
        or not 0 <= manifest["row_count"] <= MAX_ROWS
        or not isinstance(indexed_rows, list)
        or len(indexed_rows) > MAX_ROWS
    ):
        raise ActivationError("unsupported, capped or invalid generation")
    unique: dict[str, dict] = {}
    for row in indexed_rows:
        if not isinstance(row, dict) or row.get("generation_id") != generation_id:
            raise ActivationError("readback contains another generation")
        record_id = row.get("record_id")
        if not isinstance(record_id, str) or not HEX.fullmatch(record_id):
            raise ActivationError("invalid history record identity")
        if row_record_id(row) != record_id:
            raise ActivationError("history record hash mismatch")
        if record_id in unique and canonical_json(unique[record_id]) != canonical_json(
            row
        ):
            raise ActivationError("conflicting duplicate history record")
        unique[record_id] = row
    rows = [unique[key] for key in sorted(unique)]
    if len(rows) != manifest["row_count"]:
        raise ActivationError("generation readback is incomplete")
    content = b"\n".join(
        canonical_json({k: v for k, v in row.items() if k != "generation_id"})
        for row in rows
    )
    if sha256_hex(content) != manifest.get("rows_sha256"):
        raise ActivationError("generation row-set hash mismatch")
    times = [
        finite_epoch(
            next(
                (
                    row[key]
                    for key in ("latest_at", "event_at", "observed_at", "received_at")
                    if row.get(key) is not None
                ),
                None,
            )
        )
        for row in rows
    ]
    if times and (
        min(times) != manifest.get("source_earliest")
        or max(times) != manifest.get("source_latest")
    ):
        raise ActivationError("generation source-time extrema mismatch")
    return rows


def verify_indexed_generation(manifest: dict, payloads: list[dict]) -> list[dict]:
    """Require the exact indexed manifest and complete unique history rows."""
    if not isinstance(payloads, list) or len(payloads) > MAX_ROWS + 2:
        raise ActivationError("indexed generation exceeded the readback cap")
    manifests = {}
    rows = {}
    total_bytes = 0
    for payload in payloads:
        if not isinstance(payload, dict):
            raise ActivationError("invalid indexed generation payload")
        content = canonical_json(payload)
        is_manifest = payload.get("record_type") == "generation_manifest"
        limit = 512 * 1024 if is_manifest else 64 * 1024
        total_bytes += len(content)
        if len(content) > limit or total_bytes > MAX_BYTES:
            raise ActivationError("indexed generation exceeded its byte budget")
        (manifests if is_manifest else rows)[content] = payload
    if len(manifests) != 1 or next(iter(manifests)) != canonical_json(manifest):
        raise ActivationError("indexed generation manifest is missing or conflicting")
    return verify_readback(manifest, list(rows.values()))


def parse_indexed_payload(raw: str) -> dict:
    """Accept the exact projected JSON bytes required by the normal reader."""
    if not isinstance(raw, str):
        raise ActivationError("indexed generation payload is not text")
    try:
        if len(raw.encode("utf-8")) > 512 * 1024:
            raise ActivationError("indexed generation payload exceeds its byte cap")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or canonical_json(payload).decode() != raw:
            raise ActivationError("indexed generation payload is not canonical JSON")
    except ActivationError:
        raise
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ActivationError("indexed generation payload is invalid") from exc
    return payload


def make_activation(manifest, rows, *, index, ingest_start, ingest_end, attested):
    if not isinstance(index, str) or not INDEX.fullmatch(index):
        raise ActivationError("invalid derived index")
    if attested is not True:
        raise ActivationError("derived-index viewer entitlement must be attested")
    start, end = finite_epoch(ingest_start), finite_epoch(ingest_end)
    if start >= end:
        raise ActivationError("reversed ingest interval")
    activated_at = int(time.time())
    if end > activated_at:
        raise ActivationError("ingest interval must close before activation")
    verified = verify_readback(manifest, rows)
    if not verified:
        raise ActivationError("empty generation requires a retained coverage record")
    source_start = finite_epoch(manifest.get("source_earliest"))
    source_latest = finite_epoch(manifest.get("source_latest"))
    source_end = finite_epoch((round(source_latest * 1000) + 1) / 1000)
    if source_start >= source_end:
        raise ActivationError("invalid source-time interval")
    activation = {
        "schema_version": 1,
        "record_type": "generation_activation",
        "generation_id": manifest["generation_id"],
        "index": index,
        "source_earliest": source_start,
        "source_latest": source_latest,
        "index_earliest": start,
        "index_latest": end,
        "activated_at": activated_at,
        "viewer_entitlement_attested": True,
        "validation_method": "sha256-full-generation-v1",
        "manifest": manifest,
    }
    activation["activation_id"] = sha256_hex(activation)
    return activation


def owned_lab():
    if os.environ.get("ADM_LAB") != "1" or not os.environ.get("ADM_LAB_TASK"):
        raise ActivationError(
            "activation requires an explicitly allocated local task lab"
        )
    lab_root = ROOT / "tests" / "splunk"
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    spec = importlib.util.spec_from_file_location(
        "change_activation_lab", ROOT / "tests/splunk/lab.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_target()  # Ownership must be checked before authentication.
    return module


def strict_owned_search_client(lab):
    """Apply the primary runner's complete-response checks to local activation."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.change_activation_transport import (
        BoundedSearchClient,
        MAX_REST_BYTES,
        _decode_json,
    )

    class OwnedRest:
        @staticmethod
        def _rest_request(method, path, body=None, *, form_encoded=False):
            if body is not None and not form_encoded:
                raise ActivationError("activation search dispatch must be form encoded")
            lab.verify_target()
            with lab._mgmt(method, path, body) as response:
                raw = response.read(MAX_REST_BYTES + 1)
                if len(raw) > MAX_REST_BYTES:
                    raise ActivationError("activation response exceeds its byte cap")
                return {"status": response.status, "body": _decode_json(raw)}

    return BoundedSearchClient(OwnedRest(), MAX_ROWS + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--readback", type=Path)
    parser.add_argument("--lab", action="store_true")
    parser.add_argument("--index", default="atlas_changes")
    parser.add_argument("--ingest-start", type=int)
    parser.add_argument("--ingest-end", type=int)
    parser.add_argument("--attest-viewer-entitlement", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = read_json(args.manifest)
        if args.readback and not args.lab:
            rows = verify_readback(manifest, read_json(args.readback))
            print(json.dumps({"verified_rows": len(rows), "activated": False}))
            return 0
        if not args.lab or args.readback:
            raise ActivationError(
                "choose offline readback verification or owned-lab activation"
            )
        if args.ingest_start is None or args.ingest_end is None:
            raise ActivationError("actual ingest-time bounds are required")
        ingest_start = finite_epoch(args.ingest_start)
        ingest_end = finite_epoch(args.ingest_end)
        if ingest_start >= ingest_end or ingest_end > int(time.time()):
            raise ActivationError("a closed ordered ingest interval is required")
        if not args.attest_viewer_entitlement:
            raise ActivationError("derived-index viewer entitlement must be attested")
        if not INDEX.fullmatch(args.index) or not HEX.fullmatch(
            manifest.get("generation_id", "")
        ):
            raise ActivationError("invalid generation selector")
        lab = owned_lab()
        source_start = finite_epoch(manifest.get("source_earliest"))
        source_latest = finite_epoch(manifest.get("source_latest"))
        source_end = finite_epoch((round(source_latest * 1000) + 1) / 1000)
        query = (
            f'index={args.index} (sourcetype="{CHANGE_TYPE}" OR sourcetype="{MANIFEST_TYPE}") '
            f"_index_earliest={args.ingest_start} _index_latest={args.ingest_end} "
            "| spath input=_raw path=generation_id output=adm_generation_id "
            f'| where adm_generation_id="{manifest["generation_id"]}" '
            f"AND _indextime>={ingest_start} AND _indextime<{ingest_end} "
            f"| dedup _raw | head {MAX_ROWS + 2} | table _raw"
        )
        capture_spec = importlib.util.spec_from_file_location(
            "configuration_readback_capture",
            ROOT / "tools/capture_networking_fixtures.py",
        )
        capture = importlib.util.module_from_spec(capture_spec)
        capture_spec.loader.exec_module(capture)
        try:
            result, _provenance = capture.search(
                strict_owned_search_client(lab),
                query,
                str(min(source_start, ingest_start)),
                str(max(source_end, ingest_end)),
            )
        except Exception as exc:
            raise ActivationError(
                "indexed generation search did not complete cleanly"
            ) from exc
        rows = verify_indexed_generation(
            manifest, [parse_indexed_payload(row["_raw"]) for row in result]
        )
        activation = make_activation(
            manifest,
            rows,
            index=args.index,
            ingest_start=args.ingest_start,
            ingest_end=args.ingest_end,
            attested=args.attest_viewer_entitlement,
        )
        # Reuse the ownership-checked HEC transport. No secrets enter command args.
        event = {
            "index": args.index,
            "sourcetype": ACTIVATION_TYPE,
            "source": "atlas:configuration_history",
            "time": activation["activated_at"],
            "event": activation,
        }
        # Reserve an exclusive output before the index mutation, so an existing
        # output cannot make a successful activation appear to have failed.
        output = (
            args.output.open("x", encoding="utf-8") if args.output else nullcontext()
        )
        with output as out:
            lab._hec_post(canonical_json(event))
            if out is not None:
                out.write(json.dumps(activation, sort_keys=True) + "\n")
        print(
            json.dumps(
                {
                    "activation_id": activation["activation_id"],
                    "generation_id": activation["generation_id"],
                }
            )
        )
        return 0
    except (ActivationError, OSError, ValueError, KeyError, TypeError):
        print(
            "configuration generation qualification failed; inspect local evidence",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
