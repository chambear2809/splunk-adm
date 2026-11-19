#!/usr/bin/env python3
"""Assess bounded source evidence; never assert independent completeness.

Inputs are evidence claims, not a trusted inventory. Eligibility means the
specified evidence fields are present and internally consistent and still
requires independent provenance, methodology and population review.
"""

import argparse
import hashlib
import json
import re
import sys

WINDOWS = ((1794844500, 1794844560), (1794844560, 1794844620))
FAMILIES = {"identity", "spans"}
SCOPE = {
    "service": "coreapi",
    "environment": "lab",
    "cluster": "k8s-01.uktme.cisco.com",
    "namespace": "tenant-jobs",
}
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_INPUT = 262144


def valid_digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def nonnegative(value):
    return type(value) is int and value >= 0


def assess(document):
    """Return named gaps; plausible input alone never grants qualification."""
    gaps = []

    def need(condition, name):
        if not condition:
            gaps.append(name)

    if not isinstance(document, dict):
        return {
            "status": "evidence_insufficient",
            "gaps": ["document"],
            "qualified": False,
        }
    need(document.get("scope") == SCOPE, "scope")
    need(document.get("producer_id") == "uktme-atlas-identity", "producer_identity")
    need(
        document.get("producer_config_revision")
        == "0b0d18412ba0d8c424ca1d0abe7603612edd66a48a9501eb82d6a288208266fc",
        "producer_revision",
    )
    need(valid_digest(document.get("catalog_evidence_sha256")), "catalog_evidence")
    families = document.get("families")
    if not isinstance(families, dict) or set(families) != FAMILIES:
        gaps.append("families")
        families = families if isinstance(families, dict) else {}
    for family in sorted(FAMILIES):
        item = families.get(family)
        item = item if isinstance(item, dict) else {}
        prefix = family + "."
        need(
            valid_digest(item.get("population_method_sha256")),
            prefix + "population_method",
        )
        need(
            valid_digest(item.get("producer_receipts_sha256")),
            prefix + "producer_receipts",
        )
        need(
            valid_digest(item.get("loss_measurement_sha256")),
            prefix + "loss_measurement",
        )
        need(
            valid_digest(item.get("sampling_measurement_sha256")),
            prefix + "sampling_measurement",
        )
        need(
            valid_digest(item.get("lateness_measurement_sha256")),
            prefix + "lateness_measurement",
        )
        maximum_lateness = item.get("max_lateness_seconds")
        need(nonnegative(maximum_lateness), prefix + "lateness_limit")
        windows = item.get("windows")
        if not isinstance(windows, list) or len(windows) != len(WINDOWS):
            gaps.append(prefix + "windows")
            continue
        for index, (row, bounds) in enumerate(zip(windows, WINDOWS)):
            tag = prefix + "window_" + str(index)
            if not isinstance(row, dict):
                gaps.append(tag)
                continue
            need((row.get("start"), row.get("end")) == bounds, tag + ".bounds")
            expected, indexed, excluded = (
                row.get(key)
                for key in (
                    "expected_population",
                    "indexed_population",
                    "accounted_exclusions",
                )
            )
            need(
                all(nonnegative(x) for x in (expected, indexed, excluded))
                and expected > 0
                and indexed + excluded == expected,
                tag + ".population",
            )
            need(
                valid_digest(row.get("expected_population_sha256"))
                and valid_digest(row.get("observed_population_sha256")),
                tag + ".population_evidence",
            )
            need(
                valid_digest(row.get("exclusion_evidence_sha256"))
                if nonnegative(excluded) and excluded > 0
                else excluded == 0,
                tag + ".exclusions",
            )
            need(
                row.get("producer_dropped") == 0
                and type(row.get("producer_dropped")) is int
                and row.get("sampled_out") == 0
                and type(row.get("sampled_out")) is int,
                tag + ".loss_sampling",
            )
            watermark = row.get("indexed_watermark")
            need(
                nonnegative(watermark)
                and nonnegative(maximum_lateness)
                and watermark >= bounds[1] + maximum_lateness,
                tag + ".watermark",
            )
            receipts = row.get("continuous_receipts")
            complete = isinstance(receipts, list) and bool(receipts)
            cursor = bounds[0]
            if complete:
                for receipt in receipts:
                    if (
                        not isinstance(receipt, dict)
                        or receipt.get("start") != cursor
                        or type(receipt.get("end")) is not int
                        or not (cursor < receipt["end"] <= bounds[1])
                        or not valid_digest(receipt.get("sha256"))
                    ):
                        complete = False
                        break
                    cursor = receipt["end"]
            need(complete and cursor == bounds[1], tag + ".continuous_receipts")
    return {
        "status": "evidence_insufficient"
        if gaps
        else "eligible_for_independent_review",
        "gaps": gaps,
        "qualified": False,
        "scope": "internal consistency only; producer and population truth unverified",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", help="bounded private JSON evidence file")
    args = parser.parse_args()
    try:
        with open(args.evidence, "rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("input limit")
        document = json.loads(raw)
        result = assess(document)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, sort_keys=True))
        return 0 if result["status"] == "eligible_for_independent_review" else 1
    except (OSError, ValueError, TypeError):
        print(
            json.dumps(
                {
                    "status": "evidence_insufficient",
                    "gaps": ["unreadable_or_invalid"],
                    "qualified": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
