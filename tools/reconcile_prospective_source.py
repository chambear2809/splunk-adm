#!/usr/bin/env python3
"""Reconcile bounded prospective attestations, never establish qualification."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys

MAX_INPUT = 262144
MAX_RECORDS = 2000
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def fields(value, keys):
    return type(value) is dict and set(value) == set(keys)


def token(value):
    return type(value) is str and TOKEN.fullmatch(value) is not None


def digest(value):
    return type(value) is str and DIGEST.fullmatch(value) is not None


def integer(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def reject_constant(_value):
    raise ValueError("non-finite number")


def read_json(path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise ValueError("safe open unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not a regular file")
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("input limit")
    return (
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        ),
        hashlib.sha256(raw).hexdigest(),
    )


def same(left, right):
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def reconcile(policy, evidence):
    """Return fixed diagnostic codes without echoing untrusted input."""

    def fail(code):
        return {"status": "evidence_insufficient", "qualified": False, "gaps": [code]}

    binding_keys = ("cluster", "scope", "producer", "epoch", "config_sha256")
    policy_keys = (
        "version",
        "binding",
        "window",
        "clock",
        "lateness_seconds",
        "families",
    )
    if (
        not fields(policy, policy_keys)
        or policy["version"] != 1
        or type(policy["version"]) is not int
    ):
        return fail("policy_schema")
    binding = policy["binding"]
    if (
        not fields(binding, binding_keys)
        or not all(token(binding[k]) for k in binding_keys[:-1])
        or not digest(binding["config_sha256"])
    ):
        return fail("policy_binding")
    window = policy["window"]
    if (
        not fields(window, ("start", "end"))
        or not all(integer(window[k]) for k in ("start", "end"))
        or window["start"] >= window["end"]
    ):
        return fail("policy_window")
    clock = policy["clock"]
    if (
        not fields(clock, ("basis", "max_error_seconds", "evidence_sha256"))
        or clock["basis"] != "utc_unix_seconds"
        or not integer(clock["max_error_seconds"])
        or not digest(clock["evidence_sha256"])
        or not integer(policy["lateness_seconds"])
    ):
        return fail("policy_clock_lateness")
    families = policy["families"]
    if not fields(families, ("identity", "spans")):
        return fail("policy_families")
    for item in families.values():
        if (
            not fields(
                item, ("population_sha256", "sampling", "signal_semantics_sha256")
            )
            or not digest(item["population_sha256"])
            or item["sampling"] != "none"
            or not digest(item["signal_semantics_sha256"])
        ):
            return fail("policy_population")
    if not fields(evidence, ("version", "binding", "window", "families")):
        return fail("evidence_schema")
    if type(evidence["version"]) is not int or evidence["version"] != 1:
        return fail("evidence_schema")
    if not same(evidence["binding"], binding) or not same(evidence["window"], window):
        return fail("binding_or_window")
    claims = evidence["families"]
    if not fields(claims, ("identity", "spans")):
        return fail("evidence_families")
    identifiers = set()
    for name in ("identity", "spans"):
        item = claims[name]
        if not fields(
            item,
            (
                "contract",
                "first_sequence",
                "last_sequence",
                "records",
                "watermark",
                "closure_sha256",
                "loss_evidence_sha256",
                "sampling_evidence_sha256",
                "rejected",
                "retried",
                "dropped",
            ),
        ):
            return fail("family_schema")
        if not same(item["contract"], families[name]):
            return fail("family_contract")
        first, last = item["first_sequence"], item["last_sequence"]
        records = item["records"]
        if (
            not integer(first)
            or not integer(last)
            or last < first
            or last - first + 1 > MAX_RECORDS
            or type(records) is not list
            or len(records) != last - first + 1
            or not digest(item["closure_sha256"])
            or not digest(item["loss_evidence_sha256"])
            or not digest(item["sampling_evidence_sha256"])
        ):
            return fail("sequence_coverage")
        if (
            not integer(item["watermark"])
            or item["watermark"]
            < window["end"] + policy["lateness_seconds"] + clock["max_error_seconds"]
        ):
            return fail("watermark")
        retries = 0
        for offset, record in enumerate(records):
            if not fields(
                record,
                (
                    "sequence",
                    "event_time",
                    "receipt_sha256",
                    "outcome",
                    "attempts",
                    "index_ack_sha256",
                ),
            ):
                return fail("record_schema")
            if (
                type(record["sequence"]) is not int
                or record["sequence"] != first + offset
            ):
                return fail("sequence_gap_or_duplicate")
            if (
                not integer(record["event_time"])
                or not window["start"] <= record["event_time"] < window["end"]
            ):
                return fail("event_time")
            if (
                not digest(record["receipt_sha256"])
                or record["receipt_sha256"] in identifiers
            ):
                return fail("receipt_missing_or_duplicate")
            identifiers.add(record["receipt_sha256"])
            if (
                record["outcome"] != "accepted"
                or not integer(record["attempts"])
                or record["attempts"] < 1
            ):
                return fail("unsettled_or_loss")
            if (
                not digest(record["index_ack_sha256"])
                or record["index_ack_sha256"] in identifiers
            ):
                return fail("index_ack_missing_or_duplicate")
            identifiers.add(record["index_ack_sha256"])
            retries += record["attempts"] - 1
        if (
            type(item["rejected"]) is not int
            or item["rejected"] != 0
            or type(item["dropped"]) is not int
            or item["dropped"] != 0
            or not integer(item["retried"])
            or item["retried"] != retries
        ):
            return fail("delivery_counters")
    return {"status": "eligible_for_independent_review", "qualified": False, "gaps": []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", help="bounded independently selected policy JSON")
    parser.add_argument("evidence", help="bounded private attestation JSON")
    args = parser.parse_args()
    try:
        policy, policy_hash = read_json(args.policy)
        evidence, evidence_hash = read_json(args.evidence)
        result = reconcile(policy, evidence)
        result.update(policy_sha256=policy_hash, evidence_sha256=evidence_hash)
    except (OSError, ValueError, TypeError, RecursionError):
        result = {
            "status": "evidence_insufficient",
            "qualified": False,
            "gaps": ["unreadable_or_invalid"],
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "eligible_for_independent_review" else 1


if __name__ == "__main__":
    sys.exit(main())
