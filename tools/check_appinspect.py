#!/usr/bin/env python3
"""Fail when a Splunk AppInspect JSON report contains errors or failures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


BAD_RESULTS = frozenset(("error", "failure"))
KNOWN_RESULTS = frozenset(
    ("success", "warning", "not_applicable", "skipped", "future_failure", *BAD_RESULTS)
)


def _bad_results(value: Any, location: str = "report") -> list[str]:
    """Return paths for every check/message whose result is failure or error."""
    found: list[str] = []
    if isinstance(value, dict):
        result = value.get("result")
        if isinstance(result, str) and result.casefold() in BAD_RESULTS:
            found.append(f"{location}: {result}")
        for key in BAD_RESULTS:
            count = value.get(key)
            if isinstance(count, (int, float)) and count > 0:
                found.append(f"{location}.{key}: {count}")
        for key, child in value.items():
            found.extend(_bad_results(child, f"{location}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_bad_results(child, f"{location}[{index}]"))
    return found


def check_report(path: Path) -> list[str]:
    """Validate *path* and return human-readable failing result locations."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"unable to read AppInspect JSON report {path}: {exc}"
        ) from exc
    if not isinstance(report, (dict, list)):
        raise ValueError("AppInspect JSON report must contain an object or array")
    reports = report.get("reports") if isinstance(report, dict) else report
    if not isinstance(reports, list) or not reports:
        raise ValueError("AppInspect JSON report contains no reports")
    checks = [
        check
        for item in reports
        if isinstance(item, dict)
        for group in item.get("groups", [])
        if isinstance(group, dict)
        for check in group.get("checks", [])
        if isinstance(check, dict)
    ]
    if not checks:
        raise ValueError("AppInspect JSON report contains no checks")
    results = [check.get("result") for check in checks]
    results.extend(
        message.get("result")
        for check in checks
        for message in check.get("messages", [])
        if isinstance(message, dict)
    )
    unknown = sorted(
        result
        for result in results
        if isinstance(result, str) and result.casefold() not in KNOWN_RESULTS
    )
    if unknown:
        raise ValueError(
            f"AppInspect JSON report contains unknown result: {unknown[0]}"
        )
    if not any(isinstance(result, str) for result in results):
        raise ValueError("AppInspect JSON report contains no check results")
    failures = _bad_results(report)
    if failures:
        return failures
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        failures = check_report(args.report)
    except ValueError as exc:
        parser.error(str(exc))
    if failures:
        print("AppInspect report contains failures or errors:")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print(f"AppInspect report passed: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
