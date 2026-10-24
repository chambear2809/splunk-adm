#!/usr/bin/env python3
"""Read-only native browser qualification of an already active V2 lab.

The coordinator owns installation, initialization, migration and expectations.
Credentials travel only from the protected lab file to the browser's stdin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests/splunk")]
from lab_lock import LabLock  # noqa: E402
from capture_networking_fixtures import (  # noqa: E402
    handoff_query,
    require_client,
    require_handoff,
    search,
)
from test_cisco_browser import CiscoV2BrowserTest  # noqa: E402
import lab  # noqa: E402


def _normal(value):
    return re.sub(r"\s+", " ", value.replace("\\\n", " ")).strip()


def _evidence_records(value):
    """Match the graph parser's omission of absent optional JSON fields."""
    records = json.loads(value) if isinstance(value, str) else value
    if not isinstance(records, list) or not records:
        raise AssertionError("selected MAC evidence records are missing")
    if any(not isinstance(record, dict) for record in records):
        raise AssertionError("selected MAC evidence records are malformed")
    return [
        {name: field for name, field in record.items() if field is not None}
        for record in records
    ]


def _content(path):
    return lab._json("GET", path)["entry"][0]["content"]


def _index_names(name, definition):
    literal = r"[a-z][a-z0-9_-]{0,79}"
    if name in {"adm_summary_index_name", "adm_summary_index_v2_name"}:
        return [definition] if re.fullmatch(literal, definition) else []
    if re.fullmatch("index=" + literal, definition):
        return [definition.removeprefix("index=")]
    if re.fullmatch(
        r"\(index=" + literal + r"(?:\s+OR\s+index=" + literal + r")+\)", definition
    ):
        return [
            term.removeprefix("index=")
            for term in re.split(r"\s+OR\s+", definition[1:-1])
        ]
    return []


def configuration(interface):
    base = "/servicesNS/nobody/splunk_adm/"
    selectors = {}
    for selector in interface["activation"]["cutover_selectors"]:
        name = selector["name"]
        definition = _content(
            base + "configs/conf-macros/" + urllib.parse.quote(name, safe="")
        )["definition"]
        if _normal(definition) != _normal(selector["after"]):
            raise AssertionError("installed public V2 selector mismatch: " + name)
        selectors[name] = hashlib.sha256(definition.encode()).hexdigest()
    settings = lab._json("GET", base + "adm/deployment-settings")
    if settings.get("state") != "configured":
        raise AssertionError(
            "administrator deployment expectations must already be configured"
        )
    document = settings["settings"]
    if document["revision"] not in settings["observedRevisions"]:
        raise AssertionError("deployment settings revision is not verified")
    registry = json.loads((ROOT / "config/deployment-health.json").read_text())
    definitions = {row["id"]: row for row in registry["sources"]}

    def active(name):
        row = definitions[name]
        if row["selectable"]:
            return (
                document["sources"].get(name, {}).get("state") == "active"
                and row["minimumContract"] <= 2
            )
        return row.get("contract") in (None, 2) and any(
            active(source) for source in row["derivedFrom"]
        )

    required = {
        "netflow",
        "dcn",
        "k8s",
        "traces",
        "hubble",
        "catalyst",
        "meraki",
        "sdwan",
    }
    if not all(active(name) for name in required):
        raise AssertionError(
            "configure expectations for the initialized raw networking dependency chain"
        )
    sources = [row for row in registry["sources"] if active(row["id"])]
    indexes = {}
    index_names = {}
    for name in sorted({name for row in sources for name in row["indexMacros"]}):
        definition = _content(base + "configs/conf-macros/" + name)["definition"]
        index_names[name] = _index_names(name, definition)
        if not index_names[name]:
            raise AssertionError("active source index macro is not configured: " + name)
        indexes[name] = hashlib.sha256(definition.encode()).hexdigest()
    for source in sources:
        if "derived_traffic" in source["evidence"] and source["indexMacros"]:
            values = [index_names[name] for name in source["indexMacros"]]
            if any(len(value) != 1 or value != values[0] for value in values):
                raise AssertionError(
                    "active derived source reader/writer indexes disagree"
                )
    jobs = [
        row
        for row in registry["jobs"]
        if row["stage"] == "active"
        and 2 in row["contracts"]
        and any(active(name) for name in row["sourceIds"])
    ]
    writers = {}
    for name in (
        "ADM - Conversation rollup",
        "ADM - Conversation rollup v2",
        "ADM - Traffic observation rollup v2",
        "ADM - Application catalog v2",
    ):
        row = _content(base + "saved/searches/" + urllib.parse.quote(name, safe=""))
        writers[name] = {
            key: row[key] for key in ("disabled", "is_scheduled", "cron_schedule")
        }
        disabled = str(row["disabled"]).lower() in ("1", "true")
        scheduled = str(row["is_scheduled"]).lower() in ("1", "true")
        if name == "ADM - Conversation rollup":
            if not disabled:
                raise AssertionError("legacy V1 rollup is not disabled")
        elif disabled or not scheduled:
            raise AssertionError(
                "required V2 writer is not enabled and scheduled: " + name
            )
    quality = {
        name
        for row in sources
        for name in row.get("qualitySourcesByContract", {}).get(
            "2", row["qualitySources"]
        )
    }
    probes = {row["probeMacro"] for row in sources}
    probes.update(
        registry["qualityProbes"][name]
        for name in quality
        if name in registry["qualityProbes"]
    )
    if any(row["required"] for row in jobs):
        probes.add("adm_health_jobs")
    return dict(
        selectors=selectors,
        settingsRevision=document["revision"],
        indexes=indexes,
        writers=writers,
    ), dict(
        selectors=list(selectors),
        indexMacros=list(indexes),
        healthProbes=sorted(probes),
        sourceLabels=[row["label"] for row in sources],
        requiredJobs=[row["name"] for row in jobs if row["required"]],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initialization", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    stage = "owned lab and protected authentication"
    try:
        if os.environ.get("ADM_LAB") != "1" or not LabLock(ROOT).check_owned():
            raise AssertionError("requires ADM_LAB=1 under the coordinator's lab lock")
        secret_stat = lab.SECRETS.lstat()
        if (
            not stat.S_ISREG(secret_stat.st_mode)
            or secret_stat.st_uid != os.getuid()
            or secret_stat.st_mode & 0o077
        ):
            raise AssertionError(
                "lab authentication file must be owner-only and regular"
            )
        ca = os.environ["ADM_CISCO_MIGRATION_CA_FILE"]
        lab._CTX = ssl.create_default_context(cafile=ca)
        lab.MGMT = (
            f"https://localhost:{int(os.environ.get('ADM_LAB_MGMT_PORT', '8089'))}"
        )
        initialized = json.loads(args.initialization.read_text())
        raw_manifest = ROOT / initialized["raw_dir"] / "capture-manifest.json"
        if (
            hashlib.sha256(raw_manifest.read_bytes()).hexdigest()
            != initialized["raw_manifest_sha256"]
        ):
            raise AssertionError("initialized raw manifest changed after loading")
        interface = json.loads(
            (ROOT / "research/cisco-pipeline-interface.json").read_text()
        )
        stage = "installed public selectors, writers and configured expectations"
        before, dependencies = configuration(interface)
        Browser = CiscoV2BrowserTest
        Browser.lab = lab
        Browser.window = tuple(
            int(initialized["window"][key]) for key in ("earliest", "latest")
        )
        stage = "read-only recorded raw networking scenarios"
        scenarios = Browser._read_scenarios()
        for platform, scenario in zip(("aci", "nxos"), scenarios, strict=True):
            rows, _ = search(
                lab,
                f'| search `adm_graph("checkout","demo","{scenario["cluster"]}","shop")`',
                *Browser.window,
            )
            require_client(rows, platform)
            # Preserve the exact per-connection receiver/observer proof before
            # graph aggregation. It remains separate from MAC attachment.
            handoffs, _ = search(
                lab,
                handoff_query(platform) + " via_node adm_mT adm_cid adm_cands",
                *Browser.window,
            )
            require_handoff(rows, handoffs, platform)
            scenario["handoffRows"] = handoffs
            client = next(
                row
                for row in rows
                if row.get("endpoint_kind") == "network_client"
                and row.get("attr_client_mac") == scenario["clientMac"]
            )
            scenario["clientId"] = client["id"]
            scenario["sourceTime"] = client.get("attr_source_time")
            scenario["receivedTime"] = client.get("attr_received_time")
            scenario["observationRecords"] = [
                {
                    "id": row["id"],
                    "target": row["target"],
                    "traffic": _evidence_records(row.get("traffic_observations")),
                    "attachments": _evidence_records(row.get("attachment_evidence")),
                }
                for row in rows
                if row.get("row_type") == "edge"
                and row.get("source") == client["id"]
                and row.get("relationship") == "traffic_observation"
            ]
        stage = "native post-cutover browser"
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(
            auth=dict(username="admin", password=lab.read_secrets()["SPLUNK_PASSWORD"]),
            scenarios=scenarios,
            dependencies=dependencies,
            artifactDirectory=str(output.parent),
        )
        process = subprocess.run(
            ["node", str(ROOT / "tests/splunk/cisco-v2-browser.mjs")],
            input=json.dumps(payload),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        try:
            evidence = json.loads(process.stdout)
        except (ValueError, TypeError):
            raise AssertionError(
                "native driver did not return sanitized JSON evidence"
            ) from None
        browser_ok = process.returncode == 0 and evidence.get("ok") is True
        if not browser_ok:
            evidence["ok"] = False
        stage = "post-browser configuration readback"
        after, _ = configuration(interface)
        if before != after:
            raise AssertionError("configuration changed during the read-only qualifier")
        evidence.update(
            configurationUnchanged=True,
            configuration=after,
            initializedRawManifest=initialized["raw_manifest_sha256"],
            qualification="owned standalone synthetic raw networking; no collector qualification",
        )
        with os.fdopen(
            os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            ),
            "w",
        ) as stream:
            json.dump(evidence, stream, indent=2)
            stream.write("\n")
        print(json.dumps(evidence, sort_keys=True))
        return 0 if browser_ok else 1
    except Exception as error:
        failure = dict(ok=False, stage=stage, errorType=type(error).__name__)
        if isinstance(error, AssertionError):
            failure["reason"] = str(error)[:500]
        print(json.dumps(failure))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
