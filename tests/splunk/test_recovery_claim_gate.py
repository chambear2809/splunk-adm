"""Live insert-only claim qualification; standalone only, not SHC or failover.

Only a confirmed insert winner may dispatch a harmless search. Environment
errors are INCONCLUSIVE (unittest errors), never a pass or an atomicity failure.
Set ADM_CLAIM_GATE_REPORT to preserve structured per-trial evidence.
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid


class GateInconclusive(RuntimeError):
    """The environment did not provide enough evidence to qualify the gate."""


def http_status(error):
    """LabError preserves the original HTTPError as its explicit cause."""
    cause = error.__cause__
    return cause.code if isinstance(cause, urllib.error.HTTPError) else None


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class RecoveryClaimGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        sys.path.insert(0, str(root))
        sys.path.insert(0, str(root / "tests" / "splunk"))
        import lab
        from tools.fault_pipeline import wait_kv_ready

        cls.lab = lab
        cls.wait_kv_ready = staticmethod(wait_kv_ready)

    def insert(self, path, record):
        secrets = self.lab.read_secrets()
        auth = base64.b64encode(f"admin:{secrets['SPLUNK_PASSWORD']}".encode()).decode()
        request = urllib.request.Request(
            self.lab.MGMT + path,
            data=json.dumps(record).encode(),
            method="POST",
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/json",
            },
        )
        with self.lab._open(request, timeout=30) as response:
            return json.loads(response.read())

    def wait_collection(self, path, timeout=180):
        """Wait for this newly created collection, after shared KV readiness."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.lab._json("GET", path + "?limit=1")
                return
            except self.lab.LabError as exc:
                if http_status(exc) not in (404, 503):
                    raise GateInconclusive(
                        f"collection readiness HTTP {http_status(exc)}"
                    ) from exc
            time.sleep(1)
        raise GateInconclusive("new collection data endpoint readiness timeout")

    def run_trial(self, data, trial, report):
        contenders = report["contenders"]
        key = f"slot_identity_{trial}"
        barrier = threading.Barrier(contenders, timeout=30)

        def claim_and_dispatch(number):
            owner = f"{trial}_{number}_{uuid.uuid4().hex}"
            record = {
                "_key": key,
                "owner": owner,
                "expires_at": int(time.time()) + 1800,
                "state": "claimed",
            }
            outcome = {
                "owner": owner,
                "claim": "unknown",
                "dispatch_attempted": False,
            }
            stage = "barrier"
            try:
                barrier.wait()
                stage = "insert"
                try:
                    inserted = self.insert(data, record)
                except self.lab.LabError as exc:
                    outcome["http_status"] = http_status(exc)
                    if http_status(exc) == 409:
                        outcome["claim"] = "rejected"
                        return outcome
                    raise
                if inserted.get("_key") != key:
                    raise GateInconclusive("unexpected insert response key")
                outcome.update(claim="won", record=record)
                stage = "dispatch"
                outcome["dispatch_attempted"] = True
                result = self.lab._json(
                    "POST",
                    "/servicesNS/admin/splunk_adm/search/v2/jobs",
                    {
                        "search": f'| makeresults | eval claim_owner="{owner}"',
                        "exec_mode": "normal",
                    },
                )
                outcome["sid"] = result["sid"]
                stage = "verify_dispatch"
                self.lab._wait_job(result["sid"], timeout=60)
                rows = self.lab._results(result["sid"])
                if len(rows) != 1 or rows[0].get("claim_owner") != owner:
                    raise GateInconclusive("dispatch result could not be verified")
            except Exception as exc:
                # Keep all contender outcomes, including partial dispatches.
                # Do not log exception text containing response bodies/tokens.
                outcome["error"] = {
                    "stage": stage,
                    "type": type(exc).__name__,
                    "http_status": http_status(exc),
                }
            return outcome

        with ThreadPoolExecutor(max_workers=contenders) as pool:
            outcomes = list(pool.map(claim_and_dispatch, range(contenders)))
        winners = [outcome for outcome in outcomes if outcome["claim"] == "won"]
        row = {
            "trial": trial,
            "winners": len(winners),
            "rejected_409": sum(outcome["claim"] == "rejected" for outcome in outcomes),
            "dispatches": sum(outcome["dispatch_attempted"] for outcome in outcomes),
            "confirmed_dispatches": sum("sid" in outcome for outcome in outcomes),
            "losing_dispatches": sum(
                outcome["claim"] == "rejected" and outcome["dispatch_attempted"]
                for outcome in outcomes
            ),
            "errors": sum("error" in outcome for outcome in outcomes),
            "status": "pending",
            "outcomes": outcomes,
        }
        report["trials"].append(row)
        try:
            # An observed invariant violation remains conclusive even if a
            # different contender also encountered an environment error.
            self.assertLessEqual(row["winners"], 1, "multiple same-key insert winners")
            self.assertLessEqual(row["dispatches"], 1, "multiple claim dispatches")
            self.assertEqual(row["losing_dispatches"], 0)
            if row["errors"]:
                raise GateInconclusive(f"trial {trial}: non-409 or environment error")
            self.assertEqual(
                row["winners"], 1, "same-key insertion must have one winner"
            )
            self.assertEqual(row["rejected_409"], contenders - 1)
            self.assertEqual(row["dispatches"], 1)
            self.assertEqual(row["confirmed_dispatches"], 1)
            self.assertEqual(row["losing_dispatches"], 0)
            persisted = self.lab._json("GET", data + "/" + key)
            for field, expected in winners[0]["record"].items():
                self.assertIn(field, persisted, "winning record lost a field")
                self.assertEqual(
                    persisted[field], expected, "winning record was changed"
                )
            row["status"] = "passed"
        except AssertionError:
            row["status"] = "failed"
            raise
        except Exception as exc:
            row["status"] = "inconclusive"
            raise GateInconclusive(f"trial {trial}: incomplete evidence") from exc
        finally:
            print(
                "claim gate "
                + json.dumps({k: v for k, v in row.items() if k != "outcomes"}),
                flush=True,
            )

    def test_concurrent_same_key_insert_has_one_winner_and_no_losing_dispatches(self):
        report = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "scope": "standalone only; not SHC or failover",
            "planned_trials": 25,
            "contenders": 8,
            "status": "inconclusive",
            "trials": [],
        }
        config = None
        try:
            # Reuse the engine-status AND successful-data-read readiness check.
            self.wait_kv_ready(timeout=180)
            server = self.lab._json("GET", "/services/server/info")["entry"][0][
                "content"
            ]
            report["splunk_version"] = server["version"]
            collection = "adm_claim_gate_" + uuid.uuid4().hex
            base = "/servicesNS/nobody/splunk_adm/storage/collections/"
            self.lab._json("POST", base + "config", {"name": collection})
            config = base + "config/" + collection
            data = base + "data/" + collection
            self.wait_collection(data)
            for trial in range(1, report["planned_trials"] + 1):
                self.run_trial(data, trial, report)
            report["status"] = "qualified"
        except AssertionError:
            report["status"] = "failed"
            raise
        except Exception as exc:
            report["status"] = "inconclusive"
            report["error_type"] = type(exc).__name__
            raise GateInconclusive(
                "INCONCLUSIVE: readiness or non-409 environment error; "
                "atomicity is not qualified"
            ) from exc
        finally:
            try:
                if config:
                    with self.lab._mgmt("DELETE", config):
                        pass
            except Exception as exc:
                report["cleanup_error_type"] = type(exc).__name__
                if report["status"] == "qualified":
                    report["status"] = "inconclusive"
                raise GateInconclusive(
                    "INCONCLUSIVE: collection cleanup failed"
                ) from exc
            finally:
                report["finished_at"] = datetime.now(timezone.utc).isoformat()
                destination = os.environ.get("ADM_CLAIM_GATE_REPORT")
                if destination:
                    path = Path(destination)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(
                        json.dumps(report, indent=2) + "\n", encoding="utf-8"
                    )
                print(
                    f"claim gate result={report['status']} scope=standalone", flush=True
                )


if __name__ == "__main__":
    unittest.main()
