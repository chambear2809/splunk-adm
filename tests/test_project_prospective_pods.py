import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools/project_prospective_pods.py"
DEPLOYMENT = "11111111-1111-1111-1111-111111111111"
REPLICA = "22222222-2222-2222-2222-222222222222"
POD = "33333333-3333-3333-3333-333333333333"


def obj(kind, name, uid, owner=None):
    meta = {
        "name": name,
        "namespace": "kube-system",
        "uid": uid,
        "resourceVersion": "10",
    }
    if owner:
        meta["ownerReferences"] = [
            {
                "apiVersion": "apps/v1",
                "kind": owner[0],
                "name": owner[1],
                "uid": owner[2],
                "controller": True,
            }
        ]
    return {
        "apiVersion": "v1" if kind == "Pod" else "apps/v1",
        "kind": kind,
        "metadata": meta,
    }


def snapshot():
    deployment = obj("Deployment", "coredns", DEPLOYMENT)
    replica = obj(
        "ReplicaSet", "coredns-abc", REPLICA, ("Deployment", "coredns", DEPLOYMENT)
    )
    pod = obj("Pod", "coredns-abc-xyz", POD, ("ReplicaSet", "coredns-abc", REPLICA))
    pod["metadata"]["labels"] = {"k8s-app": "kube-dns"}
    pod["spec"] = {
        "containers": [
            {
                "name": "coredns",
                "image": "example/image:v1",
                "env": [{"value": "private-marker"}],
                "args": ["private-marker"],
            }
        ]
    }
    pod["status"] = {
        "phase": "Running",
        "containerStatuses": [
            {
                "name": "coredns",
                "ready": True,
                "restartCount": 0,
                "state": {"running": {}},
                "imageID": "example@sha256:abcdef",
            }
        ],
    }
    return {"deployment": deployment, "replicasets": [replica], "pods": [pod]}


class ProjectionTests(unittest.TestCase):
    def invoke(self, first, second, uid=DEPLOYMENT):
        with tempfile.TemporaryDirectory() as d:
            paths = [Path(d) / "first", Path(d) / "second"]
            for path, value in zip(paths, (first, second)):
                path.write_text(value if isinstance(value, str) else json.dumps(value))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), uid, *map(str, paths)],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode, json.loads(result.stdout), result.stdout

    def test_paired_and_no_raw_values(self):
        value = snapshot()
        code, result, raw = self.invoke(value, value)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "paired_projection_consistent")
        for secret in (
            "private-marker",
            "example/image",
            "sha256:abcdef",
            POD,
            REPLICA,
            DEPLOYMENT,
        ):
            self.assertNotIn(secret, raw)

    def test_changed_or_ambiguous_evidence_refused(self):
        mutations = [
            lambda x: x["pods"][0]["metadata"].update(namespace="other"),
            lambda x: x["pods"][0]["metadata"].update(resourceVersion="11"),
            lambda x: x["pods"][0]["status"]["containerStatuses"][0].update(
                imageID="changed"
            ),
            lambda x: x["pods"][0]["metadata"]["ownerReferences"][0].update(
                uid=DEPLOYMENT
            ),
            lambda x: x["replicasets"][0]["metadata"]["ownerReferences"][0].update(
                uid=REPLICA
            ),
            lambda x: x["pods"].append(copy.deepcopy(x["pods"][0])),
            lambda x: x["pods"][0]["status"].update(containerStatuses=[]),
            lambda x: x["pods"][0]["metadata"]["ownerReferences"][0].update(
                controller="true"
            ),
            lambda x: x["pods"][0]["status"]["containerStatuses"][0].update(
                state={"running": {}, "waiting": {}}
            ),
            lambda x: x["pods"][0]["status"]["containerStatuses"][0].update(imageID=""),
            lambda x: x["pods"][0]["metadata"]["labels"].update({"k8s-app": "other"}),
        ]
        for change in mutations:
            with self.subTest(change=change):
                first = snapshot()
                second = copy.deepcopy(first)
                change(second)
                code, result, _ = self.invoke(first, second)
                self.assertEqual(code, 1)
                self.assertEqual(result["status"], "insufficient")
        value = snapshot()
        self.assertEqual(self.invoke(value, value, uid=REPLICA)[0], 1)
        value["pods"] = []
        self.assertEqual(self.invoke(value, value)[0], 1)

    def test_unready_status_visible_without_qualification(self):
        value = snapshot()
        value["pods"][0]["status"]["containerStatuses"][0].update(
            ready=False, state={"waiting": {"message": "private-marker"}}
        )
        code, result, raw = self.invoke(value, value)
        self.assertEqual(code, 0)
        self.assertFalse(result["projection"]["pods"][0]["containers"][0]["ready"])
        self.assertNotIn("private-marker", raw)
        self.assertIn("unknown", result["scope"])

    def test_bounded_and_duplicate_json(self):
        value = snapshot()
        for raw in (
            '{"secret":"' + "x" * 1048576 + '"}',
            '{"a":1,"a":2}',
            "[" * 2000 + "0" + "]" * 2000,
        ):
            self.assertEqual(self.invoke(value, raw)[0], 1)
        value["pods"] *= 21
        self.assertEqual(self.invoke(value, value)[0], 1)

    def test_fifo_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fifo"
            os.mkfifo(path)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), DEPLOYMENT, str(path), str(path)],
                capture_output=True,
                text=True,
                timeout=2,
            )
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
