import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import qualify_prospective_runtime as runtime  # noqa: E402
from tests.test_project_prospective_pods import DEPLOYMENT, snapshot  # noqa: E402

NS = "44444444-4444-4444-4444-444444444444"


def data():
    snap = snapshot()
    snap["deployment"]["spec"] = {
        "template": {
            "spec": {
                "volumes": [{"configMap": {"name": "coredns"}}],
                "containers": [{"env": [{"value": "private-marker"}]}],
            }
        }
    }
    return {
        runtime.WHO: {"status": {"userInfo": {"username": "private-marker"}}},
        runtime.NAMESPACE: {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "kube-system", "uid": NS, "resourceVersion": "100"},
        },
        runtime.DEPLOYMENT: snap["deployment"],
        runtime.REPLICASETS: {
            "apiVersion": "apps/v1",
            "kind": "ReplicaSetList",
            "metadata": {},
            "items": snap["replicasets"],
        },
        runtime.PODS: {
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": snap["pods"],
        },
    }


def identity(raw):
    return runtime.decode(raw)["status"]["userInfo"]["username"]


class RuntimeTests(unittest.TestCase):
    def test_assembly_from_real_subprocess_responses(self):
        values = data()
        calls = []

        def call(args):
            self.assertTrue(runtime.allowed_request(args))
            calls.append(tuple(args))
            payload = json.dumps(values[tuple(args)])
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write(sys.argv[1])",
                    payload,
                ],
                capture_output=True,
                check=True,
                timeout=2,
            ).stdout

        result = runtime.collect(call, identity, DEPLOYMENT, NS)
        self.assertEqual(
            calls,
            [
                runtime.WHO,
                runtime.NAMESPACE,
                runtime.DEPLOYMENT,
                runtime.REPLICASETS,
                runtime.PODS,
                runtime.DEPLOYMENT,
                runtime.REPLICASETS,
                runtime.PODS,
                runtime.NAMESPACE,
                runtime.WHO,
            ],
        )
        self.assertEqual(result["status"], "paired_projection_consistent")
        self.assertNotIn("private-marker", json.dumps(result))
        self.assertEqual(len(result["configmap_volume_references"]), 1)

    def test_allowlist_and_inconsistent_claims_fail(self):
        self.assertFalse(
            runtime.allowed_request(
                ["get", "secrets", "-n", "kube-system", "-o", "json"]
            )
        )
        self.assertFalse(runtime.allowed_request(["exec", "coredns"]))
        self.assertFalse(runtime.allowed_request(list(runtime.PODS) + ["--watch"]))
        for mutation in (
            lambda d: d[runtime.NAMESPACE]["metadata"].update(uid=DEPLOYMENT),
            lambda d: d[runtime.REPLICASETS]["metadata"].update({"continue": "opaque"}),
            lambda d: d[runtime.PODS]["items"][0]["metadata"]["ownerReferences"][
                0
            ].update(uid=DEPLOYMENT),
            lambda d: d[runtime.DEPLOYMENT]["metadata"].update(uid=NS),
        ):
            with self.subTest(mutation=mutation):
                values = data()
                mutation(values)
                with self.assertRaises(ValueError):
                    runtime.collect(
                        lambda args: json.dumps(values[tuple(args)]).encode(),
                        identity,
                        DEPLOYMENT,
                        NS,
                    )

    def test_pair_change_and_identity_change_refused(self):
        for command in (
            runtime.WHO,
            runtime.NAMESPACE,
            runtime.DEPLOYMENT,
            runtime.REPLICASETS,
            runtime.PODS,
        ):
            values = data()
            counts = {}

            def call(args):
                key = tuple(args)
                counts[key] = counts.get(key, 0) + 1
                value = copy.deepcopy(values[key])
                if key == command and counts[key] == 2:
                    if key == runtime.WHO:
                        value["status"]["userInfo"]["username"] = "other"
                    elif key in (runtime.NAMESPACE, runtime.DEPLOYMENT):
                        value["metadata"]["resourceVersion"] = "101"
                    else:
                        value["items"][0]["metadata"]["resourceVersion"] = "101"
                return json.dumps(value).encode()

            with self.subTest(command=command), self.assertRaises(ValueError):
                runtime.collect(call, identity, DEPLOYMENT, NS)

    def test_bounded_and_duplicate_input(self):
        for raw in (
            b"{" + b" " * (1024 * 1024),
            b'{"a":1,"a":2}',
            b"[" * 2000 + b"0" + b"]" * 2000,
        ):
            with (
                self.subTest(size=len(raw)),
                self.assertRaises((ValueError, RecursionError)),
            ):
                runtime.decode(raw)


if __name__ == "__main__":
    unittest.main()
